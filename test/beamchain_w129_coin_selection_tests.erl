-module(beamchain_w129_coin_selection_tests).

%% W129 Coin selection deep-dive — beamchain (Erlang/OTP)
%%
%% 30 gates focused on the four algorithms (BnB / Knapsack / SRD / CG)
%% and their inputs (effective_value, long-term feerate, cost-of-change,
%% min_viable_change, change_target, SFFO, change avoidance) plus the
%% multi-algorithm orchestration (run-all-then-pick-lowest-waste).
%%
%% Status (see audit/w129_coin_selection.md for the gate index):
%%   - PARTIAL    : 2 gates (G1, G7)
%%   - MISSING    : 27 gates
%%   - PRESENT    : 0 gates that fully match Core
%%   - BUGs       : 18 (5 HIGH / 8 MEDIUM / 5 LOW)
%%
%% Bugs introduced by this audit (W129; W113's 12 bugs preserved):
%%
%%   BUG-1 (HIGH)   BnB upper bound uses fixed 546-sat DustLimit, not
%%                  Core's cost_of_change. Rejects valid changeless
%%                  solutions at low feerate, accepts wrong ones at high.
%%   BUG-2 (HIGH)   BnB depth-bounded at 20 (count of UTXOs considered)
%%                  instead of Core's try-bounded at 100000 branches with
%%                  lookahead pruning. Deepening of W113 BUG-1.
%%   BUG-3 (HIGH)   BnB sorts by raw value, never by effective_value.
%%                  Wrong order when input weights vary across UTXOs.
%%   BUG-4 (HIGH)   First-success short-circuit BnB->Knapsack; never
%%                  compares results by waste. Deepening of W113 BUG-3.
%%   BUG-5 (HIGH)   No mixed-output-type re-attempt; every UTXO treated
%%                  generically (W113 BUG-5 deeper consequence).
%%   BUG-6 (MEDIUM) BnB unconditionally run regardless of SFFO; Core
%%                  skips BnB when subtract_fee_outputs=true.
%%   BUG-7 (MEDIUM) Knapsack is deterministic linear sweep, not
%%                  1000-iter stochastic two-pass. Deepening W113 BUG-8.
%%   BUG-8 (MEDIUM) Knapsack has no `lowest_larger` fallback.
%%   BUG-9 (MEDIUM) Knapsack does not use FastRandomContext-seeded
%%                  shuffle. Fully deterministic ordering.
%%   BUG-10 (MEDIUM) No `cost_of_change` parameter exists anywhere.
%%   BUG-11 (MEDIUM) No long-term/consolidate feerate concept; cannot
%%                   gate CoinGrinder on 3xLTFRE.
%%   BUG-12 (MEDIUM) No SelectionResult.RecalculateWaste; W113 BUG-2
%%                   deeper. Even if added, infrastructure absent.
%%   BUG-13 (MEDIUM) No randomized GenerateChangeTarget. Change is
%%                   always residual after target+fee.
%%   BUG-14 (MEDIUM) m_subtract_fee_outputs absent; SFFO unsupported in
%%                   wallet RPCs that should accept it.
%%   BUG-15 (LOW)   COutput.safe / .solvable / .from_me flags absent;
%%                  malicious external unconfirmed UTXOs can be spent.
%%   BUG-16 (LOW)   CoinEligibilityFilter 6-step escalation ladder
%%                  absent; single pass over all UTXOs.
%%   BUG-17 (LOW)   No m_max_tx_weight enforcement at the algorithm
%%                  level; can build non-standard-weight transactions.
%%   BUG-18 (LOW)   feebumper bumpfee does not re-run coin selection;
%%                  Core's CreateRateBumpTransaction does.
%%
%% NOT a CDIV: every bug affects wallet fee efficiency, change
%% fingerprinting, performance, or operator UX. None affects
%% consensus validation of received blocks.
%%
%% Reference: bitcoin-core/src/wallet/coinselection.{h,cpp},
%%            bitcoin-core/src/wallet/spend.cpp,
%%            bitcoin-core/src/wallet/feebumper.cpp.
%%
%% Audit-flip: every test below asserts the current (divergent)
%% behavior so it PASSES today; a follow-up FIX wave that brings
%% the implementation into parity will flip these PASS -> FAIL.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% ===================================================================
%%% Source-path helpers (mirrors FIX-66 / FIX-65 convention)
%%% ===================================================================

beamchain_src_dir() ->
    Beam = code:which(beamchain_wallet),
    case Beam of
        non_existing -> "src";
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true -> Src;
                false -> "src"
            end
    end.

beamchain_wallet_src() ->
    filename:join(beamchain_src_dir(), "beamchain_wallet.erl").

beamchain_rpc_src() ->
    filename:join(beamchain_src_dir(), "beamchain_rpc.erl").

beamchain_hrl_path() ->
    Beam = code:which(beamchain_wallet),
    case Beam of
        non_existing -> filename:join(["include", "beamchain.hrl"]);
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            filename:join([Lib, "include", "beamchain.hrl"])
    end.

%%% ===================================================================
%%% Test data helpers
%%% ===================================================================

mk_utxo(Index, Value) ->
    Script = <<0, 20, 1:160>>,
    {<<Index:256>>, 0,
     #utxo{value = Value, script_pubkey = Script,
           is_coinbase = false, height = 100}}.

%%% ===================================================================
%%% G1 — BnB exists (PARTIAL)
%%% ===================================================================

g1_bnb_exists_test_() ->
    {"G1: PARTIAL — BnB exists but is structurally different from "
     "Core's SelectCoinsBnB (see G2..G6 sub-gates)",
     [
      ?_test(begin
         Fns = beamchain_wallet:module_info(exports),
         %% select_coins/3 is the public entry; bnb_search is internal
         %% but verifiable via behavior.
         ?assert(lists:member({select_coins, 3}, Fns)),
         %% Exact-match drives the BnB path. EffTarget = Target + 40
         %% (BaseFee), CostPerInput = round(FeeRate*272/4) = 68 at
         %% FeeRate=1, so a 50200-sat UTXO has EffValue = 50132 and
         %% Diff = 50132 - 50040 = 92 (well within DustLimit=546).
         {ok, Selected, Change} =
             beamchain_wallet:select_coins(50000, 1,
                 [mk_utxo(1, 50200)]),
         ?assertEqual(1, length(Selected)),
         %% No change emitted on BnB path
         ?assertEqual(0, Change)
       end)
     ]}.

%%% ===================================================================
%%% G2 — BUG-3: BnB does not sort by effective_value
%%% ===================================================================

g2_bnb_sorts_raw_value_not_effective_test_() ->
    {"G2: BUG-3 — BnB sorts by raw value, not effective_value. "
     "select_coins outer sort uses Utxo#utxo.value directly.",
     [
      ?_test(begin
         %% Verify the public sort is by raw value: build two UTXOs
         %% with same raw value where Core would prefer one by
         %% effective_value. We cannot probe internal sort order
         %% directly, so we assert the only sort callsite in the
         %% module uses #utxo.value. This is a source-level guard.
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         %% select_coins/3 uses lists:sort on A#utxo.value >= B#utxo.value
         ?assert(binary:match(Source,
             <<"A#utxo.value >= B#utxo.value">>) =/= nomatch)
       end)
     ]}.

%%% ===================================================================
%%% G3 — BUG-1: BnB upper bound is fixed 546-sat DustLimit
%%% ===================================================================

g3_bnb_uses_dustlimit_not_cost_of_change_test_() ->
    {"G3: BUG-1 — BnB declares match on Diff =< 546 (DustLimit), "
     "not Diff =< cost_of_change (Core's bounding box).",
     [
      ?_test(begin
         %% Exact match within 546 sat overshoot -> BnB returns Change=0.
         {ok, _, 0} = beamchain_wallet:select_coins(
             10000, 1, [mk_utxo(1, 10500)]),  %% 500-sat overshoot, < 546
         %% Overshoot just over 546 -> falls through to knapsack which
         %% includes change. Document by checking Change > 0.
         {ok, _, Change} = beamchain_wallet:select_coins(
             10000, 1, [mk_utxo(1, 11000)]),  %% 1000-sat overshoot, > 546
         ?assert(Change > 0),
         %% Also confirm DustLimit constant lives in source.
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assert(binary:match(Source,
             <<"DustLimit = 546">>) =/= nomatch)
       end)
     ]}.

%%% ===================================================================
%%% G4 — BUG-2: BnB depth bound = 20, not Core's TOTAL_TRIES=100000
%%% ===================================================================

g4_bnb_depth_capped_at_20_test_() ->
    {"G4: BUG-2 — BnB recursion aborts at Depth > 20 UTXOs. "
     "Core's TOTAL_TRIES is 100000 branches with lookahead.",
     [
      ?_test(begin
         %% Source-level guard for the constant; behavior probe is
         %% covered by W113 g11_bnb_depth tests already (W113 BUG-1).
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assert(binary:match(Source,
             <<"when Depth > 20">>) =/= nomatch),
         %% Core's TOTAL_TRIES constant is absent.
         ?assertEqual(nomatch,
             binary:match(Source, <<"TOTAL_TRIES">>)),
         %% Note: literal "100000" appears unrelatedly in
         %% PBKDF2 iterate_key (line 1724); we don't grep for it
         %% to avoid a false-positive collision.
         ?assertEqual(nomatch,
             binary:match(Source, <<"TotalTries">>))
       end)
     ]}.

%%% ===================================================================
%%% G5 — BUG-6: BnB always runs; no SFFO gate
%%% ===================================================================

g5_bnb_runs_unconditionally_no_sffo_gate_test_() ->
    {"G5: BUG-6 — BnB runs unconditionally. Core skips BnB when "
     "m_subtract_fee_outputs=true (spend.cpp:751).",
     [
      ?_test(begin
         %% select_coins/3 takes no subtract_fee_outputs argument; SFFO
         %% is unsupported entirely.
         Fns = beamchain_wallet:module_info(exports),
         ?assert(lists:member({select_coins, 3}, Fns)),
         ?assertNot(lists:member({select_coins, 4}, Fns)),
         ?assertNot(lists:member({select_coins, 5}, Fns)),
         %% Verify by source that no subtract_fee / sffo / sffa keyword
         %% appears in select_coins or its helpers.
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"subtract_fee_outputs">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"m_subtract_fee">>))
       end)
     ]}.

%%% ===================================================================
%%% G6 — BnB returns flat tuple, not SelectionResult struct
%%% ===================================================================

g6_bnb_returns_flat_tuple_test_() ->
    {"G6: BnB / select_coins returns {ok, [Coin], Change} flat tuple. "
     "Core returns SelectionResult with algo / waste / weight / "
     "selections_evaluated / algo_completed.",
     [
      ?_test(begin
         Result = beamchain_wallet:select_coins(
             10000, 1, [mk_utxo(1, 11000)]),
         ?assertMatch({ok, _, _}, Result),
         %% No record-shaped return; specifically not a SelectionResult.
         {ok, Selected, Change} = Result,
         ?assert(is_list(Selected)),
         ?assert(is_integer(Change))
       end)
     ]}.

%%% ===================================================================
%%% G7 — Knapsack exists (PARTIAL)
%%% ===================================================================

g7_knapsack_exists_test_() ->
    {"G7: PARTIAL — Knapsack exists but is structurally different "
     "from Core's KnapsackSolver (see G8..G10 sub-gates).",
     [
      ?_test(begin
         %% Drive a case where BnB cannot find an in-dust-range match
         %% so accumulate_coins/5 runs.
         Utxos = [mk_utxo(1, 3000), mk_utxo(2, 7000), mk_utxo(3, 11000)],
         {ok, _, _} = beamchain_wallet:select_coins(9999, 1, Utxos)
       end)
     ]}.

%%% ===================================================================
%%% G8 — BUG-7: Knapsack is deterministic linear sweep
%%% ===================================================================

g8_knapsack_deterministic_linear_sweep_test_() ->
    {"G8: BUG-7 — Knapsack is a deterministic single-pass linear "
     "sweep. Core does 1000-iter randomized two-pass.",
     [
      ?_test(begin
         %% Repeat identical calls — outputs must be identical
         %% (proof of determinism vs Core's stochastic ApproximateBestSubset).
         Utxos = lists:foldl(
             fun(I, Acc) -> [mk_utxo(I, 1000 + I*100) | Acc] end,
             [], lists:seq(1, 10)),
         R1 = beamchain_wallet:select_coins(5500, 1, Utxos),
         R2 = beamchain_wallet:select_coins(5500, 1, Utxos),
         R3 = beamchain_wallet:select_coins(5500, 1, Utxos),
         ?assertEqual(R1, R2),
         ?assertEqual(R2, R3),
         %% Source-level guard: no FastRandomContext / random / shuffle
         %% in knapsack helpers.
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         %% rand: not used in coin selection helpers
         %% (extract the select_coins block)
         ?assertEqual(nomatch,
             binary:match(Source, <<"rand:uniform">>))
       end)
     ]}.

%%% ===================================================================
%%% G9 — BUG-8: Knapsack has no lowest_larger fallback
%%% ===================================================================

g9_knapsack_no_lowest_larger_test_() ->
    {"G9: BUG-8 — Knapsack accumulate_coins/5 has no lowest_larger "
     "fallback. Core's KnapsackSolver picks lowest_larger when the "
     "approximate is worse.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"lowest_larger">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"lowestLarger">>))
       end)
     ]}.

%%% ===================================================================
%%% G10 — BUG-9: Knapsack uses no RNG-seeded shuffle
%%% ===================================================================

g10_knapsack_no_rng_shuffle_test_() ->
    {"G10: BUG-9 — Knapsack uses lists:sort + lists:reverse, not a "
     "RNG-seeded shuffle. Privacy regression (selection is "
     "fully deterministic given UTXO set + target + feerate).",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         %% Confirm the deterministic reverse trick is present.
         ?assert(binary:match(Source,
             <<"SmallFirst = lists:reverse(Sorted)">>) =/= nomatch),
         %% Confirm no shuffle helper exists.
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({shuffle, 1}, Fns)),
         ?assertNot(lists:member({shuffle, 2}, Fns))
       end)
     ]}.

%%% ===================================================================
%%% G11 — SRD entirely absent
%%% ===================================================================

g11_srd_absent_test_() ->
    {"G11: SRD (SelectCoinsSRD) absent. Core uses SRD as one of four "
     "candidates in ChooseSelectionResult.",
     [
      ?_test(begin
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({select_coins_srd, 2}, Fns)),
         ?assertNot(lists:member({select_coins_srd, 3}, Fns)),
         ?assertNot(lists:member({select_coins_srd, 4}, Fns)),
         ?assertNot(lists:member({srd, 2}, Fns)),
         ?assertNot(lists:member({srd, 3}, Fns)),
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch, binary:match(Source, <<"SelectCoinsSRD">>)),
         ?assertEqual(nomatch, binary:match(Source, <<"SingleRandomDraw">>))
       end)
     ]}.

%%% ===================================================================
%%% G12 — CoinGrinder entirely absent
%%% ===================================================================

g12_coingrinder_absent_test_() ->
    {"G12: CoinGrinder absent. Core added CoinGrinder in 27.0 for "
     "weight-aware minimization at high feerate.",
     [
      ?_test(begin
         Fns = beamchain_wallet:module_info(exports),
         ?assertNot(lists:member({coin_grinder, 3}, Fns)),
         ?assertNot(lists:member({coin_grinder, 4}, Fns)),
         ?assertNot(lists:member({coingrinder, 3}, Fns)),
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch, binary:match(Source, <<"CoinGrinder">>)),
         ?assertEqual(nomatch, binary:match(Source, <<"coin_grinder">>))
       end)
     ]}.

%%% ===================================================================
%%% G13 — CG gating on `effective_feerate > 3 × long_term_feerate` absent
%%% ===================================================================

g13_cg_feerate_gate_absent_test_() ->
    {"G13: CG-gate (effective_feerate > 3*long_term_feerate) absent. "
     "Core only runs CoinGrinder when feerate >= 3x LTFRE (~30 sat/vB).",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"long_term_feerate">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"long_term_fee">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"consolidate_feerate">>))
       end)
     ]}.

%%% ===================================================================
%%% G14 — OutputGroup struct absent
%%% ===================================================================

g14_outputgroup_absent_test_() ->
    {"G14: OutputGroup record absent. Core groups UTXOs sharing "
     "scriptPubKey for -avoidpartialspends + per-group "
     "effective_value tracking.",
     [
      ?_test(begin
         %% Verify no record name in beamchain.hrl matches output_group
         {ok, Hrl} = file:read_file(beamchain_hrl_path()),
         ?assertEqual(nomatch, binary:match(Hrl, <<"output_group">>)),
         ?assertEqual(nomatch, binary:match(Hrl, <<"-record(output_group">>))
       end)
     ]}.

%%% ===================================================================
%%% G15 — OUTPUT_GROUP_MAX_ENTRIES = 100 absent
%%% ===================================================================

g15_output_group_max_entries_absent_test_() ->
    {"G15: OUTPUT_GROUP_MAX_ENTRIES=100 cap absent. Core limits any "
     "single OutputGroup to 100 UTXOs.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"OUTPUT_GROUP_MAX_ENTRIES">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"output_group_max">>))
       end)
     ]}.

%%% ===================================================================
%%% G16 — m_avoid_partial_spends absent
%%% ===================================================================

g16_avoid_partial_spends_absent_test_() ->
    {"G16: avoid_partial_spends flag absent. Core honors "
     "-avoidpartialspends across SelectCoinsArgs.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"avoid_partial">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"avoidpartialspends">>))
       end)
     ]}.

%%% ===================================================================
%%% G17 — COutput.effective_value caching absent
%%% ===================================================================

g17_coutput_effective_value_caching_absent_test_() ->
    {"G17: COutput.effective_value caching absent. Core caches "
     "effective_value at COutput-construction.",
     [
      ?_test(begin
         %% The #utxo{} record has no effective_value field.
         {ok, Hrl} = file:read_file(beamchain_hrl_path()),
         ?assertEqual(nomatch,
             binary:match(Hrl, <<"effective_value">>))
       end)
     ]}.

%%% ===================================================================
%%% G18 — COutput.long_term_fee absent
%%% ===================================================================

g18_coutput_long_term_fee_absent_test_() ->
    {"G18: COutput.long_term_fee caching absent. Core caches "
     "long_term_fee at OutputGroup::Insert.",
     [
      ?_test(begin
         {ok, Hrl} = file:read_file(beamchain_hrl_path()),
         ?assertEqual(nomatch,
             binary:match(Hrl, <<"long_term_fee">>))
       end)
     ]}.

%%% ===================================================================
%%% G19 — COutput.ancestor_bump_fees + ApplyBumpFee absent
%%% ===================================================================

g19_ancestor_bump_fees_absent_test_() ->
    {"G19: COutput.ancestor_bump_fees + ApplyBumpFee absent. Core "
     "tracks per-input bump fee from unconfirmed-ancestor walk.",
     [
      ?_test(begin
         {ok, Hrl} = file:read_file(beamchain_hrl_path()),
         ?assertEqual(nomatch,
             binary:match(Hrl, <<"ancestor_bump_fee">>)),
         ?assertEqual(nomatch,
             binary:match(Hrl, <<"bump_fee_group_discount">>))
       end)
     ]}.

%%% ===================================================================
%%% G20 — BUG-10: cost_of_change not computed
%%% ===================================================================

g20_cost_of_change_absent_test_() ->
    {"G20: BUG-10 — cost_of_change parameter absent. Core computes "
     "discard_feerate.GetFee(change_spend_size) + change_fee.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"cost_of_change">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"costOfChange">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"m_cost_of_change">>))
       end)
     ]}.

%%% ===================================================================
%%% G21 — min_viable_change absent (W113 BUG-9 expansion)
%%% ===================================================================

g21_min_viable_change_absent_test_() ->
    {"G21: min_viable_change absent. Core: max(change_spend_fee+1, "
     "dust). beamchain hardcodes 546 in two places.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"min_viable_change">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"minViableChange">>)),
         %% But hardcoded 546 IS present (W113 BUG-9).
         ?assert(binary:match(Source, <<"DustLimit = 546">>) =/= nomatch),
         %% And in rpc_sendtoaddress.
         {ok, Rpc} = file:read_file(beamchain_rpc_src()),
         ?assert(binary:match(Rpc, <<"Change > 546">>) =/= nomatch)
       end)
     ]}.

%%% ===================================================================
%%% G22 — m_change_fee absent
%%% ===================================================================

g22_change_fee_absent_test_() ->
    {"G22: change_fee parameter absent. Core: "
     "effective_feerate.GetFee(change_output_size).",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"change_fee">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"changeFee">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"m_change_fee">>))
       end)
     ]}.

%%% ===================================================================
%%% G23 — BUG-13: GenerateChangeTarget randomization absent
%%% ===================================================================

g23_generate_change_target_absent_test_() ->
    {"G23: BUG-13 — GenerateChangeTarget randomization absent. "
     "Core picks random change target in [50ksat, min(2*pay, 1Msat)] "
     "to disguise change vs payment outputs.",
     [
      ?_test(begin
         %% Repeat calls -> identical change amount, proves no randomization.
         Utxos = [mk_utxo(1, 100000)],
         {ok, _, C1} = beamchain_wallet:select_coins(50000, 1, Utxos),
         {ok, _, C2} = beamchain_wallet:select_coins(50000, 1, Utxos),
         ?assertEqual(C1, C2),
         %% Source-level guard.
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"GenerateChangeTarget">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"change_target">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"CHANGE_LOWER">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"CHANGE_UPPER">>))
       end)
     ]}.

%%% ===================================================================
%%% G24 — BUG-4: ChooseSelectionResult multi-algo + min-waste pick absent
%%% ===================================================================

g24_choose_selection_result_first_success_test_() ->
    {"G24: BUG-4 — Orchestrator is first-success BnB->Knapsack, not "
     "Core's run-all-then-pick-min-waste.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         %% select_coins/3 uses a case bnb_select/3 -> early-return ok
         ?assert(binary:match(Source,
             <<"case bnb_select(Target, FeeRate, Sorted) of">>) =/= nomatch),
         %% No second/third algorithm appended; only knapsack_select
         ?assert(binary:match(Source,
             <<"knapsack_select(Target, FeeRate, Sorted)">>) =/= nomatch),
         ?assertEqual(nomatch,
             binary:match(Source, <<"min_element">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"ChooseSelectionResult">>))
       end)
     ]}.

%%% ===================================================================
%%% G25 — BUG-12: SelectionResult.RecalculateWaste absent
%%% ===================================================================

g25_recalculate_waste_absent_test_() ->
    {"G25: BUG-12 — SelectionResult.RecalculateWaste absent. "
     "Waste metric is computed nowhere in beamchain.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"RecalculateWaste">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"recalculate_waste">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"GetWaste">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"get_waste">>))
       end)
     ]}.

%%% ===================================================================
%%% G26 — SelectionResult.Merge for preset inputs absent
%%% ===================================================================

g26_selection_result_merge_absent_test_() ->
    {"G26: SelectionResult.Merge for preset (manual) inputs absent. "
     "wcfp_select_coins (rpc) does list-concat instead.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"selection_result_merge">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"SelectionResult">>)),
         %% Confirm the ad-hoc concat in rpc_wcfp_select_coins.
         {ok, Rpc} = file:read_file(beamchain_rpc_src()),
         ?assert(binary:match(Rpc,
             <<"ManualInputs ++ AutoSelected">>) =/= nomatch)
       end)
     ]}.

%%% ===================================================================
%%% G27 — BUG-16: CoinEligibilityFilter escalation ladder absent
%%% ===================================================================

g27_eligibility_filter_ladder_absent_test_() ->
    {"G27: BUG-16 — 6-step CoinEligibilityFilter ladder absent. "
     "Core escalates (1,6,0)->(1,1,0)->(0,1,2)->...; beamchain does "
     "one pass.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"CoinEligibilityFilter">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"eligibility_filter">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"conf_mine">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"conf_theirs">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"max_ancestors">>))
       end)
     ]}.

%%% ===================================================================
%%% G28 — BUG-17: max_tx_weight / max_selection_weight absent
%%% ===================================================================

g28_max_tx_weight_absent_test_() ->
    {"G28: BUG-17 — m_max_tx_weight / MAX_STANDARD_TX_WEIGHT gating "
     "absent at coin-selection layer.",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"max_tx_weight">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"MAX_STANDARD_TX_WEIGHT">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"max_selection_weight">>))
       end)
     ]}.

%%% ===================================================================
%%% G29 — BUG-18: feebumper does not re-run coin selection
%%% ===================================================================

g29_feebumper_no_coin_selection_test_() ->
    {"G29: BUG-18 — feebumper rpc_bumpfee re-signs with same inputs, "
     "never calls select_coins. Core's CreateRateBumpTransaction "
     "calls CreateTransaction with m_allow_other_inputs=true.",
     [
      ?_test(begin
         {ok, Rpc} = file:read_file(beamchain_rpc_src()),
         %% Find the bumpfee implementation.
         ?assert(binary:match(Rpc, <<"rpc_bumpfee">>) =/= nomatch),
         %% rpc_bumpfee must NOT call select_coins (it only re-signs).
         %% Approximate by extracting a window starting at the function
         %% and checking select_coins is absent within ~6 KB of source.
         {Pos, _} = binary:match(Rpc, <<"rpc_bumpfee(P, W)">>),
         WindowSize = 6000,
         Window = binary:part(Rpc, Pos,
             min(WindowSize, byte_size(Rpc) - Pos)),
         %% The bumpfee window should NOT invoke select_coins.
         ?assertEqual(nomatch,
             binary:match(Window, <<"select_coins(">>))
       end)
     ]}.

%%% ===================================================================
%%% G30 — BUG-18 cont'd: chain.calculateCombinedBumpFee absent
%%% ===================================================================

g30_combined_bump_fee_absent_test_() ->
    {"G30: chain.calculateCombinedBumpFee absent. Core uses it to "
     "deduplicate bump fees across UTXOs that share ancestors. "
     "(Note: the function name appears once in a W118 FIX-61 "
     "out-of-scope comment in beamchain_rpc.erl:5576 — we assert "
     "the function is never CALLED, only referenced in a doc "
     "comment listing things beamchain doesn't do.)",
     [
      ?_test(begin
         {ok, Source} = file:read_file(beamchain_wallet_src()),
         ?assertEqual(nomatch,
             binary:match(Source, <<"calculateCombinedBumpFee">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"combined_bump_fee">>)),
         ?assertEqual(nomatch,
             binary:match(Source, <<"SetBumpFeeDiscount">>)),
         %% Also absent in rpc as a callsite. The name appears once
         %% as a bareword in a comment ("Out of scope (deferred):
         %% ..., calculateCombinedBumpFee.") — we count occurrences
         %% and assert exactly one, with no function-call form.
         {ok, Rpc} = file:read_file(beamchain_rpc_src()),
         Matches = binary:matches(Rpc, <<"calculateCombinedBumpFee">>),
         ?assertEqual(1, length(Matches)),
         %% No function-call form (no "(" suffix variant): assert
         %% the comment is followed by ".\n" (sentence terminator),
         %% not by "(" (call) or ":" (module-qualified call).
         [{Pos, Len}] = Matches,
         After = binary:part(Rpc, Pos + Len, 2),
         ?assert(After == <<".\n">> orelse After == <<".">>),
         %% No actual call sites for combined_bump_fee variants.
         ?assertEqual(nomatch,
             binary:match(Rpc, <<"combined_bump_fee(">>)),
         ?assertEqual(nomatch,
             binary:match(Rpc, <<":calculateCombinedBumpFee(">>))
       end)
     ]}.

%%% ===================================================================
%%% End of W129 (30 gates)
%%% ===================================================================
