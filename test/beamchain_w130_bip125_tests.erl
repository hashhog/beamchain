-module(beamchain_w130_bip125_tests).

%% W130 — BIP-125 RBF feebumper Rule 3 audit (wallet-side).
%%
%% References:
%%   bitcoin-core/src/wallet/feebumper.cpp
%%     - PreconditionChecks         :23-57
%%     - CheckFeeRate               :60-117
%%     - EstimateFeeRate            :119-144
%%     - CreateRateBumpTransaction  :159-328
%%     - CommitTransaction          :350-382
%%   bitcoin-core/src/policy/rbf.{cpp,h}
%%   bitcoin-core/src/policy/feerate.cpp
%%   BIP-125
%%
%% Audit-flip convention: every test asserts a divergent fact that holds
%% today. Tests PASS now (audit) and will FAIL when the fix lands
%% (flipping the gate from MISSING/BUG to PRESENT).
%%
%% Gate groups (30 total):
%%   G1-G3    Universal constants (BIP-125 + Core incremental relay fees)
%%   G4-G9    Rule 3 / Rule 4 (PaysForRBF) wallet and mempool integration
%%   G10-G11  EstimateFeeRate path
%%   G12-G15  Wallet-tx ops not implemented (combined_bump_fee,
%%            original_change_index, outputs override, calc-max-signed-size)
%%   G16-G18  PreconditionChecks gaps (HasWalletSpend, depth, replaced_by)
%%   G19-G22  CreateRateBumpTransaction wiring (AllInputsMine, findCoins,
%%            commit/MarkReplaced)
%%   G23-G25  Rule 5 cluster count + EntriesAndTxidsDisjoint + diagram strict
%%   G26-G28  Coin-selection + package-RBF wallet path
%%   G29-G30  Lint / future-rot guards (positional pattern, comment claim)
%%
%% This module catalogues 22 BUGs. Tests are organised so the test name
%% encodes the gate number and the bug it documents.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% -------------------------------------------------------------------
%%% Path helpers (cwd-portable; tests must work from rebar3's test dir)
%%% -------------------------------------------------------------------

beamchain_src_dir() ->
    Beam = code:which(beamchain_rpc),
    case Beam of
        non_existing -> "src";
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true  -> Src;
                false -> "src"
            end
    end.

rpc_src_path() ->
    filename:join(beamchain_src_dir(), "beamchain_rpc.erl").

wallet_src_path() ->
    filename:join(beamchain_src_dir(), "beamchain_wallet.erl").

mempool_src_path() ->
    filename:join(beamchain_src_dir(), "beamchain_mempool.erl").

config_src_path() ->
    filename:join(beamchain_src_dir(), "beamchain_config.erl").

read_src(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        {error, _} -> <<>>
    end.

%% Slice out the rpc_bumpfee section of beamchain_rpc.erl. Used to scope
%% absence checks so they don't trip on unrelated comments / RPC handlers
%% elsewhere in the file. Returns the substring from the
%% `do_bumpfee_rpc(TxidHex` clause to the start of the next `%%% ====`
%% banner (or end-of-file).
bumpfee_section(Src) ->
    case binary:match(Src, <<"do_bumpfee_rpc(TxidHex">>) of
        {Start, _} ->
            Slice = binary:part(Src, Start, byte_size(Src) - Start),
            case binary:match(Slice, <<"%%% =================">>) of
                {EndStart, _} -> binary:part(Slice, 0, EndStart);
                nomatch       -> Slice
            end;
        nomatch -> <<>>
    end.

%% Strip whole-line Erlang comments from a chunk of source. We use this
%% so absence checks (e.g. "no AllInputsMine token") don't trip on
%% explanatory commentary that references Core's function names while
%% documenting what beamchain doesn't (yet) have. Conservative: removes
%% any line whose first non-whitespace character is `%`.
strip_comments(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    Kept = [L || L <- Lines, not is_comment_line(L)],
    iolist_to_binary(lists:join(<<"\n">>, Kept)).

is_comment_line(Line) ->
    Stripped = trim_leading_ws(Line),
    case Stripped of
        <<"%", _/binary>> -> true;
        _ -> false
    end.

trim_leading_ws(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t ->
    trim_leading_ws(Rest);
trim_leading_ws(Bin) -> Bin.

%% Convenience: the code-only (comments stripped) bumpfee section.
bumpfee_code(Src) -> strip_comments(bumpfee_section(Src)).

%%% ===================================================================
%%% G1 — MAX_BIP125_RBF_SEQUENCE constant value
%%% Core util/rbf.h: MAX_BIP125_RBF_SEQUENCE = 0xFFFFFFFD.
%%% Status: PRESENT.
%%% ===================================================================

g1_max_bip125_sequence_value_test_() ->
    [?_assertEqual(16#fffffffd, ?MAX_BIP125_RBF_SEQUENCE)].

%%% ===================================================================
%%% G2 — DEFAULT_INCREMENTAL_RELAY_FEE constant value
%%% Core policy/policy.h:48: 100 sat/kvB.
%%% Status: PRESENT.
%%% ===================================================================

g2_default_incremental_relay_fee_test_() ->
    [?_assertEqual(100, ?DEFAULT_INCREMENTAL_RELAY_FEE),
     ?_assertEqual(100, beamchain_mempool:incremental_relay_fee_constant())].

%%% ===================================================================
%%% G3 — WALLET_INCREMENTAL_RELAY_FEE constant shape
%%% Core wallet/wallet.h: WALLET_INCREMENTAL_RELAY_FEE = 5000 (sat/kvB).
%%% beamchain stores it as `5` in sat/vB. Numerically equal at multiples
%%% of 1000 sat/kvB, but the *shape* drops the sub-vbyte precision.
%%% BUG-7 (LOW): constant value is correct accidentally but the integer
%%% sat/vB collapse hides the ceiling-vs-floor distinction.
%%% Audit-flip: test asserts the divergent shape ('=5' sat/vB integer).
%%% ===================================================================

g3_wallet_incremental_relay_fee_shape_test_() ->
    Src = read_src(rpc_src_path()),
    %% Confirms the divergent shape (sat/vB integer) lives at the
    %% documented line. The 5000-sat-per-kvB Core shape doesn't appear
    %% as an actual -define (only mentioned in the explanatory comment).
    [?_assert(binary:match(Src,
        <<"-define(WALLET_INCREMENTAL_RELAY_FEE_SATVB, 5).">>) =/= nomatch),
     %% A -define using the kvB unit suffix does NOT exist anywhere.
     ?_assertEqual(nomatch,
        binary:match(Src, <<"-define(WALLET_INCREMENTAL_RELAY_FEE_SATKVB">>)),
     ?_assertEqual(nomatch,
        binary:match(read_src(wallet_src_path()),
                     <<"-define(WALLET_INCREMENTAL_RELAY_FEE_SATKVB">>))].

%%% ===================================================================
%%% G4 — Rule 3: replacement_fees >= original_fees (mempool side present)
%%% Core policy/rbf.cpp:109-112.
%%% Status: PRESENT in `do_rbf` (mempool side).
%%% ===================================================================

g4_rule3_mempool_side_present_test_() ->
    Src = read_src(mempool_src_path()),
    [?_assert(binary:match(Src, <<"NewFee >= EvictedFeeTotal">>) =/= nomatch
              orelse binary:match(Src, <<"rbf_insufficient_fee">>) =/= nomatch)].

%%% ===================================================================
%%% G5 — Rule 4 wallet-side: uses OldVSize, not replacement_vsize
%%% Core policy/rbf.cpp:117-123 / wallet/feebumper.cpp:93.
%%% BUG-1 HIGH: `rpc_bumpfee` line ~5750 computes
%%%   MinNewFee = OldFee + OldVSize * IncrSatVB
%%% — the OldVSize argument is the **original** tx's vsize, not the
%%% replacement's. Wallet computes "good"; mempool's real PaysForRBF
%%% (which uses replacement vsize) rejects on the same tx.
%%% Audit-flip: test asserts the OldVSize literal lives at the doc'd
%%% site; fixing the bug removes that literal.
%%% ===================================================================

g5_rule4_wallet_uses_old_vsize_test_() ->
    Src = read_src(rpc_src_path()),
    [?_assert(binary:match(Src,
        <<"MinNewFee = OldFee + OldVSize * IncrSatVB">>) =/= nomatch)].

%%% ===================================================================
%%% G6 — Rule 4 mempool side: uses replacement_vsize (correct)
%%% Core policy/rbf.cpp:118 mirror.
%%% Status: PRESENT. `do_rbf` line ~1991 computes
%%%   NewVSize = beamchain_serialize:tx_sigop_vsize(NewTx, SigopCost)
%%% and uses it for the increment check.
%%% ===================================================================

g6_rule4_mempool_uses_replacement_vsize_test_() ->
    Src = read_src(mempool_src_path()),
    [?_assert(binary:match(Src,
        <<"NewVSize = beamchain_serialize:tx_sigop_vsize(NewTx">>) =/= nomatch)].

%%% ===================================================================
%%% G7 — `CheckFeeRate.mempoolMinFee` precheck absent
%%% Core wallet/feebumper.cpp:67-75.
%%% BUG-2 HIGH: `rpc_bumpfee` does not query rolling mempool min fee.
%%% Audit-flip: test asserts neither `mempoolMinFee` nor `GetMinFee`
%%% nor the wallet-chain-API equivalent token lives anywhere in
%%% `rpc_bumpfee` or its helpers.
%%% ===================================================================

g7_check_fee_rate_mempoolminfee_missing_test_() ->
    RpcSrc = read_src(rpc_src_path()),
    %% Locate the rpc_bumpfee section and scan it specifically.
    Section = case binary:match(RpcSrc, <<"do_bumpfee_rpc(TxidHex">>) of
        {Start, _} -> binary:part(RpcSrc, Start, byte_size(RpcSrc) - Start);
        nomatch    -> <<>>
    end,
    %% Cap to the next %%% banner to keep the section sane.
    Truncated = case binary:match(Section, <<"%%% =====">>) of
        {EndStart, _} -> binary:part(Section, 0, EndStart);
        nomatch       -> Section
    end,
    [?_assertEqual(nomatch, binary:match(Truncated, <<"mempoolMinFee">>)),
     ?_assertEqual(nomatch, binary:match(Truncated, <<"GetMinFee">>)),
     ?_assertEqual(nomatch, binary:match(Truncated, <<"get_min_fee">>))].

%%% ===================================================================
%%% G8 — Rule 3 `minTotalFee` wallet mirror uses wrong size
%%% Core wallet/feebumper.cpp:93:
%%%   minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize)
%%% BUG-5 MEDIUM: beamchain uses OldVSize; maxTxSize is the
%%% replacement's projected max signed vsize. Wallet-side mirror of
%%% BUG-1.
%%% Audit-flip: test asserts no `CalculateMaximumSignedTxSize` helper.
%%% ===================================================================

g8_min_total_fee_no_max_tx_size_helper_test_() ->
    Sources = [read_src(P) || P <- [rpc_src_path(), wallet_src_path()]],
    Joined = list_to_binary([X || X <- Sources, is_binary(X)]),
    [?_assertEqual(nomatch, binary:match(Joined, <<"CalculateMaximumSignedTxSize">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"max_tx_size">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"maxTxSize">>))].

%%% ===================================================================
%%% G9 — `-maxtxfee` / `m_default_max_tx_fee` cap missing
%%% Core wallet/feebumper.cpp:108-114.
%%% BUG-3 HIGH: no max-tx-fee config or cap in beamchain.
%%% ===================================================================

g9_maxtxfee_cap_missing_test_() ->
    Files = [read_src(P) || P <- [rpc_src_path(), wallet_src_path(),
                                  config_src_path()]],
    AllJoined = list_to_binary([X || X <- Files, is_binary(X)]),
    [?_assertEqual(nomatch, binary:match(AllJoined, <<"m_default_max_tx_fee">>)),
     ?_assertEqual(nomatch, binary:match(AllJoined, <<"maxtxfee">>)),
     %% wallet_max_tx_fee / max_tx_fee tokens do not appear either.
     ?_assertEqual(nomatch, binary:match(AllJoined, <<"max_tx_fee">>))].

%%% ===================================================================
%%% G10 — `EstimateFeeRate` default-path estimator
%%% Core wallet/feebumper.cpp:119-144.
%%% BUG-6 MEDIUM: beamchain's default path collapses to
%%%   MinNewFee = OldFee + OldVSize * IncrSatVB
%%% No fee estimator, no GetMinimumFeeRate, no +1 sat/vB margin for the
%%% rounded old fee rate.
%%% ===================================================================

g10_estimate_fee_rate_no_estimator_test_() ->
    WSrc = strip_comments(read_src(wallet_src_path())),
    BumpfeeCode = bumpfee_code(read_src(rpc_src_path())),
    [?_assertEqual(nomatch, binary:match(BumpfeeCode, <<"EstimateFeeRate">>)),
     ?_assertEqual(nomatch, binary:match(BumpfeeCode, <<"estimate_fee_rate">>)),
     ?_assertEqual(nomatch, binary:match(WSrc, <<"EstimateFeeRate">>)),
     ?_assertEqual(nomatch, binary:match(WSrc, <<"estimate_fee_rate">>)),
     %% beamchain has a fee estimator module but it's not wired in to bumpfee
     %% (it IS used elsewhere for the estimatefee/estimatesmartfee RPCs).
     ?_assert(filelib:is_file(filename:join(beamchain_src_dir(),
                                            "beamchain_fee_estimator.erl"))),
     %% Scope the absence check to the bumpfee code (no comments).
     ?_assertEqual(nomatch,
        binary:match(BumpfeeCode, <<"beamchain_fee_estimator">>))].

%%% ===================================================================
%%% G11 — WALLET_INCREMENTAL_RELAY_FEE used only on PaysForRBF gate
%%% BUG-18 LOW: when fee_rate= is provided, the wallet floor is bypassed.
%%% Audit-flip: test confirms the macro is referenced at exactly one site
%%% in `rpc_bumpfee` (the `IncrSatVB = max(...)` line).
%%% ===================================================================

g11_wallet_incrfloor_one_site_test_() ->
    Src = read_src(rpc_src_path()),
    Matches = binary:matches(Src, <<"?WALLET_INCREMENTAL_RELAY_FEE_SATVB">>),
    [?_assert(length(Matches) >= 1),
     %% Defensive: the macro definition itself plus 1-2 use-sites is fine.
     %% The bug is "not consulted on the fee_rate= path", not "duplicated"
     %% — so we only assert the macro is referenced *somewhere*.
     ?_assert(length(Matches) =< 3)].

%%% ===================================================================
%%% G12 — calculateCombinedBumpFee integration missing
%%% Core wallet/feebumper.cpp:83-87 + chain interface.
%%% BUG-9 MEDIUM: no combined-bump-fee call in `rpc_bumpfee`.
%%% ===================================================================

g12_combined_bump_fee_missing_test_() ->
    %% Strip comments from each source and verify no CODE reference to
    %% calculateCombinedBumpFee anywhere. (The token does appear in the
    %% rpc.erl out-of-scope comment block — line 5576 — and that is
    %% expected: the comment documents what is NOT implemented.)
    Stripped = [strip_comments(read_src(P)) || P <- [rpc_src_path(),
                                                     wallet_src_path(),
                                                     mempool_src_path()]],
    Joined = list_to_binary(Stripped),
    [?_assertEqual(nomatch, binary:match(Joined, <<"calculateCombinedBumpFee">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"combined_bump_fee">>))].

%%% ===================================================================
%%% G13 — `original_change_index` option missing
%%% Core wallet/feebumper.cpp:181-184.
%%% BUG-10 MEDIUM: no original_change_index in `rpc_bumpfee` Options
%%% destructure. Change output discovered by listaddresses walk.
%%% ===================================================================

g13_original_change_index_missing_test_() ->
    %% Use code-only view: rpc.erl line 5574 names the token in the
    %% out-of-scope comment.
    Code = strip_comments(read_src(rpc_src_path())),
    [?_assertEqual(nomatch, binary:match(Code, <<"original_change_index">>)),
     ?_assertEqual(nomatch, binary:match(Code, <<"change_position">>))].

%%% ===================================================================
%%% G14 — `outputs` array override missing
%%% Core wallet/feebumper.cpp:159-160, 251-263.
%%% BUG-11 MEDIUM: rpc_bumpfee uses OldTx#transaction.outputs only.
%%% ===================================================================

g14_outputs_array_override_missing_test_() ->
    Src = read_src(rpc_src_path()),
    %% No code consumes an `<<"outputs">>` option key in bumpfee_run /
    %% bumpfee_build_and_finalize. Note: `outputs` *is* used elsewhere
    %% in the RPC dispatcher (createrawtransaction etc.), so we scope
    %% the check to within ~50 lines after rpc_bumpfee's clause.
    case binary:match(Src, <<"rpc_bumpfee([TxidHex, Options]">>) of
        {Start, _} ->
            Slice = binary:part(Src, Start, min(20000, byte_size(Src) - Start)),
            EndIdx = case binary:match(Slice, <<"bumpfee_extract_entry">>) of
                {E, _} -> E;
                nomatch -> byte_size(Slice)
            end,
            Section = binary:part(Slice, 0, EndIdx),
            [?_assertEqual(nomatch,
                binary:match(Section, <<"maps:get(<<\"outputs\">>">>))];
        nomatch ->
            [?_assert(false)]  %% rpc_bumpfee should always be present.
    end.

%%% ===================================================================
%%% G15 — `CalculateMaximumSignedTxSize` not implemented
%%% Core wallet/spend.cpp / feebumper.cpp:289.
%%% BUG-8 MEDIUM: OldVSize reused as the size estimate for the new tx.
%%% ===================================================================

g15_calculate_max_signed_size_missing_test_() ->
    Sources = [read_src(P) || P <- [rpc_src_path(), wallet_src_path()]],
    Joined = list_to_binary([X || X <- Sources, is_binary(X)]),
    [?_assertEqual(nomatch, binary:match(Joined, <<"calculate_maximum_signed">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"CalculateMaximumSigned">>))].

%%% ===================================================================
%%% G16 — `HasWalletSpend` wallet-descendants check missing
%%% Core wallet/feebumper.cpp:25-28.
%%% BUG-12 MEDIUM: only mempool descendants checked.
%%% ===================================================================

g16_has_wallet_spend_missing_test_() ->
    Src = read_src(rpc_src_path()),
    [?_assertEqual(nomatch, binary:match(Src, <<"HasWalletSpend">>)),
     ?_assertEqual(nomatch, binary:match(Src, <<"has_wallet_spend">>)),
     ?_assertEqual(nomatch, binary:match(Src, <<"wallet_descendants">>))].

%%% ===================================================================
%%% G17 — `GetTxDepthInMainChain` check missing
%%% Core wallet/feebumper.cpp:37-40.
%%% BUG-13 MEDIUM: no wallet-side depth check.
%%% ===================================================================

g17_tx_depth_in_main_chain_missing_test_() ->
    Sources = [read_src(P) || P <- [rpc_src_path(), wallet_src_path()]],
    Joined = list_to_binary([X || X <- Sources, is_binary(X)]),
    [?_assertEqual(nomatch, binary:match(Joined, <<"GetTxDepthInMainChain">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"tx_depth_in_main_chain">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"get_tx_depth">>))].

%%% ===================================================================
%%% G18 — `replaced_by_txid` recursive-bump guard missing
%%% Core wallet/feebumper.cpp:42-45.
%%% BUG-14 MEDIUM: no replaced_by_txid map-value tracking.
%%% ===================================================================

g18_replaced_by_txid_missing_test_() ->
    Files = [read_src(P) || P <- [rpc_src_path(), wallet_src_path()]],
    Joined = list_to_binary([X || X <- Files, is_binary(X)]),
    [?_assertEqual(nomatch, binary:match(Joined, <<"replaced_by_txid">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"replaced_by">>))].

%%% ===================================================================
%%% G19 — `AllInputsMine` is implicit via lookup_privkeys_for_inputs
%%% Core wallet/feebumper.cpp:47-54.
%%% BUG-15 LOW: enforcement by side-effect; rejects watch-only inputs.
%%% Status: PARTIAL.
%%% ===================================================================

g19_all_inputs_mine_implicit_test_() ->
    %% rpc.erl line 5670 mentions "Core's AllInputsMine()" in a comment;
    %% verify there is no CODE call.
    Code = strip_comments(read_src(rpc_src_path())),
    Src = read_src(rpc_src_path()),
    [?_assertEqual(nomatch, binary:match(Code, <<"AllInputsMine">>)),
     ?_assertEqual(nomatch, binary:match(Code, <<"all_inputs_mine">>)),
     %% But the lookup_privkeys_for_inputs walk DOES happen.
     ?_assert(binary:match(Src,
        <<"lookup_privkeys_for_inputs(Pid, Selected, Network)">>) =/= nomatch)].

%%% ===================================================================
%%% G20 — `chain.findCoins` atomicity vs sequential lookups
%%% Core wallet/feebumper.cpp:191-208.
%%% BUG-16 LOW: chainstate→mempool race window.
%%% ===================================================================

g20_find_coins_sequential_not_atomic_test_() ->
    Src = read_src(rpc_src_path()),
    %% The lookup helper does two sequential queries with no shared lock.
    [?_assert(binary:match(Src,
        <<"case beamchain_chainstate:get_utxo(H, I) of">>) =/= nomatch),
     ?_assert(binary:match(Src,
        <<"case beamchain_mempool:get_mempool_utxo(H, I) of">>) =/= nomatch),
     %% No "atomic" or "lock" word in the lookup helper.
     %% (Loose lint: just confirm the sequential pattern exists.)
     ?_assertEqual(nomatch, binary:match(Src, <<"atomic_findcoins">>))].

%%% ===================================================================
%%% G21 — `CommitTransaction.MarkReplaced` not invoked
%%% Core wallet/feebumper.cpp:370-379.
%%% BUG-17 LOW: no MarkReplaced and no replaces_txid map value.
%%% ===================================================================

g21_mark_replaced_missing_test_() ->
    Files = [read_src(P) || P <- [rpc_src_path(), wallet_src_path()]],
    Joined = list_to_binary([X || X <- Files, is_binary(X)]),
    [?_assertEqual(nomatch, binary:match(Joined, <<"MarkReplaced">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"mark_replaced">>)),
     ?_assertEqual(nomatch, binary:match(Joined, <<"replaces_txid">>))].

%%% ===================================================================
%%% G22 — Wallet-side mirror of PaysForRBF on default path
%%% BUG-1 wallet-mirror summary gate. Asserts the literal `OldVSize *
%%% IncrSatVB` expression sits at the documented site.
%%% ===================================================================

g22_pays_for_rbf_wallet_mirror_test_() ->
    Src = read_src(rpc_src_path()),
    [?_assert(binary:match(Src, <<"OldVSize * IncrSatVB">>) =/= nomatch)].

%%% ===================================================================
%%% G23 — Rule 5 cluster count: beamchain caps total txs, not clusters
%%% Core policy/rbf.cpp:69-75 (GetUniqueClusterCount).
%%% BUG-4 HIGH: ?MAX_RBF_EVICTIONS=100 is total-tx-count cap, not
%%% cluster-count cap. Comment in beamchain_protocol.hrl falsely claims
%%% Core parity.
%%% Audit-flip: test asserts no `GetUniqueClusterCount` /
%%% `unique_cluster_count` helper exists, and the count-tx-not-clusters
%%% pattern is at the documented site.
%%% ===================================================================

g23_max_replacement_candidates_is_tx_count_test_() ->
    MSrc = read_src(mempool_src_path()),
    PSrc = read_src(filename:join(beamchain_src_dir(),
                                  "../include/beamchain_protocol.hrl")),
    JoinHrl = case PSrc of
        <<>> -> read_src(
                  filename:join([beamchain_src_dir(), "..",
                                 "include", "beamchain_protocol.hrl"]));
        _ -> PSrc
    end,
    [?_assertEqual(nomatch, binary:match(MSrc, <<"GetUniqueClusterCount">>)),
     ?_assertEqual(nomatch, binary:match(MSrc, <<"unique_cluster_count">>)),
     %% Total-tx-count gate lives at the documented site.
     ?_assert(binary:match(MSrc,
        <<"length(AllEvictTxids) =< ?MAX_RBF_EVICTIONS">>) =/= nomatch),
     %% Header comment falsely claims Core parity.
     ?_assert(JoinHrl =:= <<>> orelse
              binary:match(JoinHrl,
                <<"Core: MAX_REPLACEMENT_CANDIDATES">>) =/= nomatch)].

%%% ===================================================================
%%% G24 — EntriesAndTxidsDisjoint walks direct parents only
%%% Core policy/rbf.cpp:85-98.
%%% W120 BUG-7 carry-forward: ancestor set is approximated by
%%% NewParents (direct parents) only.
%%% Status: PARTIAL.
%%% ===================================================================

g24_entries_and_txids_disjoint_partial_test_() ->
    Src = read_src(mempool_src_path()),
    [?_assert(binary:match(Src,
        <<"%% 2b. EntriesAndTxidsDisjoint">>) =/= nomatch),
     %% NewParents is what gets walked, not full ancestor set.
     ?_assert(binary:match(Src,
        <<"lists:foreach(fun(AncTxid) ->">>) =/= nomatch)].

%%% ===================================================================
%%% G25 — ImprovesFeerateDiagram uses non-strict comparison
%%% Core policy/rbf.cpp:136 `std::is_gt(CompareChunks(...))`.
%%% W120 BUG-12 carry-forward: beamchain uses `>=` (non-strict).
%%% Status: PARTIAL.
%%% ===================================================================

g25_diagram_dominates_non_strict_test_() ->
    Src = read_src(mempool_src_path()),
    [?_assert(binary:match(Src, <<"NewFee >= OldFee">>) =/= nomatch),
     %% No `is_gt` strict-comparator helper.
     ?_assertEqual(nomatch, binary:match(Src, <<"is_gt">>))].

%%% ===================================================================
%%% G26 — `rpc_bumpfee` does NOT re-run coin selection
%%% W129 BUG-29 carry / W130 BUG-21.
%%% Status: MISSING.
%%% ===================================================================

g26_bumpfee_no_coin_selection_rerun_test_() ->
    Src = read_src(rpc_src_path()),
    %% bumpfee_build_and_finalize doesn't call select_coins/bnb_select.
    case binary:match(Src, <<"bumpfee_build_and_finalize">>) of
        {Start, _} ->
            Slice = binary:part(Src, Start, min(8000, byte_size(Src) - Start)),
            [?_assertEqual(nomatch, binary:match(Slice, <<"select_coins">>)),
             ?_assertEqual(nomatch, binary:match(Slice, <<"bnb_select">>)),
             ?_assertEqual(nomatch, binary:match(Slice, <<"knapsack_select">>))];
        nomatch ->
            [?_assert(false)]
    end.

%%% ===================================================================
%%% G27 — `psbtbumpfee` return shape sanity
%%% Core wallet/feebumper.cpp result envelope.
%%% Status: PARTIAL — fields present but `errors` semantics minimal.
%%% ===================================================================

g27_psbtbumpfee_shape_test_() ->
    Src = read_src(rpc_src_path()),
    [?_assert(binary:match(Src, <<"bumpfee_emit_psbt">>) =/= nomatch),
     ?_assert(binary:match(Src, <<"<<\"psbt\">>">>) =/= nomatch),
     ?_assert(binary:match(Src, <<"<<\"origfee\">>">>) =/= nomatch),
     ?_assert(binary:match(Src, <<"<<\"errors\">>">>) =/= nomatch)].

%%% ===================================================================
%%% G28 — Package-RBF wallet path absent
%%% Core validation.cpp PackageRBFChecks (mempool side) only.
%%% BUG-22 LOW: rpc_bumpfee never enters accept_package.
%%% ===================================================================

g28_no_package_bumpfee_test_() ->
    Src = read_src(rpc_src_path()),
    case binary:match(Src, <<"bumpfee_sign_and_submit">>) of
        {Start, _} ->
            Slice = binary:part(Src, Start, min(4000, byte_size(Src) - Start)),
            [?_assert(binary:match(Slice,
                <<"beamchain_mempool:accept_to_memory_pool">>) =/= nomatch),
             ?_assertEqual(nomatch, binary:match(Slice, <<"accept_package">>))];
        nomatch ->
            [?_assert(false)]
    end.

%%% ===================================================================
%%% G29 — `bumpfee_extract_entry` positional record-pattern is rot-prone
%%% BUG-20 LOW: 19-field positional match silently rots on field add.
%%% Audit-flip: test asserts the positional pattern is still in place.
%%% Future fix: use #mempool_entry{tx=Tx, fee=F, vsize=VS} record-field
%%% access, which is field-name-driven and rot-safe.
%%% ===================================================================

g29_extract_entry_positional_pattern_test_() ->
    Src = read_src(rpc_src_path()),
    [?_assert(binary:match(Src,
        <<"{mempool_entry, _Txid, _Wtxid, Tx, Fee">>) =/= nomatch),
     %% A record-field-access version would mention #mempool_entry{tx
     %% — confirm that future-fix shape is absent.
     ?_assertEqual(nomatch,
        binary:match(Src, <<"Entry#mempool_entry.tx">>))].

%%% ===================================================================
%%% G30 — Comment-as-confession at descendants check
%%% BUG-19 LOW: comment claims `get_descendants includes self`; the
%%% actual implementation excludes self. The filter `[D || D <- Descs,
%%% D =/= Txid]` is redundant but harmless TODAY. Documenting it as a
%%% future-rot trap: anyone "fixing" the comment by changing
%%% `get_descendants` to include self would silently break bumpfee.
%%% Audit-flip: test asserts BOTH (a) the misleading comment and
%%% (b) the filtering line live at the doc'd site.
%%% ===================================================================

g30_comment_confession_descendants_test_() ->
    RpcSrc = read_src(rpc_src_path()),
    MempSrc = read_src(mempool_src_path()),
    [%% Misleading comment lives at the documented site.
     ?_assert(binary:match(RpcSrc,
        <<"%% get_descendants includes self; require length =< 1.">>)
              =/= nomatch),
     %% Defensive filter is at the documented site.
     ?_assert(binary:match(RpcSrc,
        <<"[D || D <- Descs, D =/= Txid]">>) =/= nomatch),
     %% Reality: get_all_descendants seeds with [Txid] but only adds
     %% Children to the accumulator, NOT the seed.
     ?_assert(binary:match(MempSrc,
        <<"get_all_descendants([Txid | Rest], Visited, Acc)">>)
              =/= nomatch),
     ?_assert(binary:match(MempSrc,
        <<"Children ++ Acc">>) =/= nomatch)].
