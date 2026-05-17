-module(beamchain_w132_nsequence_tests).

%% W132 — BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP audit
%% (beamchain).
%%
%% Discovery-only wave. Tests anchor today's behavior so a follow-up
%% FIX wave that closes the documented BUGs (especially the
%% mempool-on-reorg cluster BUG-1/BUG-2/BUG-3) flips the assertions
%% in a controlled, observable way.
%%
%% Status counts (from audit/w132_nsequence_csv_mtp.md):
%%   PRESENT : 19  (constants + happy-path block-connect path)
%%   PARTIAL : 8   (BUG-4 BUG-6 G14 G39 are notable)
%%   MISSING : 3   (BUG-1 BUG-3 G38 — mempool reorg re-eval / LockPoints)
%%   BUGs    : 11  (3 P1-MEM, 5 P2-SCRIPT, 3 P3-COSM ; 0 P0-CDIV)
%%
%% Reference: bitcoin-core/src/consensus/tx_verify.cpp,
%%            bitcoin-core/src/script/interpreter.cpp:522-593, :1745-1826,
%%            bitcoin-core/src/chain.h:231-245,
%%            bitcoin-core/src/validation.cpp:147-167, :2478-2482,
%%            bitcoin-core/src/validation.cpp:4080-4150 (CCTB),
%%            bitcoin-core/src/util/rbf.cpp.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Source-path helpers (W129 / W128 convention)
%%% ===================================================================

beamchain_src_dir() ->
    Beam = code:which(beamchain_validation),
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

beamchain_validation_src() ->
    filename:join(beamchain_src_dir(), "beamchain_validation.erl").

beamchain_chainstate_src() ->
    filename:join(beamchain_src_dir(), "beamchain_chainstate.erl").

beamchain_script_src() ->
    filename:join(beamchain_src_dir(), "beamchain_script.erl").

%%% ===================================================================
%%% Test data helpers
%%% ===================================================================

mk_input(Seq) ->
    #tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
           script_sig = <<>>,
           sequence = Seq,
           witness = []}.

mk_tx(Version, LockTime, Sequences) ->
    Inputs = [mk_input(S) || S <- Sequences],
    #transaction{
        version = Version,
        inputs = Inputs,
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = LockTime
    }.

mk_utxo_at(Height) ->
    #utxo{value = 50000, script_pubkey = <<>>,
          is_coinbase = false, height = Height}.

%% Build a stub PrevIndex map with a cached mtp_timestamps list. The
%% chainstate normally injects this; we mirror it for the unit-test path
%% that doesn't go through the DB.
mk_prev_index(Height, Header, Timestamps) ->
    #{height => Height,
      header => Header,
      chainwork => <<0:256>>,
      status => 2,
      mtp_timestamps => Timestamps}.

mk_header(Ts) ->
    #block_header{version = 2, prev_hash = <<0:256>>, merkle_root = <<0:256>>,
                  timestamp = Ts, bits = 16#1d00ffff, nonce = 0}.

%%% ===================================================================
%%% Constants — G1..G9
%%% ===================================================================

g1_sequence_final_constant_test() ->
    %% G1: SEQUENCE_FINAL = 0xffffffff
    ?assertEqual(16#ffffffff, ?SEQUENCE_FINAL).

g2_max_bip125_rbf_sequence_constant_test() ->
    %% G8: MAX_BIP125_RBF_SEQUENCE = 0xfffffffd
    ?assertEqual(16#fffffffd, ?MAX_BIP125_RBF_SEQUENCE),
    %% Adjacent: MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1 = 0xfffffffe;
    %% beamchain doesn't define a separate macro for this, the difference
    %% is in the BIP-125 admission gate.
    ?assert(?SEQUENCE_FINAL - 1 =:= 16#fffffffe).

g3_disable_flag_constant_test() ->
    %% G3: SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
    ?assertEqual(1 bsl 31, ?SEQUENCE_LOCKTIME_DISABLE_FLAG),
    ?assertEqual(16#80000000, ?SEQUENCE_LOCKTIME_DISABLE_FLAG).

g4_type_flag_constant_test() ->
    %% G4: SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
    ?assertEqual(1 bsl 22, ?SEQUENCE_LOCKTIME_TYPE_FLAG),
    ?assertEqual(16#00400000, ?SEQUENCE_LOCKTIME_TYPE_FLAG).

g5_mask_constant_test() ->
    %% G5: SEQUENCE_LOCKTIME_MASK = 0x0000ffff
    ?assertEqual(16#0000ffff, ?SEQUENCE_LOCKTIME_MASK).

g6_granularity_constant_test() ->
    %% G6: SEQUENCE_LOCKTIME_GRANULARITY = 9 (≈ 512 seconds per unit)
    ?assertEqual(9, ?SEQUENCE_LOCKTIME_GRANULARITY),
    ?assertEqual(512, 1 bsl ?SEQUENCE_LOCKTIME_GRANULARITY).

g7_locktime_threshold_constant_test() ->
    %% G7: LOCKTIME_THRESHOLD = 500_000_000 (script/script.h:47)
    ?assertEqual(500000000, ?LOCKTIME_THRESHOLD).

g9_mtp_window_constant_test() ->
    %% G9: nMedianTimeSpan = 11. beamchain hard-codes 11 inside
    %% collect_timestamps and median_time_past. We verify via a source-
    %% level guard (no exported constant to assert against).
    {ok, Src} = file:read_file(beamchain_validation_src()),
    ?assert(binary:match(Src, <<"collect_timestamps(PrevIndex, 11">>) =/= nomatch),
    ?assert(binary:match(Src, <<"length(Sorted) div 2">>) =/= nomatch).

%%% ===================================================================
%%% IsFinalTx — G10..G12
%%% ===================================================================

g10_is_final_tx_zero_locktime_test() ->
    %% G10: nLockTime == 0 is always final
    Tx = mk_tx(1, 0, [16#10]),
    ?assert(beamchain_validation:is_final_tx(Tx, 100, 1000000000)),
    %% Same for v2
    Tx2 = mk_tx(2, 0, [16#10]),
    ?assert(beamchain_validation:is_final_tx(Tx2, 100, 1000000000)).

g11_is_final_tx_height_threshold_pick_test() ->
    %% G11: locktime < LOCKTIME_THRESHOLD → compared against height
    %% locktime=100, height=101 → 100<101 → final
    Tx = mk_tx(1, 100, [0]),
    ?assert(beamchain_validation:is_final_tx(Tx, 101, 0)),
    %% locktime=100, height=100 → 100<100 false; seq=0 ≠ FINAL → non-final
    ?assertNot(beamchain_validation:is_final_tx(Tx, 100, 0)).

g11b_is_final_tx_time_threshold_pick_test() ->
    %% G11: locktime >= LOCKTIME_THRESHOLD → compared against time
    Tx = mk_tx(1, 600000000, [0]),
    ?assert(beamchain_validation:is_final_tx(Tx, 999999, 600000001)),
    ?assertNot(beamchain_validation:is_final_tx(Tx, 999999, 599999999)).

g12_is_final_tx_seq_final_overrides_test() ->
    %% G12: all inputs SEQUENCE_FINAL → final even when locktime cutoff fails
    Tx = mk_tx(1, 100, [?SEQUENCE_FINAL]),
    ?assert(beamchain_validation:is_final_tx(Tx, 50, 0)),
    %% Mixed: one non-final, one final → non-final
    Tx2 = mk_tx(1, 100, [?SEQUENCE_FINAL, 16#fffffffe]),
    ?assertNot(beamchain_validation:is_final_tx(Tx2, 50, 0)).

%%% ===================================================================
%%% CalculateSequenceLocks — G13..G17
%%% ===================================================================

g13_bip68_skipped_for_v1_test() ->
    %% G13: tx.version < 2 → {-1, -1} regardless of sequence
    Tx = mk_tx(1, 0, [100]),
    Coins = [mk_utxo_at(100)],
    ?assertEqual({-1, -1},
        beamchain_validation:calculate_sequence_lock_pair(Tx, Coins, #{})).

g14_disable_flag_skips_input_test() ->
    %% G14: input with DISABLE_FLAG → no constraint contributed.
    %% (BUG-8 note: beamchain skip is fold-skip, doesn't zero a
    %% prevHeights vector — currently benign because no LockPoints.)
    DisableSeq = ?SEQUENCE_LOCKTIME_DISABLE_FLAG bor 10,
    Tx = mk_tx(2, 0, [DisableSeq]),
    Coins = [mk_utxo_at(100)],
    ?assertEqual({-1, -1},
        beamchain_validation:calculate_sequence_lock_pair(Tx, Coins, #{})).

g15_height_based_lock_test() ->
    %% G15: height-based: MinH = max(prev_MinH, coinHeight + value - 1)
    %% nSequence=10 (no flags) → height-based. coinHeight=100.
    %% MinH = 100 + 10 - 1 = 109.
    Tx = mk_tx(2, 0, [10]),
    Coins = [mk_utxo_at(100)],
    {MinH, MinT} =
        beamchain_validation:calculate_sequence_lock_pair(Tx, Coins, #{}),
    ?assertEqual(109, MinH),
    ?assertEqual(-1, MinT).

g15b_height_based_max_across_inputs_test() ->
    %% G15: multi-input → takes max
    Tx = mk_tx(2, 0, [5, 15]),
    Coins = [mk_utxo_at(100), mk_utxo_at(110)],
    {MinH, _} =
        beamchain_validation:calculate_sequence_lock_pair(Tx, Coins, #{}),
    %% max(100+5-1, 110+15-1) = max(104, 124) = 124
    ?assertEqual(124, MinH).

g16_time_based_ancestor_mtp_lookup_test_() ->
    %% G16: time-based lock walks ancestor at max(coinHeight-1, 0).
    %%
    %% We cannot exercise the DB-path easily from here without a live
    %% chainstate, so the source-level guard confirms beamchain uses
    %% `max(H_mtp - 1, 0)` (Core tx_verify.cpp:74 parity).
    {"G16 source-level parity: ancestor walk = max(coinHeight - 1, 0)",
     [
      ?_test(begin
        {ok, Src} = file:read_file(beamchain_validation_src()),
        ?assert(binary:match(Src, <<"max(H_mtp - 1, 0)">>) =/= nomatch),
        ?assert(binary:match(Src,
            <<"beamchain_db:get_block_index(AncestorHeight)">>) =/= nomatch)
      end)
     ]}.

g17_time_based_max_formula_test_() ->
    %% G17: time-based: MinT = max(prev_MinT, coinMTP + (value<<9) - 1)
    %% Source-level guard confirming the formula.
    {"G17 time-based formula parity: coinMTP + (value<<9) - 1",
     [
      ?_test(begin
        {ok, Src} = file:read_file(beamchain_validation_src()),
        ?assert(binary:match(Src,
            <<"LockSeconds = Masked bsl ?SEQUENCE_LOCKTIME_GRANULARITY">>)
            =/= nomatch),
        ?assert(binary:match(Src,
            <<"CoinMTP + LockSeconds - 1">>) =/= nomatch)
      end)
     ]}.

%%% ===================================================================
%%% EvaluateSequenceLocks — G18
%%% ===================================================================

g18_evaluate_sequence_locks_boundary_test_() ->
    %% G18: lock satisfied iff MinH < Height AND MinT < MTP.
    %% We exercise the boundary by calling check_sequence_locks/4 with
    %% a stub PrevIndex carrying mtp_timestamps so median_time_past/1
    %% bypasses the DB.
    %%
    %% Build:
    %%   Tx = v2, single input with seq=5 (height-based)
    %%   Coin at height=100 → MinH = 100+5-1 = 104
    %%   PrevIndex.mtp_timestamps = [100..110] → MTP=105
    %% Cases:
    %%   Height=105 → MinH=104 < 105 → ok (accept)
    %%   Height=104 → MinH=104 >= 104 → throw(sequence_lock_not_met)
    {"G18 BIP-68 height-boundary accept/reject",
     [
      ?_test(begin
        Tx = mk_tx(2, 0, [5]),
        Coins = [mk_utxo_at(100)],
        Header = mk_header(110),
        PrevIndex = mk_prev_index(104, Header,
            [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110]),
        %% accept at height 105 (MinH=104 < 105)
        ?assertEqual(ok,
            beamchain_validation:check_sequence_locks(Tx, Coins, 105, PrevIndex)),
        %% reject at height 104 (MinH=104 >= 104)
        ?assertThrow(sequence_lock_not_met,
            beamchain_validation:check_sequence_locks(Tx, Coins, 104, PrevIndex))
      end)
     ]}.

g18b_evaluate_sequence_locks_version1_passes_test() ->
    %% Version 1 always passes check_sequence_locks regardless of seq/locks.
    Tx = mk_tx(1, 0, [16#0000ffff]),  %% max height-lock for v1
    Coins = [mk_utxo_at(100)],
    Header = mk_header(110),
    PrevIndex = mk_prev_index(100, Header,
        [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110]),
    ?assertEqual(ok,
        beamchain_validation:check_sequence_locks(Tx, Coins, 101, PrevIndex)).

%%% ===================================================================
%%% OP_CLTV (BIP-65) interpreter gates — G19..G25
%%% ===================================================================

g19_cltv_flag_gate_off_is_nop_test() ->
    %% G19: flag-off → CLTV is a NOP (operand left on stack)
    {ok, [<<1>>]} = beamchain_script:eval_script(
        <<16#51, 16#b1>>, [], 0, #{}, base).

g20_cltv_empty_stack_underflow_test_() ->
    {"G20 CLTV empty-stack underflow",
     [?_test(begin
        Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
        SigChecker = #{check_locktime => fun(_) -> true end},
        Res = beamchain_script:eval_script(
            <<16#b1>>, [], Flags, SigChecker, base),
        ?assertMatch({error, stack_underflow}, Res)
      end)]}.

g21_cltv_minimal_5_byte_test() ->
    %% G21: CScriptNum 5-byte limit + MINIMALDATA gate
    SigChecker = #{check_locktime => fun(_) -> true end},
    Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY bor ?SCRIPT_VERIFY_MINIMALDATA,
    %% Non-minimal: 1 encoded as <<0x01, 0x00>>
    {error, non_minimal_encoding} = beamchain_script:eval_script(
        <<16#02, 16#01, 16#00, 16#b1>>, [], Flags, SigChecker, base).

g22_cltv_negative_locktime_rejection_test() ->
    %% G22: negative locktime → SCRIPT_ERR_NEGATIVE_LOCKTIME
    SigChecker = #{check_locktime => fun(_) -> true end},
    Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    {error, negative_locktime} = beamchain_script:eval_script(
        <<1, 16#81, 16#b1>>, [], Flags, SigChecker, base).

g23_cltv_same_type_apples_test() ->
    %% G23: type mismatch (locktime < THRESHOLD but tx.locktime >=) fails.
    %% Operand=1 (height-type), tx.locktime=600_000_000 (time-type)
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#fffffffe,
                         witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 600000000
    },
    Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SigChecker = {Tx, 0, 1000},
    %% OP_1 OP_CLTV
    {error, locktime_failed} = beamchain_script:eval_script(
        <<16#51, 16#b1>>, [], Flags, SigChecker, base).

g24_cltv_magnitude_compare_test() ->
    %% G24: locktime operand > tx.locktime → fail (locktime_failed)
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#fffffffe,
                         witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 10
    },
    Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SigChecker = {Tx, 0, 1000},
    %% Push 20 (1-byte 0x14), OP_CLTV — 20 > 10 → fail
    {error, locktime_failed} = beamchain_script:eval_script(
        <<16#01, 16#14, 16#b1>>, [], Flags, SigChecker, base).

g25_cltv_sequence_final_disables_test() ->
    %% G25: input.sequence == SEQUENCE_FINAL → CheckLockTime fails even
    %% if magnitude and type would pass.
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 100
    },
    Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SigChecker = {Tx, 0, 1000},
    %% Push 50 (height-type < 100), but sequence=FINAL → fail
    {error, locktime_failed} = beamchain_script:eval_script(
        <<16#01, 16#32, 16#b1>>, [], Flags, SigChecker, base).

%%% ===================================================================
%%% OP_CSV (BIP-112) interpreter gates — G26..G32
%%% ===================================================================

g26_csv_flag_gate_off_is_nop_test() ->
    %% G26: flag-off → CSV is a NOP (operand left on stack)
    {ok, [<<1>>]} = beamchain_script:eval_script(
        <<16#51, 16#b2>>, [], 0, #{}, base).

g27_csv_5_byte_minimal_test() ->
    SigChecker = #{check_sequence => fun(_) -> true end},
    Flags = ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor ?SCRIPT_VERIFY_MINIMALDATA,
    %% Non-minimal 1: <<0x01, 0x00>>
    {error, non_minimal_encoding} = beamchain_script:eval_script(
        <<16#02, 16#01, 16#00, 16#b2>>, [], Flags, SigChecker, base).

g28_csv_negative_n_test() ->
    Flags = ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SigChecker = #{check_sequence => fun(_) -> true end},
    {error, negative_sequence} = beamchain_script:eval_script(
        <<16#4f, 16#b2>>, [], Flags, SigChecker, base).

g29_csv_operand_disable_flag_is_nop_test() ->
    %% G29: operand has DISABLE_FLAG set → CSV behaves as NOP
    Flags = ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    %% Returns false would normally fail, but disable-flag should bypass.
    SigChecker = #{check_sequence => fun(_) -> false end},
    DisableVal = 1 bsl 31,
    DisableEnc = beamchain_script:encode_script_num(DisableVal),
    PushLen = byte_size(DisableEnc),
    Script = <<PushLen:8, DisableEnc/binary, 16#b2>>,
    {ok, _} = beamchain_script:eval_script(Script, [], Flags, SigChecker, base).

g30_csv_v1_tx_fails_test() ->
    %% G30: tx.version < 2 → CheckSequence returns false
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                         script_sig = <<>>, sequence = 100, witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 0
    },
    Flags = ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SigChecker = {Tx, 0, 1000},
    {error, sequence_failed} = beamchain_script:eval_script(
        <<16#51, 16#b2>>, [], Flags, SigChecker, base).

g31_csv_input_disable_flag_fails_test() ->
    %% G31: input.sequence has DISABLE_FLAG → CheckSequence returns false
    DisableSeq = ?SEQUENCE_LOCKTIME_DISABLE_FLAG bor 10,
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<1:256>>, index = 0},
                         script_sig = <<>>, sequence = DisableSeq,
                         witness = []}],
        outputs = [#tx_out{value = 1000, script_pubkey = <<16#6a>>}],
        locktime = 0
    },
    Flags = ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SigChecker = {Tx, 0, 1000},
    %% OP_5 OP_CSV — operand=5 (no flags) → check_sequence_impl sees
    %% input disable-flag → returns false.
    {error, sequence_failed} = beamchain_script:eval_script(
        <<16#55, 16#b2>>, [], Flags, SigChecker, base).

g32_csv_full_mask_parity_test_() ->
    %% G32: BUG-4 / BUG-6 regression guard.
    %%
    %% beamchain compares the 16-bit MASK portion separately from the
    %% TYPE_FLAG. Core uses (TYPE_FLAG | MASK) as a single mask. For
    %% same-type operands the answers match — but a future encoder
    %% drift in the high bits would silently diverge. This source-level
    %% guard pins the masked-compare structure.
    {"G32 CSV mask structure (BUG-4/BUG-6 regression guard)",
     [
      ?_test(begin
        {ok, Src} = file:read_file(beamchain_script_src()),
        ?assert(binary:match(Src,
            <<"SeqVal = Sequence band ?SEQUENCE_LOCKTIME_MASK">>)
            =/= nomatch),
        ?assert(binary:match(Src,
            <<"TxVal = TxSeq band ?SEQUENCE_LOCKTIME_MASK">>)
            =/= nomatch),
        %% Type flag is checked separately (the BUG): not merged with mask.
        ?assert(binary:match(Src,
            <<"SeqType = Sequence band ?SEQUENCE_LOCKTIME_TYPE_FLAG">>)
            =/= nomatch),
        ?assert(binary:match(Src,
            <<"TxType = TxSeq band ?SEQUENCE_LOCKTIME_TYPE_FLAG">>)
            =/= nomatch)
      end)
     ]}.

%%% ===================================================================
%%% Contextual gates — G33..G36
%%% ===================================================================

g33_bip113_cutoff_gated_on_csv_height_test_() ->
    %% G33: contextual_check_block selects cutoff = MTP iff
    %% Height >= csv_height. Source guard.
    {"G33 BIP-113 MTP cutoff gated on csv_height",
     [
      ?_test(begin
        {ok, Src} = file:read_file(beamchain_validation_src()),
        ?assert(binary:match(Src,
            <<"CsvHeight = maps:get(csv_height, Params, 419328)">>)
            =/= nomatch),
        ?assert(binary:match(Src,
            <<"true  -> median_time_past(PrevIndex);">>)
            =/= nomatch),
        ?assert(binary:match(Src,
            <<"false -> Header#block_header.timestamp">>)
            =/= nomatch)
      end)
     ]}.

g34_check_final_tx_at_tip_uses_height_plus_one_test_() ->
    %% G34: mempool gate uses (TipHeight+1, tip.MTP). Source guard.
    {"G34 mempool IsFinalTx uses TipHeight+1 + tip MTP",
     [
      ?_test(begin
        SrcPath = filename:join(beamchain_src_dir(), "beamchain_mempool.erl"),
        {ok, Src} = file:read_file(SrcPath),
        ?assert(binary:match(Src,
            <<"beamchain_validation:is_final_tx(Tx, TipHeight + 1, Mtp)">>)
            =/= nomatch)
      end)
     ]}.

g35_connect_block_csv_gate_test_() ->
    %% G35: check_sequence_locks only invoked when Height >= csv_height.
    {"G35 connect_block BIP-68 gated on csv_height",
     [
      ?_test(begin
        {ok, Src} = file:read_file(beamchain_validation_src()),
        ?assert(binary:match(Src,
            <<"Bip68Active = Height >= CsvHeight">>) =/= nomatch),
        ?assert(binary:match(Src,
            <<"check_sequence_locks(Tx, InputCoins, Height, PrevIndex)">>)
            =/= nomatch)
      end)
     ]}.

g36_mtp_eleven_block_window_test() ->
    %% G36: median of last 11 timestamps. Verify via cached-path with a
    %% deliberately-permuted list — median is unaffected by order.
    Timestamps = [100, 105, 110, 95, 90, 120, 115, 80, 125, 130, 85],
    Header = mk_header(140),
    PrevIndex = mk_prev_index(100, Header, Timestamps),
    %% Sorted: [80,85,90,95,100,105,110,115,120,125,130]
    %% beamchain uses lists:nth((length div 2) + 1, sorted) → idx 6 → 105.
    %% Core: pbegin[(pend - pbegin) / 2] = pbegin[5] (0-indexed) → 105.
    ?assertEqual(105, beamchain_validation:median_time_past(PrevIndex)).

g36b_mtp_short_chain_median_test() ->
    %% Fewer than 11 timestamps: median = element at div(N,2)+1.
    %% N=4 → idx 3 → 3rd of sorted [10,20,30,40] = 30.
    Header = mk_header(50),
    PrevIndex = mk_prev_index(3, Header, [40, 10, 30, 20]),
    ?assertEqual(30, beamchain_validation:median_time_past(PrevIndex)),
    %% N=5 → idx 3 → 3rd of [10,20,30,40,50] = 30.
    PrevIndex2 = mk_prev_index(4, Header, [50, 10, 40, 20, 30]),
    ?assertEqual(30, beamchain_validation:median_time_past(PrevIndex2)).

%%% ===================================================================
%%% BIP-125 RBF signalling — G37
%%% ===================================================================

g37_rbf_signalling_via_sequence_test_() ->
    %% G37: any input.sequence <= 0xfffffffd signals opt-in RBF.
    %% Boundary values: 0xfffffffd → yes; 0xfffffffe → no; 0xffffffff → no.
    %%
    %% beamchain inlines the signalling test in
    %% accept_to_memory_pool/get_raw_mempool_entry; we exercise the
    %% literal-value cutoff via the same constant.
    {"G37 BIP-125 RBF signalling at MAX_BIP125_RBF_SEQUENCE boundary",
     [
      ?_test(begin
        Cutoff = ?MAX_BIP125_RBF_SEQUENCE,
        ?assertEqual(16#fffffffd, Cutoff),
        ?assert(16#fffffffd =< Cutoff),
        ?assertNot(16#fffffffe =< Cutoff),
        ?assertNot(16#ffffffff =< Cutoff),
        ?assert(0 =< Cutoff),
        %% Disable-flag set: 0x80000000 is well below cutoff → signals.
        ?assert(16#80000000 =< Cutoff)
      end)
     ]}.

%%% ===================================================================
%%% Reorg / mempool re-eval gaps — G38..G40 (BUG-1 / BUG-2 / BUG-3)
%%% ===================================================================

g38_remove_for_reorg_missing_test_() ->
    %% G38 = BUG-1: MISSING.
    %% beamchain_chainstate.erl has no symbol for re-evaluating EXISTING
    %% mempool entries against the new tip after a reorg. Only
    %% disconnected-block txs are re-fed via refill_mempool_after_reorg.
    %% This is the documented divergence from Core's RemoveForReorg.
    {"G38 BUG-1: existing mempool entries are never re-eval'd post-reorg",
     [
      ?_test(begin
        {ok, Src} = file:read_file(beamchain_chainstate_src()),
        %% refill_mempool_after_reorg exists (closure of W90b Pattern B1)
        ?assert(binary:match(Src, <<"refill_mempool_after_reorg">>) =/= nomatch),
        %% but no equivalent of RemoveForReorg / re-eval-existing logic
        ?assertEqual(nomatch, binary:match(Src, <<"remove_for_reorg">>)),
        ?assertEqual(nomatch, binary:match(Src, <<"RemoveForReorg">>)),
        ?assertEqual(nomatch, binary:match(Src,
            <<"reeval_existing_mempool_entries">>)),
        %% Source guard for the missing helper — flips to PRESENT once the
        %% fix wave lands a function named `recheck_mempool_after_reorg`
        %% or similar.
        true
      end)
     ]}.

g39_disconnected_txs_forward_order_partial_test_() ->
    %% G39 = BUG-2: PARTIAL.
    %% refill_mempool_after_reorg uses foldl over the list given by
    %% submit_block's {ok, reorg, DisconnectedTxs}. Order is whatever the
    %% rollback loop produced (reverse block order). No re-sort here.
    {"G39 BUG-2: disconnected txs re-admitted in non-forward order",
     [
      ?_test(begin
        {ok, Src} = file:read_file(beamchain_chainstate_src()),
        ?assert(binary:match(Src, <<"refill_mempool_after_reorg(Txs) ->">>)
                =/= nomatch),
        ?assert(binary:match(Src, <<"lists:foldl(">>) =/= nomatch),
        %% No `lists:reverse(Txs)` or topo-sort step before the fold.
        case binary:matches(Src, <<"refill_mempool_after_reorg">>) of
            [] -> ?assert(false);
            _Matches ->
                %% Snip the function body and check there is no reverse / sort
                Snippet = case re:run(Src,
                    <<"refill_mempool_after_reorg\\(Txs\\) ->.*?\\.">>,
                    [dotall, {capture, first, binary}]) of
                    {match, [B]} -> B;
                    _ -> <<>>
                end,
                ?assertEqual(nomatch, binary:match(Snippet,
                    <<"lists:reverse(Txs)">>))
        end
      end)
     ]}.

g40_lock_points_missing_test_() ->
    %% G40 = BUG-3: MISSING.
    %% No LockPoints / UpdateLockPoints / maxInputBlock anywhere.
    {"G40 BUG-3: LockPoints cache absent (no UpdateLockPoints helper)",
     [
      ?_test(begin
        Dir = beamchain_src_dir(),
        {ok, Files} = file:list_dir(Dir),
        ErlFiles = [F || F <- Files, lists:suffix(".erl", F)],
        Hits = lists:foldl(fun(F, Acc) ->
            {ok, Bin} = file:read_file(filename:join(Dir, F)),
            case binary:match(Bin, [<<"lock_points">>, <<"LockPoints">>,
                                    <<"UpdateLockPoints">>,
                                    <<"max_input_block">>]) of
                nomatch -> Acc;
                _ -> [F | Acc]
            end
        end, [], ErlFiles),
        %% No source file references LockPoints in any form.
        ?assertEqual([], Hits)
      end)
     ]}.

%%% ===================================================================
%%% Bonus: not-a-bug sanity checks (regression guards)
%%% ===================================================================

%% Confirm version<2 + nLockTime=0 path: tx is final regardless of sequence
v1_zero_locktime_always_final_test() ->
    Tx = mk_tx(1, 0, [0, 1, 16#fffffffd, 16#fffffffe]),
    ?assert(beamchain_validation:is_final_tx(Tx, 1, 0)).

%% Confirm coinbase tx with nLockTime=0 + sequence=FINAL is final
coinbase_final_test() ->
    %% Coinbase-shaped tx
    Cb = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = <<3, 1, 0, 0>>,
                         sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 5000000000,
                           script_pubkey = <<16#6a>>}],
        locktime = 0
    },
    ?assert(beamchain_validation:is_final_tx(Cb, 1, 1000000000)).

%% Confirm SEQUENCE_LOCKTIME_GRANULARITY scales correctly: a 1-unit
%% time-lock = 512 seconds. Use the calculate_sequence_lock_pair fold
%% indirectly via a fake DB-lookup path is out-of-scope; assert the
%% constant relationship instead.
granularity_scale_test() ->
    ?assertEqual(512, 1 bsl ?SEQUENCE_LOCKTIME_GRANULARITY),
    %% Max time lock value: 0xffff units × 512 s ≈ 387 days
    MaxTimeLock = 16#ffff bsl ?SEQUENCE_LOCKTIME_GRANULARITY,
    ?assertEqual(33553920, MaxTimeLock),
    ?assert(MaxTimeLock > 365 * 86400).

%%% ===================================================================
%%% Audit summary
%%% ===================================================================
%%%
%%% 30 numbered audit gates exercised across this module:
%%%   - 19 PRESENT  (constants + happy-path Core-parity)
%%%   - 8  PARTIAL  (BUG-4 BUG-6 BUG-7 BUG-8 G14 G32 G39 BUG-10 BUG-11)
%%%   - 3  MISSING  (BUG-1 BUG-3 BUG-7-mempool — G38 G40)
%%%
%%% 11 BUGs catalogued, all sub-P0:
%%%   3 P1-MEM (reorg / state cache)
%%%   5 P2-SCRIPT (defence-in-depth)
%%%   3 P3-COSM (observability)
%%%
%%% Reference: audit/w132_nsequence_csv_mtp.md
