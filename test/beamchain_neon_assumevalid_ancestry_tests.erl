-module(beamchain_neon_assumevalid_ancestry_tests).

%% Finding 12 of the Gemini (Neon) audit of beamchain against Bitcoin Core
%% v31.1 (item verify-neon-beamchain-findings). Core's ConnectBlock
%% (validation.cpp:2349-2385) skips script checks only if ALL hold:
%%   2. the assumevalid hash is in the block index;
%%   3. AV->GetAncestor(pindex->nHeight) == pindex   (block is on AV's chain)
%%   4. m_best_header->GetAncestor(pindex->nHeight) == pindex
%%   5. m_best_header->nChainWork >= MinimumChainWork()
%%   6. GetBlockProofEquivalentTime(*best, *pindex, *best) > 2 weeks
%%      (chain.cpp: (best.nChainWork - pindex.nChainWork) * nPowTargetSpacing
%%       / GetBlockProof(best)), work, not timestamps.
%% beamchain's skip_scripts_eval/6 checked only heights for 3 and 4, and
%% header timestamps for 6 (with 0 for a block missing from the index), so a
%% fork block at or below the AV height had its scripts skipped.
%%
%% beamchain_header_chain:hash_at/1 (the best header chain's hash at a
%% height) and lookup/1 (an index entry by hash) are mocked to lay out the
%% two chains; beamchain_db:get_block_index_by_hash/1 is mocked the same
%% way for the header tip.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(AV_HEIGHT, 900000).
-define(BITS, 16#1d00ffff).
-define(SPACING, 600).

av_display() -> <<16#aa:256>>.
av_hash() -> beamchain_serialize:reverse_bytes(av_display()).

params() ->
    #{assume_valid => av_display(), min_chainwork => <<0:256>>,
      network => mainnet, pow_target_spacing => ?SPACING}.

proof() -> beamchain_pow:compute_work(?BITS).

cw(N) -> <<(N * proof()):256>>.

header(Ts) ->
    #block_header{version = 4, prev_hash = <<0:256>>, merkle_root = <<0:256>>,
                  timestamp = Ts, bits = ?BITS, nonce = 0}.

entry(Hash, Height, CwBlocks, Ts) ->
    #{hash => Hash, height => Height, header => header(Ts),
      chainwork => cw(CwBlocks), status => 1}.

%% Layout: the block under test (Hash at Height, CwBlocks of work), the
%% header tip (HdrHash at HdrHeight with HdrCw work) and what the best
%% header chain holds at Height and at the AV height.
with_layout(#{hash := Hash, height := Height, cw := Cw, ts := Ts,
              hdr_height := HdrHeight, hdr_cw := HdrCw, hdr_ts := HdrTs,
              best_at_height := BestAtH, best_at_av := BestAtAV}, Fun) ->
    HdrHash = <<16#dd:256>>,
    HdrEntry = entry(HdrHash, HdrHeight, HdrCw, HdrTs),
    BlockEntry = entry(Hash, Height, Cw, Ts),
    ok = meck:new(beamchain_header_chain, [passthrough, non_strict]),
    ok = meck:new(beamchain_db, [passthrough, non_strict]),
    try
        meck:expect(beamchain_header_chain, hash_at,
                    fun(H) when H =:= Height -> {ok, BestAtH};
                       (H) when H =:= ?AV_HEIGHT -> {ok, BestAtAV};
                       (_) -> not_found
                    end),
        meck:expect(beamchain_header_chain, lookup,
                    fun(H) when H =:= HdrHash -> {ok, HdrEntry};
                       (H) when H =:= Hash -> {ok, BlockEntry};
                       (_) -> not_found
                    end),
        meck:expect(beamchain_db, get_block_index_by_hash,
                    fun(H) when H =:= HdrHash -> {ok, HdrEntry};
                       (H) when H =:= Hash -> {ok, BlockEntry};
                       (_) -> not_found
                    end),
        Fun(#{hash => Hash, height => Height,
              av_lookup => {ok, #{hash => av_hash(), height => ?AV_HEIGHT}},
              hdr_tip => {ok, #{hash => HdrHash, height => HdrHeight}},
              block_entry => {ok, BlockEntry}})
    after
        meck:unload(beamchain_db),
        meck:unload(beamchain_header_chain)
    end.

skip(#{hash := Hash, height := Height, av_lookup := AV, hdr_tip := Tip,
       block_entry := BE}) ->
    beamchain_validation:skip_scripts_eval(Height, Hash, params(), AV, Tip, BE).

%% A block 500,000 deep, the header tip 3,000 blocks past AV: far more than
%% two weeks of work and of wall-clock between them.
base_layout(Hash) ->
    #{hash => Hash, height => 500000, cw => 500000, ts => 1500000000,
      hdr_height => ?AV_HEIGHT + 3000, hdr_cw => ?AV_HEIGHT + 3000,
      hdr_ts => 1500000000 + (?AV_HEIGHT + 3000 - 500000) * ?SPACING,
      best_at_height => Hash, best_at_av => av_hash()}.

%%% --- hostile: Core verifies scripts, master skipped them ---------------

%% Condition 3. The best header chain holds the fork block F at its height,
%% but does not hold AV: AV's ancestor at that height is another block.
%% (A heavier chain that forked below the AV height.)
f12_fork_block_not_on_av_chain_verifies_scripts_test() ->
    F = <<16#f0:256>>,
    L = (base_layout(F))#{best_at_av => <<16#ab:256>>},
    with_layout(L, fun(C) -> ?assertNot(skip(C)) end).

%% Condition 4. The block is not the best header chain's block at its height.
f12_block_not_in_best_header_chain_verifies_scripts_test() ->
    X = <<16#e0:256>>,
    L = (base_layout(X))#{best_at_height => <<16#e1:256>>},
    with_layout(L, fun(C) -> ?assertNot(skip(C)) end).

%% Condition 6 is work-equivalent time. The block's timestamp is 3 weeks
%% before the header tip's, but only 100 blocks of work separate them
%% (100 * 600 s = 60,000 s < 2 weeks): Core verifies.
f12_equivalent_time_uses_work_not_timestamps_test() ->
    B = <<16#c0:256>>,
    L = (base_layout(B))#{height => ?AV_HEIGHT - 50, cw => ?AV_HEIGHT - 50,
                          ts => 1700000000,
                          hdr_height => ?AV_HEIGHT + 50, hdr_cw => ?AV_HEIGHT + 50,
                          hdr_ts => 1700000000 + 21 * 86400},
    with_layout(L, fun(C) -> ?assertNot(skip(C)) end).

%% Condition 6 with the block's height slot empty: master took timestamp 0
%% and skipped; Core measures work (10 blocks here) and verifies.
f12_missing_block_entry_is_not_time_zero_test() ->
    B = <<16#c1:256>>,
    L = (base_layout(B))#{height => ?AV_HEIGHT - 5, cw => ?AV_HEIGHT - 5,
                          ts => 1700000000,
                          hdr_height => ?AV_HEIGHT + 5, hdr_cw => ?AV_HEIGHT + 5,
                          hdr_ts => 1700000000 + 10 * ?SPACING},
    with_layout(L, fun(C) -> ?assertNot(skip(C#{block_entry => not_found})) end).

%% Condition 3 after a header rewind: a heavier fork whose header tip is
%% BELOW the AV height. The height slot at the AV height still names AV
%% (the old chain's header, left above the new header tip), but the best
%% header chain does not reach it. Core: AV's ancestor at H is not F ->
%% verify.
f12_header_tip_below_av_stale_av_slot_verifies_scripts_test() ->
    F = <<16#f1:256>>,
    L = (base_layout(F))#{height => ?AV_HEIGHT - 3000, cw => ?AV_HEIGHT - 3000,
                          ts => 1600000000,
                          hdr_height => ?AV_HEIGHT - 10, hdr_cw => ?AV_HEIGHT + 100,
                          hdr_ts => 1600000000 + 3000 * ?SPACING,
                          best_at_av => av_hash()},
    with_layout(L, fun(C) -> ?assertNot(skip(C)) end).

%% Condition 6 needs the block's own index entry (its chainwork). When it
%% cannot be found by hash, there is nothing to measure: verify. master
%% read the height slot instead and, finding none, used timestamp 0.
f12_block_own_entry_not_found_verifies_scripts_test() ->
    B = <<16#c2:256>>,
    L = base_layout(B),
    with_layout(L, fun(C) ->
        %% Only the header tip's entry is found; the block's own is not.
        meck:expect(beamchain_header_chain, lookup,
                    fun(H) when H =:= <<16#dd:256>> ->
                            {ok, entry(H, ?AV_HEIGHT + 3000, ?AV_HEIGHT + 3000,
                                       1500000000 + (?AV_HEIGHT + 3000 - 500000) * ?SPACING)};
                       (_) -> not_found
                    end),
        ?assertNot(skip(C#{block_entry => not_found}))
    end).

%%% --- controls -----------------------------------------------------------

%% On both chains, 403,000 blocks of work behind the header tip: skip.
f12_control_block_on_av_and_best_chain_skips_test() ->
    B = <<16#b0:256>>,
    with_layout(base_layout(B), fun(C) -> ?assert(skip(C)) end).

%% Exactly 2016 blocks of work = 1,209,600 s: Core's test is "<= 2 weeks ->
%% verify", so this verifies; 2017 blocks skips.
f12_control_two_weeks_boundary_test() ->
    B = <<16#b1:256>>,
    Mk = fun(Gap) ->
        (base_layout(B))#{height => ?AV_HEIGHT - 10, cw => ?AV_HEIGHT - 10,
                          ts => 1700000000,
                          hdr_height => ?AV_HEIGHT - 10 + Gap,
                          hdr_cw => ?AV_HEIGHT - 10 + Gap,
                          hdr_ts => 1700000000 + Gap * ?SPACING}
    end,
    with_layout(Mk(2016), fun(C) -> ?assertNot(skip(C)) end),
    with_layout(Mk(2017), fun(C) -> ?assert(skip(C)) end).

%% Above the AV height: always verify (unchanged).
f12_control_above_av_height_verifies_test() ->
    B = <<16#b2:256>>,
    L = (base_layout(B))#{height => ?AV_HEIGHT + 1, cw => ?AV_HEIGHT + 1},
    with_layout(L, fun(C) -> ?assertNot(skip(C)) end).
