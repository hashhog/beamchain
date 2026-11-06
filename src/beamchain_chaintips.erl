-module(beamchain_chaintips).

%%% getchaintips: every known block-index leaf, not only the active tip.
%%%
%%% Core rpc/blockchain.cpp getchaintips:
%%%   tips = every block-index entry that is not on the active chain and is
%%%          not the pprev of another such entry, plus the active tip;
%%%   branchlen = height - FindFork(active chain).height;
%%%   status, first match wins:
%%%     active        on the active chain
%%%     invalid       BLOCK_FAILED_VALID (the block or, via the descendant
%%%                   marking, an ancestor failed)
%%%     headers-only  !HaveNumChainTxs: the block or an ancestor back to the
%%%                   active chain has no data
%%%     valid-fork    IsValid(BLOCK_VALID_SCRIPTS): connected at some point
%%%     valid-headers IsValid(BLOCK_VALID_TREE)
%%%     unknown
%%%
%%% beamchain keeps its block index in two places (beamchain_db):
%%%   - height slots (cf_block_idx, one entry per height): the active chain
%%%     at heights =< the chain tip, and above it the header chain plus
%%%     blocks disconnected by invalidateblock;
%%%   - "sbidx:" side-branch entries: off-chain bodies (submitted side
%%%     branches, blocks displaced from their height slot).
%%% Both are read; nothing here writes.
%%%
%%% The slots above the tip are streamed through a direct RocksDB iterator
%%% (no gen_server hop, nothing held per header): during IBD that range is
%%% the whole header chain, so only the runs' summaries are kept.
%%%
%%% "invalid" is the hash-keyed verdict (beamchain_chainstate:
%%% is_known_invalid/1), which invalidateblock, a consensus-invalid P2P
%%% block and their descendants carry.  The FAILED_VALID index bit alone is
%%% not used: header sync's mark_orphaned_blocks writes it on valid blocks
%%% that lost a header reorg (Core reports those valid-fork).

-include("beamchain.hrl").

-export([tips/0, tips/2, best_header/0, best_header/2]).

-define(BLOCK_VALID_TREE, 2).
-define(BLOCK_VALID_SCRIPTS, 5).
-define(BLOCK_HAVE_DATA, 8).

%% A maximal run of height slots above the tip in which each slot's
%% prev_hash is the hash of the slot below it.
-record(run, {
    start_height :: non_neg_integer(),
    start_prev   :: binary(),
    top_hash     :: binary(),
    top_height   :: non_neg_integer(),
    top_status   :: non_neg_integer(),
    top_chainwork :: binary(),
    %% lowest height in the run whose slot has no block data, or undefined
    first_missing :: non_neg_integer() | undefined
}).

%% @doc The getchaintips result for the current chain tip, as ordered
%% proplists (Core pushKV order: height, hash, branchlen, status), highest
%% first like Core's CompareBlocksByHeight set.
-spec tips() -> [[{binary(), term()}]].
tips() ->
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, Height}} -> tips(Hash, Height);
        not_found -> []
    end.

-spec tips(binary(), non_neg_integer()) -> [[{binary(), term()}]].
tips(TipHash, TipHeight) ->
    Runs = slot_runs_above(TipHeight),
    Side = side_entries(),
    %% Every off-chain entry's parent has a child, so it is not a tip.
    Prevs = sets:from_list(
              [R#run.start_prev || R <- Runs] ++
              [prev(E) || E <- Side], [{version, 2}]),
    Ctx = #{tip_height => TipHeight, runs => Runs},
    RunTips = [#{hash => R#run.top_hash, height => R#run.top_height,
                 status => R#run.top_status, run => R}
               || R <- Runs, not sets:is_element(R#run.top_hash, Prevs)],
    SideTips = [E || E = #{hash := H} <- Side,
                     not sets:is_element(H, Prevs)],
    Others = lists:usort(
               fun(A, B) -> sort_key(A) =< sort_key(B) end,
               lists:filtermap(fun(E) -> describe(E, Ctx) end,
                               RunTips ++ SideTips)),
    Active = [{<<"height">>, TipHeight},
              {<<"hash">>, hex(TipHash)},
              {<<"branchlen">>, 0},
              {<<"status">>, <<"active">>}],
    lists:sort(fun(A, B) -> height_of(A) >= height_of(B) end,
               [Active | [T || T <- Others, hash_of(T) =/= hex(TipHash)]]).

%% @doc The best header: {Hash, Height} of the most-work block-index entry
%% that is not known invalid, or not_found before genesis.
%%
%% Core getblockchaininfo / getchainstates report
%%   headers = chainman.m_best_header ? m_best_header->nHeight : -1
%% (rpc/blockchain.cpp).  m_best_header is raised by AddToBlockIndex whenever
%% a new header (P2P headers, submitheader, submitblock) has more work than it
%% (node/blockstorage.cpp AddToBlockIndex, `best_header->nChainWork <
%% pindexNew->nChainWork`), and on load it is the active tip raised to every
%% non-BLOCK_FAILED_VALID entry with more work (validation.cpp
%% LoadBlockIndex / ChainstateManager::LoadBlockIndex).  So it is a
%% headers-only entry above the tip as soon as one with more work is known,
%% not the active tip.
%%
%% Chainwork only grows along a chain, so the maximum is the active tip or a
%% leaf of the index: the top of a slot run above the tip, or a side-branch
%% entry that is nobody's parent.  Leaves whose ancestry no longer reaches the
%% active chain (left out of getchaintips, see describe/2) still count: their
%% stored chainwork is the work Core has for them.  Ties keep the active tip
%% (Core only replaces on strictly more work, starting from the tip on load),
%% then the highest, then the lowest hash, so the answer is deterministic.
%% Not covered: an invalid leaf whose non-invalid ancestor above the tip is
%% itself not a leaf is not looked through (only the leaf is read).
-spec best_header() -> {binary(), non_neg_integer()} | not_found.
best_header() ->
    case beamchain_chainstate:get_tip() of
        {ok, {Hash, Height}} -> best_header(Hash, Height);
        not_found -> not_found
    end.

-spec best_header(binary(), non_neg_integer()) -> {binary(), non_neg_integer()}.
best_header(TipHash, TipHeight) ->
    Runs = slot_runs_above(TipHeight),
    Side = side_entries(),
    Prevs = sets:from_list(
              [R#run.start_prev || R <- Runs] ++
              [prev(E) || E <- Side], [{version, 2}]),
    TipCW = case beamchain_db:get_block_index(TipHeight) of
        {ok, #{hash := TipHash, chainwork := C}} -> C;
        _ ->
            case beamchain_db:get_block_index_by_hash(TipHash) of
                {ok, #{chainwork := C}} -> C;
                _ -> <<0:256>>
            end
    end,
    Leaves = [{cw_int(R#run.top_chainwork), R#run.top_height, R#run.top_hash}
              || R <- Runs, not sets:is_element(R#run.top_hash, Prevs)] ++
             [{cw_int(maps:get(chainwork, E, <<0:256>>)), Ht, H}
              || E = #{hash := H, height := Ht} <- Side,
                 not sets:is_element(H, Prevs)],
    Ordered = lists:sort(fun({_, HA, A}, {_, HB, B}) -> {-HA, A} =< {-HB, B} end,
                         Leaves),
    {_, BestHeight, BestHash} =
        lists:foldl(
          fun({CW, Ht, H} = L, {BestCW, _, _} = Best) when CW > BestCW ->
                  case H =/= TipHash andalso
                       not beamchain_chainstate:is_known_invalid(H) of
                      true -> L;
                      false -> Best
                  end;
             (_, Best) -> Best
          end,
          {cw_int(TipCW), TipHeight, TipHash}, Ordered),
    {BestHash, BestHeight}.

cw_int(undefined) -> 0;
cw_int(CW) when is_binary(CW) -> binary:decode_unsigned(CW, big).

sort_key(T) -> {-height_of(T), hash_of(T)}.
height_of(T) -> proplists:get_value(<<"height">>, T).
hash_of(T) -> proplists:get_value(<<"hash">>, T).

%%% -------------------------------------------------------------------
%%% Index reads
%%% -------------------------------------------------------------------

%% Height slots above the chain tip, folded into chained runs.
slot_runs_above(TipHeight) ->
    Runs = beamchain_db:fold_height_slots_from(
             TipHeight + 1, fun add_slot/2, []),
    lists:reverse(Runs).

add_slot(#{hash := H, height := Ht, status := S,
           header := #block_header{prev_hash = P}} = E, Runs) ->
    CW = maps:get(chainwork, E, <<0:256>>),
    Missing = case (S band ?BLOCK_HAVE_DATA) =/= 0 of
        true -> undefined;
        false -> Ht
    end,
    case Runs of
        [#run{top_hash = P, top_height = PH} = R | Rest] when PH =:= Ht - 1 ->
            FM = case R#run.first_missing of
                undefined -> Missing;
                Lower -> Lower
            end,
            [R#run{top_hash = H, top_height = Ht, top_status = S,
                   top_chainwork = CW, first_missing = FM} | Rest];
        _ ->
            [#run{start_height = Ht, start_prev = P, top_hash = H,
                  top_height = Ht, top_status = S, top_chainwork = CW,
                  first_missing = Missing} | Runs]
    end.

%% Side-branch entries that are not (a stale copy of) the block currently
%% owning their height slot: such a copy is described by the slot.
side_entries() ->
    SB = case beamchain_db:get_all_side_branch_indexes() of
        {ok, L} -> L;
        _ -> []
    end,
    [E || E = #{hash := H, height := Ht} <- SB, slot_hash(Ht) =/= H].

slot_hash(Height) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := H}} -> H;
        _ -> undefined
    end.

prev(#{header := #block_header{prev_hash = P}}) -> P.

%%% -------------------------------------------------------------------
%%% Status + branchlen
%%% -------------------------------------------------------------------

%% {true, Tip}, or false when the entry's ancestry no longer reaches the
%% active chain.  That happens when an ancestor was a header-only entry and
%% another header took its height slot: beamchain_db's displaced_entry_ops/5
%% keeps a displaced entry only when its body is stored.  Core never loses an
%% index entry, so there is no Core answer to copy; a guessed branchlen
%% would be wrong, so the leaf is left out.
describe(#{hash := H, height := Ht} = E, Ctx) ->
    case walk(E, Ctx) of
        {lost, _} ->
            false;
        {ForkHeight, AllData} ->
            Status = status(H, maps:get(status, E, 0), AllData),
            {true, [{<<"height">>, Ht},
                    {<<"hash">>, hex(H)},
                    {<<"branchlen">>, Ht - ForkHeight},
                    {<<"status">>, Status}]}
    end.

status(Hash, S, AllData) ->
    case beamchain_chainstate:is_known_invalid(Hash) of
        true -> <<"invalid">>;
        false when not AllData -> <<"headers-only">>;
        false when (S band 7) >= ?BLOCK_VALID_SCRIPTS -> <<"valid-fork">>;
        false when (S band 7) >= ?BLOCK_VALID_TREE -> <<"valid-headers">>;
        false -> <<"unknown">>
    end.

%% Walk from an off-chain entry back to the active chain.  Returns
%% {ForkHeight, AllAncestorsBackToForkHaveData}, or {lost, _} when a parent
%% is in neither index.
walk(#{run := R, height := Ht}, Ctx) ->
    walk_from_run(R, Ht, Ctx, true);
walk(E, Ctx) ->
    walk_entry(E, Ctx, true, 0).

walk_from_run(#run{first_missing = FM, start_height = SH,
                   start_prev = P}, Ht, Ctx, Acc) ->
    Data = Acc andalso (FM =:= undefined orelse FM > Ht),
    step_to(P, SH - 1, Ctx, Data, 0).

%% Guard against a corrupt (cyclic) side-branch index.
-define(MAX_WALK, 1000000).

walk_entry(_E, _Ctx, Data, N) when N > ?MAX_WALK ->
    {lost, Data};
walk_entry(#{hash := H, height := Ht, status := S} = E, Ctx, Data, N) ->
    Data1 = Data andalso have_data(H, S),
    step_to(prev(E), Ht - 1, Ctx, Data1, N + 1).

%% Continue at the parent (hash P at height PH).
step_to(_P, PH, _Ctx, Data, _N) when PH < 0 ->
    {lost, Data};
step_to(P, PH, #{tip_height := TipHeight, runs := Runs} = Ctx, Data, N) ->
    case PH =< TipHeight andalso slot_hash(PH) =:= P of
        true ->
            {PH, Data};
        false ->
            case [R || R = #run{start_height = SH, top_height = TH} <- Runs,
                       SH =< PH, PH =< TH] of
                [R] when PH > TipHeight ->
                    %% Parent is a slot above the tip: it belongs to run R
                    %% (one slot per height, so the run is unique).
                    case slot_hash(PH) =:= P of
                        true -> walk_from_run(R, PH, Ctx, Data);
                        false -> side_parent(P, PH, Ctx, Data, N)
                    end;
                _ ->
                    side_parent(P, PH, Ctx, Data, N)
            end
    end.

side_parent(P, _PH, Ctx, Data, N) ->
    case beamchain_db:get_side_branch_index(P) of
        {ok, PE} -> walk_entry(PE, Ctx, Data, N);
        not_found -> {lost, Data}
    end.

%% A side-branch body is stored with VALID_TREE and no HAVE_DATA bit
%% (beamchain_chainstate:persist_side_branch_block/4), so ask the block
%% store when the bit is absent (as chainstate's have_block_data/2 does).
have_data(_H, S) when (S band ?BLOCK_HAVE_DATA) =/= 0 -> true;
have_data(H, _S) -> beamchain_db:has_block(H) =:= true.

hex(Hash) ->
    beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Hash)).
