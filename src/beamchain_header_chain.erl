-module(beamchain_header_chain).

%% The best header chain, read from the block index.
%%
%% Height slots at or below the connected (chainstate) tip are the ACTIVE
%% chain. Header sync never writes them: a fork header for such a height is
%% kept hash-keyed in the side-branch index, the rule
%% beamchain_chainstate:store_header_only/5 applies to submitheader (Core
%% AcceptBlockHeader adds index entries and never changes the active chain).
%% Above the connected tip the slots ARE the header chain.
%%
%% So the header chain's block at a height above the connected tip is the
%% slot. At or below it, the header chain equals the active chain unless a
%% fork is pending; then it is found by walking back by prev_hash from the
%% header chain's first block above the connected tip (or from the header
%% tip), a walk only as long as the fork. Reads the db directly; callable
%% from any process. Linear block download only asks above the connected
%% tip; the walk runs for find_start_height and for a block at or below it.

-include("beamchain.hrl").

-export([hash_at/1, lookup/1, connected_tip_height/0]).

%% @doc Hash of the best header chain's block at Height, or not_found.
-spec hash_at(integer()) -> {ok, binary()} | not_found.
hash_at(Height) when Height < 0 ->
    not_found;
hash_at(Height) ->
    CT = connected_tip_height(),
    case Height > CT of
        true ->
            slot_hash(Height);
        false ->
            at_or_below_tip(Height, CT)
    end.

%% @doc A block-index entry by hash: the height-keyed index (through its
%% reverse key) or, for a header kept off the active slots, the side-branch
%% index.
-spec lookup(binary()) -> {ok, map()} | not_found.
lookup(Hash) ->
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, _} = Found ->
            Found;
        not_found ->
            case beamchain_db:get_side_branch_index(Hash) of
                {ok, _} = Found -> Found;
                _ -> not_found
            end
    end.

%% @doc Height of the connected chainstate tip (an ETS read, never a call),
%% or -1 when no chainstate is running.
-spec connected_tip_height() -> integer().
connected_tip_height() ->
    try beamchain_chainstate:get_tip() of
        {ok, {_Hash, Height}} -> Height;
        _ -> -1
    catch
        _:_ -> -1
    end.

%%% ===================================================================

%% At or below the connected tip the header chain is the active chain
%% unless a fork is pending. Follow the header tip: if it is above the
%% connected tip, the header chain's block at CT + 1 is that slot and its
%% parent says whether the header chain leaves the active chain at or below
%% CT; otherwise the header tip itself is either an active block (then the
%% slots answer, as before) or a fork header kept hash-keyed (a walk).
at_or_below_tip(Height, CT) ->
    case beamchain_db:get_header_tip() of
        {ok, #{height := THt}} when THt > CT ->
            case beamchain_db:get_block_index(CT + 1) of
                {ok, #{header := #block_header{prev_hash = P}}} ->
                    case slot_hash(CT) of
                        {ok, P} -> slot_hash(Height);
                        _ -> walk(P, CT, Height)
                    end;
                not_found ->
                    not_found
            end;
        {ok, #{hash := TH, height := THt}} ->
            case slot_hash(THt) of
                {ok, TH} ->
                    %% The header tip is an active block (it may lag the
                    %% connected tip, e.g. below a snapshot base): the
                    %% active chain, as before.
                    slot_hash(Height);
                _ when THt >= Height ->
                    walk(TH, THt, Height);
                _ ->
                    %% The header tip is a fork header kept off the slots
                    %% and the header chain ends below Height.
                    not_found
            end;
        not_found ->
            slot_hash(Height)
    end.

slot_hash(Height) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{hash := H}} -> {ok, H};
        not_found -> not_found
    end.

walk(Hash, Ht, Target) when Ht =:= Target ->
    {ok, Hash};
walk(Hash, Ht, Target) when Ht > Target ->
    case lookup(Hash) of
        {ok, #{header := #block_header{prev_hash = P}}} ->
            walk(P, Ht - 1, Target);
        not_found ->
            not_found
    end;
walk(_Hash, _Ht, _Target) ->
    not_found.
