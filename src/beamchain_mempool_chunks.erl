%%% @doc Chunk of a mempool transaction, for getmempoolentry / getrawmempool
%%% verbose (`chunkweight`, `fees.chunk`, Bitcoin Core v31 entryToJSON).
%%%
%%% A cluster's chunks are the pieces of its feerate-diagram-optimal
%%% linearization.  They are built here by repeatedly taking the
%%% highest-feerate ancestor set among the remaining transactions, which gives
%%% non-increasing chunk feerates.  This is output formatting only: nothing in
%%% mempool admission, eviction, or block building reads it.
-module(beamchain_mempool_chunks).

-export([chunk_of/2]).

%% Nodes :: #{Txid => {ModifiedFee, Weight, [ParentTxid]}} for ONE cluster.
%% Parents outside Nodes are ignored.  Returns {ChunkWeight, ChunkFee} of the
%% chunk holding Txid.
-spec chunk_of(binary(), #{binary() => {integer(), pos_integer(), [binary()]}}) ->
    {pos_integer(), integer()}.
chunk_of(Txid, Nodes) ->
    {Set, W, F} = chunk_loop(Txid, Nodes),
    true = lists:member(Txid, Set),
    {W, F}.

chunk_loop(Target, Rem) ->
    {Set, W, F} = best_ancestor_set(Rem),
    case lists:member(Target, Set) of
        true  -> {Set, W, F};
        false -> chunk_loop(Target, maps:without(Set, Rem))
    end.

%% Best (highest fee/weight) ancestor set among the remaining transactions;
%% ties go to the smaller set, then to the smaller txid, so it is stable.
best_ancestor_set(Rem) ->
    Cands = [begin
                 Set = ancestor_set(T, Rem),
                 {W, F} = sum(Set, Rem),
                 {Set, W, F, T}
             end || T <- lists:sort(maps:keys(Rem))],
    {Set, W, F, _} = lists:foldl(
        fun({_, W1, F1, _} = C1, {_, W0, F0, _} = C0) ->
            L = F1 * W0, R = F0 * W1,
            if L > R -> C1;
               L < R -> C0;
               W1 < W0 -> C1;
               true -> C0
            end
        end, hd(Cands), tl(Cands)),
    {Set, W, F}.

ancestor_set(T, Rem) -> anc([T], Rem, #{}).

anc([], _Rem, Seen) -> maps:keys(Seen);
anc([T | Rest], Rem, Seen) ->
    case maps:is_key(T, Seen) orelse not maps:is_key(T, Rem) of
        true -> anc(Rest, Rem, Seen);
        false ->
            {_, _, Parents} = maps:get(T, Rem),
            anc(Parents ++ Rest, Rem, Seen#{T => true})
    end.

sum(Set, Rem) ->
    lists:foldl(fun(T, {WA, FA}) ->
        {F, W, _} = maps:get(T, Rem),
        {WA + W, FA + F}
    end, {0, 0}, Set).
