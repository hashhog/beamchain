%%% @doc Chunk of a mempool transaction, for getmempoolentry / getrawmempool
%%% verbose (`chunkweight`, `fees.chunk`, Bitcoin Core v31 entryToJSON).
%%%
%%% A cluster's chunks are the pieces of its feerate-diagram-optimal
%%% linearization (Core v31 cluster_linearize.h).  The first chunk of an
%%% optimal linearization is the highest-feerate topologically closed set
%%% (a set that contains every in-cluster parent of its members), and the
%%% rest follow by repeating on what remains, which gives non-increasing
%%% chunk feerates.  A closed set is not always an ancestor set of one tx (a
%%% zero-fee parent plus all of its children is not), so the best ancestor
%%% set is only the starting point: it is improved by Dinkelbach iteration,
%%% each step a maximum-weight closure solved as a min cut.  Ties keep the
%%% smaller set.  This is output formatting only: nothing in mempool
%%% admission, eviction, or block building reads it.
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
    {Set0, W0, F0} = best_single_ancestor_set(Rem),
    improve(Set0, W0, F0, Rem).

best_single_ancestor_set(Rem) ->
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

%% Dinkelbach step.  With lambda = F/W, tx i has value v_i = f_i*W - F*w_i
%% (scaled by W so it stays an integer); a closed set S has v(S) > 0 exactly
%% when its feerate beats F/W.  Take the closed set of maximum v (the minimal
%% one, so ties do not grow the chunk) and repeat until none beats F/W.
improve(Set, W, F, Rem) ->
    case max_closure(Rem, W, F) of
        [] -> {Set, W, F};
        New ->
            {W1, F1} = sum(New, Rem),
            improve(New, W1, F1, Rem)
    end.

%% Minimal closed subset of Rem with positive total value, or [].
max_closure(Rem, W, F) ->
    Vals = maps:map(fun(_, {Fee, Wt, _}) -> Fee * W - F * Wt end, Rem),
    Pos = lists:sum([V || V <- maps:values(Vals), V > 0]),
    case Pos of
        0 -> [];
        _ ->
            Inf = Pos + 1,
            Edges0 = lists:append(
                [[{s, T, V} || V > 0] ++ [{T, t, -V} || V < 0]
                 || {T, V} <- maps:to_list(Vals)]),
            %% a member needs its in-Rem parents
            Edges1 = [{T, P, Inf}
                      || {T, {_, _, Ps}} <- maps:to_list(Rem),
                         P <- lists:usort(Ps), maps:is_key(P, Rem)],
            Cap0 = lists:foldl(fun({U, V, C}, M) ->
                                   M1 = maps:update_with({U, V}, fun(X) -> X + C end, C, M),
                                   maps:update_with({V, U}, fun(X) -> X end, 0, M1)
                               end, #{}, Edges0 ++ Edges1),
            Adj = lists:foldl(fun({U, V}, A) ->
                                  maps:update_with(U, fun(L) -> [V | L] end, [V], A)
                              end, #{}, maps:keys(Cap0)),
            Res = max_flow(Cap0, Adj),
            %% source side of the min cut: reachable from s in the residual graph
            Reach = bfs_reach([s], Res, Adj, #{s => true}),
            Set = [T || T <- maps:keys(Rem), maps:is_key(T, Reach)],
            {_, FS} = sum(Set, Rem),
            {WS, _} = sum(Set, Rem),
            case Set =/= [] andalso FS * W > F * WS of
                true -> lists:sort(Set);
                false -> []
            end
    end.

%% Edmonds-Karp on a residual-capacity map; returns the final residuals.
max_flow(Res, Adj) ->
    case bfs_path(Res, Adj) of
        none -> Res;
        Path ->
            Bottleneck = lists:min([maps:get(E, Res) || E <- Path]),
            Res1 = lists:foldl(
                fun({U, V}, M) ->
                    M#{{U, V} := maps:get({U, V}, M) - Bottleneck,
                       {V, U} := maps:get({V, U}, M) + Bottleneck}
                end, Res, Path),
            max_flow(Res1, Adj)
    end.

bfs_path(Res, Adj) ->
    bfs_path([s], Res, Adj, #{s => none}).

bfs_path([], _Res, _Adj, _Prev) -> none;
bfs_path([U | Queue], Res, Adj, Prev) ->
    Next = [V || V <- maps:get(U, Adj, []),
                 not maps:is_key(V, Prev), maps:get({U, V}, Res) > 0],
    Prev1 = lists:foldl(fun(V, P) -> P#{V => U} end, Prev, Next),
    case lists:member(t, Next) of
        true -> build_path(t, Prev1, []);
        false -> bfs_path(Queue ++ Next, Res, Adj, Prev1)
    end.

build_path(s, _Prev, Acc) -> Acc;
build_path(V, Prev, Acc) ->
    U = maps:get(V, Prev),
    build_path(U, Prev, [{U, V} | Acc]).

bfs_reach([], _Res, _Adj, Seen) -> Seen;
bfs_reach([U | Queue], Res, Adj, Seen) ->
    Next = [V || V <- maps:get(U, Adj, []),
                 not maps:is_key(V, Seen), maps:get({U, V}, Res) > 0],
    Seen1 = lists:foldl(fun(V, S) -> S#{V => true} end, Seen, Next),
    bfs_reach(Queue ++ Next, Res, Adj, Seen1).
