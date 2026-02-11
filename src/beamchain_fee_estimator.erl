-module(beamchain_fee_estimator).
-behaviour(gen_server).

%% Block-based fee rate estimation using exponential decay buckets.
%% Modeled after Bitcoin Core's CBlockPolicyEstimator.

-include("beamchain.hrl").

%% API
-export([start_link/0]).
-export([track_tx/3, process_block/2]).
-export([estimate_fee/1, get_fee_histogram/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%%% -------------------------------------------------------------------
%%% Fee estimation parameters
%%% -------------------------------------------------------------------

-define(NUM_BUCKETS, 40).
-define(MIN_FEE_RATE, 1.0).       %% sat/vB
-define(MAX_FEE_RATE, 10000.0).   %% sat/vB
-define(DECAY_FACTOR, 0.998).     %% per-block exponential decay
-define(SUCCESS_THRESHOLD, 0.85). %% 85% confirmation success rate
-define(MIN_TRACKED_TXS, 100).    %% minimum data before using buckets
-define(MAX_CONF_TARGET, 1008).   %% max target (~1 week of blocks)

%% ETS table: txid -> {bucket_index, entry_height}
-define(FEE_EST_TRACKED, fee_est_tracked).

%%% -------------------------------------------------------------------
%%% Records
%%% -------------------------------------------------------------------

%% Per-bucket tracking data
-record(bucket_data, {
    total      = 0.0  :: float(),  %% weighted count of all tracked txs
    in_mempool = 0.0  :: float(),  %% currently unconfirmed
    confirmed  = #{}  :: #{integer() => float()}  %% blocks_waited => count
}).

-record(state, {
    buckets       :: [float()],          %% sorted bucket boundaries (sat/vB)
    num_buckets   :: integer(),
    data          :: #{integer() => #bucket_data{}},
    total_tracked :: integer(),          %% total txs tracked since start
    block_height  :: integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Track a transaction that entered the mempool.
%% Records its fee rate bucket for later confirmation analysis.
-spec track_tx(binary(), float(), integer()) -> ok.
track_tx(Txid, FeeRate, Height) ->
    gen_server:cast(?SERVER, {track_tx, Txid, FeeRate, Height}).

%% @doc Process a newly connected block. Updates confirmation stats
%% for tracked transactions and applies exponential decay.
-spec process_block(integer(), [binary()]) -> ok.
process_block(Height, Txids) ->
    gen_server:cast(?SERVER, {process_block, Height, Txids}).

%% @doc Estimate the fee rate (sat/vB) needed for confirmation within
%% ConfTarget blocks (1-1008).
-spec estimate_fee(integer()) -> {ok, float()} | {error, term()}.
estimate_fee(ConfTarget) when is_integer(ConfTarget),
                              ConfTarget >= 1,
                              ConfTarget =< ?MAX_CONF_TARGET ->
    gen_server:call(?SERVER, {estimate_fee, ConfTarget});
estimate_fee(_) ->
    {error, invalid_target}.

%% @doc Return fee rate distribution of the current mempool.
-spec get_fee_histogram() -> [{float(), integer()}].
get_fee_histogram() ->
    gen_server:call(?SERVER, get_fee_histogram).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    ets:new(?FEE_EST_TRACKED, [set, public, named_table]),

    Buckets = generate_buckets(),
    NumBuckets = length(Buckets),
    Data = maps:from_list([{I, #bucket_data{}} ||
                           I <- lists:seq(0, NumBuckets - 1)]),

    Height = case beamchain_chainstate:get_tip() of
        {ok, {_, H}} -> H;
        _ -> 0
    end,

    logger:info("fee_estimator: initialized with ~B buckets", [NumBuckets]),
    {ok, #state{
        buckets = Buckets,
        num_buckets = NumBuckets,
        data = Data,
        total_tracked = 0,
        block_height = Height
    }}.

handle_call({estimate_fee, ConfTarget}, _From, State) ->
    Result = do_estimate_fee(ConfTarget, State),
    {reply, Result, State};
handle_call(get_fee_histogram, _From, State) ->
    Histogram = do_get_fee_histogram(State),
    {reply, Histogram, State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast({track_tx, Txid, FeeRate, Height}, State) ->
    State2 = do_track_tx(Txid, FeeRate, Height, State),
    {noreply, State2};
handle_cast({process_block, Height, Txids}, State) ->
    State2 = do_process_block(Height, Txids, State),
    {noreply, State2};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    logger:info("fee_estimator: shutting down"),
    ok.

%%% ===================================================================
%%% Internal: bucket generation
%%% ===================================================================

%% Generate NUM_BUCKETS logarithmically-spaced fee rate boundaries
%% spanning MIN_FEE_RATE to MAX_FEE_RATE.
generate_buckets() ->
    Factor = math:pow(?MAX_FEE_RATE / ?MIN_FEE_RATE,
                      1.0 / (?NUM_BUCKETS - 1)),
    generate_buckets(?MIN_FEE_RATE, Factor, ?NUM_BUCKETS, []).

generate_buckets(_Rate, _Factor, 0, Acc) ->
    lists:reverse(Acc);
generate_buckets(Rate, Factor, N, Acc) ->
    generate_buckets(Rate * Factor, Factor, N - 1, [Rate | Acc]).

%% Find which bucket index a fee rate belongs to.
%% Returns the index of the highest bucket boundary <= FeeRate.
find_bucket(FeeRate, Buckets) ->
    find_bucket(FeeRate, Buckets, 0).

find_bucket(_FeeRate, [_], Idx) ->
    Idx;
find_bucket(FeeRate, [_, B2 | _], Idx) when FeeRate < B2 ->
    Idx;
find_bucket(FeeRate, [_ | Rest], Idx) ->
    find_bucket(FeeRate, Rest, Idx + 1).

%%% ===================================================================
%%% Internal: track transaction
%%% ===================================================================

do_track_tx(Txid, FeeRate, Height,
            #state{buckets = Buckets, data = Data,
                   total_tracked = Total} = State) ->
    BucketIdx = find_bucket(FeeRate, Buckets),

    %% Store in ETS for lookup when a block confirms this tx
    ets:insert(?FEE_EST_TRACKED, {Txid, BucketIdx, Height}),

    %% Update bucket counters
    BD = maps:get(BucketIdx, Data, #bucket_data{}),
    BD2 = BD#bucket_data{
        total = BD#bucket_data.total + 1.0,
        in_mempool = BD#bucket_data.in_mempool + 1.0
    },
    State#state{
        data = maps:put(BucketIdx, BD2, Data),
        total_tracked = Total + 1
    }.

%%% ===================================================================
%%% Internal: process block
%%% ===================================================================

do_process_block(Height, Txids, State) ->
    %% 1. Update confirmed counts for each tracked tx that got confirmed
    State2 = lists:foldl(fun(Txid, S) ->
        case ets:lookup(?FEE_EST_TRACKED, Txid) of
            [{Txid, BucketIdx, EntryHeight}] ->
                BlocksWaited = max(1, Height - EntryHeight + 1),
                ets:delete(?FEE_EST_TRACKED, Txid),
                record_confirmation(BucketIdx, BlocksWaited, S);
            [] ->
                %% Not tracked (entered before estimator, or already gone)
                S
        end
    end, State, Txids),

    %% 2. Apply exponential decay to all bucket data
    State3 = apply_decay(State2),
    State3#state{block_height = Height}.

%% Record that a tx in BucketIdx was confirmed after BlocksWaited blocks.
record_confirmation(BucketIdx, BlocksWaited,
                    #state{data = Data} = State) ->
    BD = maps:get(BucketIdx, Data, #bucket_data{}),
    Confirmed = BD#bucket_data.confirmed,
    OldCount = maps:get(BlocksWaited, Confirmed, 0.0),
    BD2 = BD#bucket_data{
        confirmed = maps:put(BlocksWaited, OldCount + 1.0, Confirmed),
        in_mempool = max(0.0, BD#bucket_data.in_mempool - 1.0)
    },
    State#state{data = maps:put(BucketIdx, BD2, Data)}.

%%% ===================================================================
%%% Internal: exponential decay
%%% ===================================================================

%% Apply decay factor to all bucket counters. Called once per block.
apply_decay(#state{data = Data} = State) ->
    Data2 = maps:map(fun(_Idx, BD) -> decay_bucket(BD) end, Data),
    State#state{data = Data2}.

decay_bucket(#bucket_data{total = T, in_mempool = M, confirmed = C}) ->
    #bucket_data{
        total = T * ?DECAY_FACTOR,
        in_mempool = M * ?DECAY_FACTOR,
        confirmed = maps:map(fun(_K, V) -> V * ?DECAY_FACTOR end, C)
    }.

%%% ===================================================================
%%% Internal: fee estimation
%%% ===================================================================

do_estimate_fee(ConfTarget, #state{total_tracked = Total} = State)
  when Total < ?MIN_TRACKED_TXS ->
    %% Not enough historical data — fall back to mempool percentile
    estimate_from_mempool(ConfTarget, State);
do_estimate_fee(ConfTarget, #state{buckets = Buckets, data = Data,
                                    num_buckets = NumBuckets} = State) ->
    case find_passing_bucket(0, NumBuckets, ConfTarget, Buckets, Data) of
        {ok, FeeRate} ->
            {ok, FeeRate};
        not_found ->
            %% Bucket model couldn't find a passing bucket, try mempool
            estimate_from_mempool(ConfTarget, State)
    end.

%% Scan buckets from lowest fee rate upward. Return the fee rate of
%% the first bucket where the confirmation success rate meets threshold.
find_passing_bucket(Idx, NumBuckets, _Target, _Buckets, _Data)
  when Idx >= NumBuckets ->
    not_found;
find_passing_bucket(Idx, NumBuckets, Target, Buckets, Data) ->
    BD = maps:get(Idx, Data, #bucket_data{}),
    %% Only consider txs that have resolved (confirmed or dropped),
    %% not ones still sitting in the mempool
    Resolved = BD#bucket_data.total - BD#bucket_data.in_mempool,
    case Resolved >= 1.0 of
        true ->
            ConfWithin = sum_confirmed_within(Target,
                                              BD#bucket_data.confirmed),
            SuccessRate = ConfWithin / Resolved,
            case SuccessRate >= ?SUCCESS_THRESHOLD of
                true ->
                    {ok, lists:nth(Idx + 1, Buckets)};
                false ->
                    find_passing_bucket(Idx + 1, NumBuckets, Target,
                                        Buckets, Data)
            end;
        false ->
            %% Not enough resolved data in this bucket
            find_passing_bucket(Idx + 1, NumBuckets, Target, Buckets, Data)
    end.

%% Sum the weighted confirmed count for all delays <= MaxBlocks.
sum_confirmed_within(MaxBlocks, Confirmed) ->
    maps:fold(fun(BlocksWaited, Count, Acc) ->
        case BlocksWaited =< MaxBlocks of
            true -> Acc + Count;
            false -> Acc
        end
    end, 0.0, Confirmed).

%%% ===================================================================
%%% Internal: mempool fallback estimation
%%% ===================================================================

%% When we don't have enough historical block data, estimate from the
%% current mempool distribution using a percentile-based heuristic.
estimate_from_mempool(ConfTarget, _State) ->
    try
        FeeRates = collect_mempool_fee_rates(),
        case FeeRates of
            [] ->
                {error, insufficient_data};
            _ ->
                N = length(FeeRates),
                %% Map confirmation target to percentile via log scale.
                %% Target 1 → ~95th percentile, target 144 → ~5th
                Pct = max(0.05, min(0.95,
                    1.0 - math:log(max(1, ConfTarget)) * 0.2)),
                Idx = max(1, min(N, ceil(N * Pct))),
                FeeRate = lists:nth(Idx, FeeRates),
                {ok, max(1.0, FeeRate)}
        end
    catch
        _:_ ->
            {error, insufficient_data}
    end.

%% Collect all fee rates from the mempool's ordered ETS table.
%% Returns ascending order (lowest fee rate first).
collect_mempool_fee_rates() ->
    try
        collect_rates_asc(ets:first(mempool_by_fee), [])
    catch
        error:badarg -> []  %% table doesn't exist yet
    end.

collect_rates_asc('$end_of_table', Acc) ->
    lists:reverse(Acc);
collect_rates_asc({FeeRate, _Txid} = Key, Acc) ->
    collect_rates_asc(ets:next(mempool_by_fee, Key), [FeeRate | Acc]).

%%% ===================================================================
%%% Internal: fee histogram
%%% ===================================================================

%% Build histogram of current mempool fee rates grouped by bucket.
do_get_fee_histogram(#state{buckets = Buckets, num_buckets = NumBuckets}) ->
    FeeRates = collect_mempool_fee_rates(),
    Counts = lists:foldl(fun(Rate, Acc) ->
        Idx = find_bucket(Rate, Buckets),
        maps:update_with(Idx, fun(C) -> C + 1 end, 1, Acc)
    end, #{}, FeeRates),
    [{lists:nth(I + 1, Buckets), maps:get(I, Counts, 0)} ||
     I <- lists:seq(0, NumBuckets - 1)].
