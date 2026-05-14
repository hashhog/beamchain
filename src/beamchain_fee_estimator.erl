-module(beamchain_fee_estimator).
-behaviour(gen_server).

%% Block-based fee rate estimation using exponential decay buckets.
%% Modeled after Bitcoin Core's CBlockPolicyEstimator.
%%
%% Three independent horizons matching Core exactly:
%%   SHORT  decay=0.962,   scale=1,  periods=12  blocks
%%   MED    decay=0.9952,  scale=2,  periods=24  blocks
%%   LONG   decay=0.99931, scale=24, periods=42  blocks
%%
%% Bucket layout matches Core:
%%   MIN=100 sat/kvB = 0.1 sat/vB, spacing=1.05, ~237 buckets up to 10000 sat/vB.

-include("beamchain.hrl").

%% API
-export([start_link/0]).
-export([track_tx/3, process_block/2]).
-export([estimate_fee/1, estimate_raw_fee/2, get_fee_histogram/0]).
-export([save_state/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%%% -------------------------------------------------------------------
%%% Fee estimation parameters — match Bitcoin Core exactly
%%% -------------------------------------------------------------------

%% Bucket layout (Core FEE_SPACING / MIN_BUCKET_FEERATE / MAX_BUCKET_FEERATE)
-define(MIN_BUCKET_FEERATE, 0.1).     %% sat/vB  (Core: 100 sat/kvB)
-define(MAX_BUCKET_FEERATE, 10000.0). %% sat/vB  (Core: 1e7 sat/kvB)
-define(FEE_SPACING, 1.05).           %% Core FEE_SPACING

%% Three horizons (Core CBlockPolicyEstimator SHORT/MED/LONG)
-define(SHORT_DECAY,  0.962).
-define(MED_DECAY,    0.9952).
-define(LONG_DECAY,   0.99931).
-define(SHORT_SCALE,  1).
-define(MED_SCALE,    2).
-define(LONG_SCALE,   24).
%% Number of periods per horizon
-define(SHORT_PERIODS, 12).
-define(MED_PERIODS,   24).
-define(LONG_PERIODS,  42).

%% Derived conf-target windows for horizon dispatch.
%% Core: short handles  1..SHORT_SCALE*SHORT_PERIODS = 12
%%       medium handles 1..MED_SCALE*MED_PERIODS     = 48
%%       long handles   1..LONG_SCALE*LONG_PERIODS   = 1008
-define(SHORT_MAX_TARGET, (?SHORT_SCALE * ?SHORT_PERIODS)).   %% 12
-define(MED_MAX_TARGET,   (?MED_SCALE   * ?MED_PERIODS)).     %% 48
-define(LONG_MAX_TARGET,  (?LONG_SCALE  * ?LONG_PERIODS)).    %% 1008

-define(SUCCESS_THRESHOLD, 0.85). %% 85 % confirmation success rate
-define(MIN_TRACKED_TXS, 100).    %% minimum data before using buckets
-define(MAX_CONF_TARGET, 1008).   %% max target (~1 week of blocks)
-define(PERSIST_INTERVAL, 300_000). %% persist every 5 minutes
-define(FEE_EST_FILE, "fee_estimates.dat").

%% ETS table: txid -> {bucket_index, entry_height}
-define(FEE_EST_TRACKED, fee_est_tracked).

%%% -------------------------------------------------------------------
%%% Records
%%% -------------------------------------------------------------------

%% Per-bucket tracking data (shared layout across all three horizons)
-record(bucket_data, {
    total      = 0.0  :: float(),  %% weighted count of all tracked txs
    in_mempool = 0.0  :: float(),  %% currently unconfirmed
    confirmed  = #{}  :: #{integer() => float()}  %% blocks_waited => count
}).

%% Per-horizon state
-record(horizon, {
    decay   :: float(),
    scale   :: integer(),
    max_target :: integer(),
    data    :: #{integer() => #bucket_data{}}
}).

-record(state, {
    buckets       :: [float()],          %% sorted bucket boundaries (sat/vB)
    num_buckets   :: integer(),
    short         :: #horizon{},
    med           :: #horizon{},
    long          :: #horizon{},
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
%% for tracked transactions and applies exponential decay to all horizons.
-spec process_block(integer(), [binary()]) -> ok.
process_block(Height, Txids) ->
    gen_server:cast(?SERVER, {process_block, Height, Txids}).

%% @doc Estimate the fee rate (sat/vB) needed for confirmation within
%% ConfTarget blocks (2-1008).  Core rejects target=1.
-spec estimate_fee(integer()) -> {ok, float()} | {error, term()}.
estimate_fee(ConfTarget) when is_integer(ConfTarget),
                              ConfTarget >= 2,
                              ConfTarget =< ?MAX_CONF_TARGET ->
    gen_server:call(?SERVER, {estimate_fee, ConfTarget});
estimate_fee(_) ->
    {error, invalid_target}.

%% @doc Raw, per-horizon fee estimate. Returns a map keyed by horizon
%% atom (<<"short">> / <<"medium">> / <<"long">>) with `feerate', `decay',
%% `scale', `pass' and `fail' bucket info — matching the Bitcoin Core
%% estimaterawfee RPC.  Threshold is the proportion (0..1) of confirmed
%% txs required for a bucket to "pass".
-spec estimate_raw_fee(integer(), float()) -> map().
estimate_raw_fee(ConfTarget, Threshold)
  when is_integer(ConfTarget),
       ConfTarget >= 1, ConfTarget =< ?MAX_CONF_TARGET,
       is_float(Threshold), Threshold >= 0.0, Threshold =< 1.0 ->
    gen_server:call(?SERVER, {estimate_raw_fee, ConfTarget, Threshold});
estimate_raw_fee(_, _) ->
    #{}.

%% @doc Return fee rate distribution of the current mempool.
-spec get_fee_histogram() -> [{float(), integer()}].
get_fee_histogram() ->
    gen_server:call(?SERVER, get_fee_histogram).

%% @doc Persist the current estimator state to disk.
-spec save_state() -> ok | {error, term()}.
save_state() ->
    gen_server:call(?SERVER, save_state).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    ets:new(?FEE_EST_TRACKED, [set, public, named_table]),

    Buckets = generate_buckets(),
    NumBuckets = length(Buckets),
    EmptyData = maps:from_list([{I, #bucket_data{}} ||
                           I <- lists:seq(0, NumBuckets - 1)]),

    Height = case beamchain_chainstate:get_tip() of
        {ok, {_, H}} -> H;
        _ -> 0
    end,

    ShortH = #horizon{decay = ?SHORT_DECAY, scale = ?SHORT_SCALE,
                      max_target = ?SHORT_MAX_TARGET, data = EmptyData},
    MedH   = #horizon{decay = ?MED_DECAY,   scale = ?MED_SCALE,
                      max_target = ?MED_MAX_TARGET,   data = EmptyData},
    LongH  = #horizon{decay = ?LONG_DECAY,  scale = ?LONG_SCALE,
                      max_target = ?LONG_MAX_TARGET,  data = EmptyData},

    %% Try to load persisted state (v2 format with 3 horizons).
    {Short2, Med2, Long2, TotalTracked} =
        case load_persisted_state(NumBuckets, ShortH, MedH, LongH) of
            {ok, PS, PM, PL, PTotal} ->
                logger:info("fee_estimator: loaded persisted state "
                            "(~B tracked txs)", [PTotal]),
                {PS, PM, PL, PTotal};
            {error, _} ->
                {ShortH, MedH, LongH, 0}
        end,

    %% Schedule periodic persistence
    erlang:send_after(?PERSIST_INTERVAL, self(), persist),

    logger:info("fee_estimator: initialized with ~B buckets, 3 horizons",
                [NumBuckets]),
    {ok, #state{
        buckets = Buckets,
        num_buckets = NumBuckets,
        short = Short2,
        med   = Med2,
        long  = Long2,
        total_tracked = TotalTracked,
        block_height = Height
    }}.

handle_call({estimate_fee, ConfTarget}, _From, State) ->
    Result = do_estimate_fee(ConfTarget, State),
    {reply, Result, State};
handle_call({estimate_raw_fee, ConfTarget, Threshold}, _From, State) ->
    Result = do_estimate_raw_fee(ConfTarget, Threshold, State),
    {reply, Result, State};
handle_call(get_fee_histogram, _From, State) ->
    Histogram = do_get_fee_histogram(State),
    {reply, Histogram, State};
handle_call(save_state, _From, State) ->
    Result = do_save_state(State),
    {reply, Result, State};
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

handle_info(persist, State) ->
    do_save_state(State),
    erlang:send_after(?PERSIST_INTERVAL, self(), persist),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    do_save_state(State),
    logger:info("fee_estimator: shutting down (state persisted)"),
    ok.

%%% ===================================================================
%%% Internal: bucket generation
%%% ===================================================================

%% Generate logarithmically-spaced fee rate boundaries matching Core.
%% Core: MIN=100 sat/kvB, MAX=1e7 sat/kvB, spacing=1.05 → ~237 buckets.
%% We work in sat/vB (÷1000): min=0.1, max=10000.
%% We append MAX_BUCKET_FEERATE as the explicit final boundary (matching
%% Core's INF sentinel approach) so the last bucket covers up to 10000.
generate_buckets() ->
    Bs = generate_buckets(?MIN_BUCKET_FEERATE, []),
    %% Ensure the maximum boundary is included
    case lists:last(Bs) < ?MAX_BUCKET_FEERATE of
        true  -> Bs ++ [?MAX_BUCKET_FEERATE];
        false -> Bs
    end.

generate_buckets(Rate, Acc) when Rate > ?MAX_BUCKET_FEERATE ->
    lists:reverse(Acc);
generate_buckets(Rate, Acc) ->
    generate_buckets(Rate * ?FEE_SPACING, [Rate | Acc]).

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
            #state{buckets = Buckets,
                   short = Short, med = Med, long = Long,
                   total_tracked = Total} = State) ->
    BucketIdx = find_bucket(FeeRate, Buckets),

    %% Store in ETS for lookup when a block confirms this tx
    ets:insert(?FEE_EST_TRACKED, {Txid, BucketIdx, Height}),

    %% Update all three horizon data sets
    Short2 = horizon_add_tx(BucketIdx, Short),
    Med2   = horizon_add_tx(BucketIdx, Med),
    Long2  = horizon_add_tx(BucketIdx, Long),

    State#state{
        short = Short2,
        med   = Med2,
        long  = Long2,
        total_tracked = Total + 1
    }.

horizon_add_tx(BucketIdx, #horizon{data = Data} = H) ->
    BD = maps:get(BucketIdx, Data, #bucket_data{}),
    BD2 = BD#bucket_data{
        total = BD#bucket_data.total + 1.0,
        in_mempool = BD#bucket_data.in_mempool + 1.0
    },
    H#horizon{data = maps:put(BucketIdx, BD2, Data)}.

%%% ===================================================================
%%% Internal: process block
%%% ===================================================================

do_process_block(Height, _Txids, #state{block_height = BestHeight} = State)
  when Height =< BestHeight ->
    %% Reorg guard: ignore blocks at or below best-seen height (Core guard).
    State;
do_process_block(Height, Txids, State) ->
    %% 1. Update confirmed counts for each tracked tx that got confirmed.
    %%    We record into all three horizons, each with its own scale.
    State2 = lists:foldl(fun(Txid, S) ->
        case ets:lookup(?FEE_EST_TRACKED, Txid) of
            [{Txid, BucketIdx, EntryHeight}] ->
                BlocksWaited = max(1, Height - EntryHeight),
                ets:delete(?FEE_EST_TRACKED, Txid),
                S2 = record_confirmation_horizon(
                         BucketIdx, BlocksWaited, short, S),
                S3 = record_confirmation_horizon(
                         BucketIdx, BlocksWaited, med, S2),
                record_confirmation_horizon(
                         BucketIdx, BlocksWaited, long, S3);
            [] ->
                S
        end
    end, State, Txids),

    %% 2. Apply per-horizon exponential decay once per block.
    State3 = apply_decay_all(State2),
    State3#state{block_height = Height}.

record_confirmation_horizon(BucketIdx, BlocksWaited, HorizonName, State) ->
    H = get_horizon(HorizonName, State),
    #horizon{scale = Scale, data = Data} = H,
    %% Core records into period index: blocksWaited / scale (integer div).
    PeriodIdx = BlocksWaited div Scale,
    BD = maps:get(BucketIdx, Data, #bucket_data{}),
    Confirmed = BD#bucket_data.confirmed,
    OldCount = maps:get(PeriodIdx, Confirmed, 0.0),
    BD2 = BD#bucket_data{
        confirmed = maps:put(PeriodIdx, OldCount + 1.0, Confirmed),
        in_mempool = max(0.0, BD#bucket_data.in_mempool - 1.0)
    },
    H2 = H#horizon{data = maps:put(BucketIdx, BD2, Data)},
    set_horizon(HorizonName, H2, State).

get_horizon(short, #state{short = H}) -> H;
get_horizon(med,   #state{med   = H}) -> H;
get_horizon(long,  #state{long  = H}) -> H.

set_horizon(short, H, State) -> State#state{short = H};
set_horizon(med,   H, State) -> State#state{med   = H};
set_horizon(long,  H, State) -> State#state{long  = H}.

%%% ===================================================================
%%% Internal: exponential decay
%%% ===================================================================

%% Apply each horizon's own decay factor once per block.
apply_decay_all(#state{short = Short, med = Med, long = Long} = State) ->
    State#state{
        short = decay_horizon(Short),
        med   = decay_horizon(Med),
        long  = decay_horizon(Long)
    }.

decay_horizon(#horizon{decay = D, data = Data} = H) ->
    H#horizon{data = maps:map(fun(_Idx, BD) -> decay_bucket(BD, D) end, Data)}.

decay_bucket(#bucket_data{total = T, in_mempool = M, confirmed = C}, D) ->
    #bucket_data{
        total = T * D,
        in_mempool = M * D,
        confirmed = maps:map(fun(_K, V) -> V * D end, C)
    }.

%%% ===================================================================
%%% Internal: fee estimation (estimatesmartfee)
%%% ===================================================================

do_estimate_fee(ConfTarget, #state{total_tracked = Total} = State)
  when Total < ?MIN_TRACKED_TXS ->
    estimate_from_mempool(ConfTarget, State);
do_estimate_fee(ConfTarget, #state{buckets = Buckets,
                                    num_buckets = NumBuckets} = State) ->
    %% Select the most-appropriate horizon: shortest that covers the target.
    Horizons = applicable_horizons(ConfTarget, State),
    case find_passing_any_horizon(Horizons, ConfTarget, Buckets, NumBuckets) of
        {ok, FeeRate} ->
            {ok, FeeRate};
        not_found ->
            estimate_from_mempool(ConfTarget, State)
    end.

%% Return horizons applicable for this conf_target, shortest first.
applicable_horizons(ConfTarget, #state{short = S, med = M, long = L}) ->
    All = [{short, S}, {med, M}, {long, L}],
    [{Name, H} || {Name, H} <- All,
                  ConfTarget =< H#horizon.max_target].

find_passing_any_horizon([], _Target, _Buckets, _NumBuckets) ->
    not_found;
find_passing_any_horizon([{_Name, H} | Rest], Target, Buckets, NumBuckets) ->
    case find_passing_bucket(0, NumBuckets, Target, H#horizon.scale,
                             Buckets, H#horizon.data) of
        {ok, FeeRate} -> {ok, FeeRate};
        not_found     -> find_passing_any_horizon(Rest, Target, Buckets,
                                                  NumBuckets)
    end.

%% Scan buckets from lowest fee rate upward. Return the fee rate of
%% the first bucket where the confirmation success rate meets threshold.
%% Scale is used to convert blocks_waited periods back to blocks.
find_passing_bucket(Idx, NumBuckets, _Target, _Scale, _Buckets, _Data)
  when Idx >= NumBuckets ->
    not_found;
find_passing_bucket(Idx, NumBuckets, Target, Scale, Buckets, Data) ->
    BD = maps:get(Idx, Data, #bucket_data{}),
    %% Only consider resolved txs (confirmed or dropped, not still in mempool)
    Resolved = BD#bucket_data.total - BD#bucket_data.in_mempool,
    case Resolved >= 1.0 of
        true ->
            %% Target in periods for this horizon
            TargetPeriods = (Target + Scale - 1) div Scale,
            ConfWithin = sum_confirmed_within(TargetPeriods,
                                              BD#bucket_data.confirmed),
            SuccessRate = ConfWithin / Resolved,
            case SuccessRate >= ?SUCCESS_THRESHOLD of
                true ->
                    {ok, lists:nth(Idx + 1, Buckets)};
                false ->
                    find_passing_bucket(Idx + 1, NumBuckets, Target, Scale,
                                        Buckets, Data)
            end;
        false ->
            find_passing_bucket(Idx + 1, NumBuckets, Target, Scale,
                                Buckets, Data)
    end.

%% Sum the weighted confirmed count for all period-delays <= MaxPeriods.
sum_confirmed_within(MaxPeriods, Confirmed) ->
    maps:fold(fun(PeriodIdx, Count, Acc) ->
        case PeriodIdx =< MaxPeriods of
            true -> Acc + Count;
            false -> Acc
        end
    end, 0.0, Confirmed).

%% Sum confirmed counts across all delays.
sum_confirmed_total(Confirmed) ->
    maps:fold(fun(_K, V, Acc) -> Acc + V end, 0.0, Confirmed).

%%% ===================================================================
%%% Internal: raw fee estimation (estimaterawfee)
%%% ===================================================================

%% Build a full per-horizon map. Returns entries for each applicable
%% horizon keyed by <<"short">>, <<"medium">>, <<"long">>.
do_estimate_raw_fee(ConfTarget, Threshold,
                    #state{buckets = Buckets, num_buckets = NumBuckets,
                           total_tracked = Total,
                           short = Short, med = Med, long = Long}) ->
    Insufficient = Total < ?MIN_TRACKED_TXS,
    HorizonDefs = [
        {<<"short">>,  Short,  ConfTarget =< Short#horizon.max_target},
        {<<"medium">>, Med,    ConfTarget =< Med#horizon.max_target},
        {<<"long">>,   Long,   ConfTarget =< Long#horizon.max_target}
    ],
    maps:from_list(
        [{Key, build_horizon_result(H, ConfTarget, Threshold,
                                   Buckets, NumBuckets, Insufficient)}
         || {Key, H, Applicable} <- HorizonDefs,
            Applicable]).

build_horizon_result(#horizon{decay = Decay, scale = Scale, data = Data},
                     ConfTarget, Threshold, Buckets, NumBuckets,
                     Insufficient) ->
    case Insufficient of
        true ->
            #{<<"decay">>  => Decay,
              <<"scale">>  => Scale,
              <<"fail">>   => empty_bucket_info(),
              <<"errors">> => [<<"Insufficient data or no feerate found "
                                "which meets threshold">>]};
        false ->
            TargetPeriods = (ConfTarget + Scale - 1) div Scale,
            case scan_buckets_for_pass(0, NumBuckets, TargetPeriods,
                                       Threshold, Buckets, Data) of
                {pass, FeeRate, Pass, Fail} ->
                    Base = #{<<"feerate">> => fee_rate_to_btc_per_kvb(FeeRate),
                             <<"decay">>   => Decay,
                             <<"scale">>   => Scale,
                             <<"pass">>    => Pass},
                    case Fail of
                        none -> Base;
                        _    -> Base#{<<"fail">> => Fail}
                    end;
                {fail, Fail} ->
                    #{<<"decay">>  => Decay,
                      <<"scale">>  => Scale,
                      <<"fail">>   => Fail,
                      <<"errors">> => [<<"Insufficient data or no feerate found "
                                        "which meets threshold">>]}
            end
    end.

%% Scan buckets ascending. Track the highest-failing bucket along the way;
%% return the first passing bucket plus the most-recent fail bucket.
scan_buckets_for_pass(Idx, NumBuckets, _TargetP, _Thr, _B, _D)
  when Idx >= NumBuckets ->
    {fail, empty_bucket_info()};
scan_buckets_for_pass(Idx, NumBuckets, TargetPeriods, Threshold,
                      Buckets, Data) ->
    scan_buckets_for_pass(Idx, NumBuckets, TargetPeriods, Threshold,
                          Buckets, Data, none).

scan_buckets_for_pass(Idx, NumBuckets, _TargetP, _Thr, _B, _D, LastFail)
  when Idx >= NumBuckets ->
    case LastFail of
        none -> {fail, empty_bucket_info()};
        _    -> {fail, LastFail}
    end;
scan_buckets_for_pass(Idx, NumBuckets, TargetPeriods, Threshold, Buckets,
                      Data, LastFail) ->
    BD = maps:get(Idx, Data, #bucket_data{}),
    StartRange = lists:nth(Idx + 1, Buckets),
    EndRange = case Idx + 2 =< length(Buckets) of
        true  -> lists:nth(Idx + 2, Buckets);
        false -> StartRange * 2.0
    end,
    Resolved = BD#bucket_data.total - BD#bucket_data.in_mempool,
    Info = bucket_info(StartRange, EndRange, TargetPeriods, BD),
    case Resolved >= 1.0 of
        true ->
            ConfWithin = sum_confirmed_within(TargetPeriods,
                                              BD#bucket_data.confirmed),
            SuccessRate = ConfWithin / Resolved,
            case SuccessRate >= Threshold of
                true ->
                    {pass, StartRange, Info, LastFail};
                false ->
                    scan_buckets_for_pass(Idx + 1, NumBuckets, TargetPeriods,
                                          Threshold, Buckets, Data, Info)
            end;
        false ->
            scan_buckets_for_pass(Idx + 1, NumBuckets, TargetPeriods,
                                  Threshold, Buckets, Data, LastFail)
    end.

bucket_info(Start, End, TargetPeriods, BD) ->
    #{
        <<"startrange">>     => Start,
        <<"endrange">>       => End,
        <<"withintarget">>   =>
            round_centi(sum_confirmed_within(TargetPeriods,
                                              BD#bucket_data.confirmed)),
        <<"totalconfirmed">> =>
            round_centi(sum_confirmed_total(BD#bucket_data.confirmed)),
        <<"inmempool">>      => round_centi(BD#bucket_data.in_mempool),
        <<"leftmempool">>    =>
            round_centi(max(0.0, BD#bucket_data.total
                                  - BD#bucket_data.in_mempool
                                  - sum_confirmed_total(
                                        BD#bucket_data.confirmed)))
    }.

empty_bucket_info() ->
    #{
        <<"startrange">>     => -1,
        <<"endrange">>       => 0,
        <<"withintarget">>   => 0.0,
        <<"totalconfirmed">> => 0.0,
        <<"inmempool">>      => 0.0,
        <<"leftmempool">>    => 0.0
    }.

%% Round to 2 decimal places (mirrors Core's round(x*100)/100).
round_centi(F) when is_float(F) ->
    round(F * 100.0) / 100.0;
round_centi(I) when is_integer(I) ->
    float(I).

%% sat/vB -> BTC/kvB
fee_rate_to_btc_per_kvb(FeeRate) ->
    FeeRate * 1000.0 / 100000000.0.

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
                %% Target 2 → ~95th percentile, target 144 → ~5th
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
%%% Internal: persistence (version 2 — 3 horizons)
%%% ===================================================================

%% Return the path to the fee estimation data file.
persist_path() ->
    DataDir = try beamchain_config:datadir()
              catch _:_ -> "/tmp"
              end,
    filename:join(DataDir, ?FEE_EST_FILE).

%% Save current estimator state to disk as an Erlang term file.
do_save_state(#state{short = Short, med = Med, long = Long,
                     total_tracked = Total, block_height = Height}) ->
    Path = persist_path(),
    Ser = fun(#horizon{decay = D, scale = Sc, max_target = MT, data = Data}) ->
        SerData = maps:map(fun(_I, #bucket_data{total = T, in_mempool = M,
                                                 confirmed = C}) ->
            #{total => T, in_mempool => M, confirmed => C}
        end, Data),
        #{decay => D, scale => Sc, max_target => MT, data => SerData}
    end,
    Term = #{version => 2,
             short => Ser(Short),
             med   => Ser(Med),
             long  => Ser(Long),
             total_tracked => Total,
             block_height  => Height},
    TmpPath = Path ++ ".tmp",
    case file:write_file(TmpPath, term_to_binary(Term)) of
        ok ->
            case file:rename(TmpPath, Path) of
                ok ->
                    logger:debug("fee_estimator: persisted state (~B tracked)",
                                 [Total]),
                    ok;
                {error, Reason} ->
                    logger:warning("fee_estimator: rename failed: ~p", [Reason]),
                    file:delete(TmpPath),
                    {error, Reason}
            end;
        {error, Reason} ->
            logger:warning("fee_estimator: write failed: ~p", [Reason]),
            {error, Reason}
    end.

%% Deserialise one horizon from the v2 on-disk map.
deser_horizon(#{decay := D, scale := Sc, max_target := MT,
                data := SerData}, NumBuckets, Default) ->
    Data = maps:map(fun(_I, #{total := T, in_mempool := M, confirmed := C}) ->
        #bucket_data{total = T, in_mempool = M, confirmed = C}
    end, SerData),
    case maps:size(Data) =:= NumBuckets of
        true ->
            {ok, Default#horizon{decay = D, scale = Sc, max_target = MT,
                                 data = Data}};
        false ->
            {error, bucket_mismatch}
    end.

%% Load persisted state from disk (v2 format; v1 is discarded).
load_persisted_state(NumBuckets, ShortDefault, MedDefault, LongDefault) ->
    Path = persist_path(),
    case file:read_file(Path) of
        {ok, Bin} ->
            try
                case binary_to_term(Bin) of
                    #{version := 2,
                      short := SS, med := SM, long := SL,
                      total_tracked := Total} ->
                        case {deser_horizon(SS, NumBuckets, ShortDefault),
                              deser_horizon(SM, NumBuckets, MedDefault),
                              deser_horizon(SL, NumBuckets, LongDefault)} of
                            {{ok, S}, {ok, M}, {ok, L}} ->
                                {ok, S, M, L, Total};
                            _ ->
                                logger:warning("fee_estimator: horizon "
                                               "bucket-count mismatch, "
                                               "starting fresh"),
                                {error, bucket_mismatch}
                        end;
                    #{version := V} ->
                        logger:info("fee_estimator: discarding v~B state "
                                    "(upgrading to v2)", [V]),
                        {error, version_mismatch};
                    _ ->
                        {error, corrupt}
                end
            catch
                _:Reason ->
                    logger:warning("fee_estimator: corrupt state file: ~p",
                                   [Reason]),
                    {error, corrupt}
            end;
        {error, enoent} ->
            {error, no_file};
        {error, Reason} ->
            logger:warning("fee_estimator: could not read ~s: ~p",
                           [Path, Reason]),
            {error, Reason}
    end.

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
