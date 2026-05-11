-module(beamchain_versionbits).

%% BIP9 versionbits deployment state machine.
%%
%% Tracks soft fork deployment status through states:
%% defined -> started -> locked_in -> active (or failed)
%%
%% Reference: Bitcoin Core versionbits.cpp

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Dialyzer suppressions for false positives:
%% get_state_for/4: the NEVER_ACTIVE (-2) clause is a valid BIP9 sentinel
%% for future soft-fork proposals; dialyzer infers start_time from the
%% specific timestamp values in existing deployment records only.
-dialyzer({nowarn_function, get_state_for/4}).

-export([
    get_deployment_state/3,
    get_deployment_state_at_height/4,
    get_state_statistics/4,
    deployment_params/2,
    deployments/1,
    deployment_maps/1,
    signal_bit/3,
    init_cache/0,
    compute_block_version/2
]).

%% For testing
-export([
    version_bits_condition/2,
    compute_state/4
]).

%%% -------------------------------------------------------------------
%%% Constants
%%% -------------------------------------------------------------------

%% Version bits top bits: binary 001 (version >= 0x20000000)
%% Reference: versionbits.h VERSIONBITS_TOP_BITS / VERSIONBITS_TOP_MASK
-define(VERSIONBITS_TOP_BITS, 16#20000000).
-define(VERSIONBITS_TOP_MASK, 16#E0000000).

%% Number of version bits available for deployments (bits 0..28)
%% Reference: versionbits.h VERSIONBITS_NUM_BITS = 29
-define(VERSIONBITS_NUM_BITS, 29).

%% Default retarget period (same as difficulty adjustment interval)
%% Individual deployments may override via #deployment.period.
-define(DEFAULT_PERIOD, ?DIFFICULTY_ADJUSTMENT_INTERVAL).

%% Default thresholds — used when constructing deployment records.
%% Reference: consensus/params.h BIP9Deployment{period=2016, threshold=1916}
-define(MAINNET_THRESHOLD, 1916).    %% 1916/2016 ~= 95%
-define(TESTNET_THRESHOLD, 1512).    %% 1512/2016 = 75%

%% Special time values
%% Reference: consensus/params.h BIP9Deployment::ALWAYS_ACTIVE / NEVER_ACTIVE
-define(ALWAYS_ACTIVE, -1).
-define(NEVER_ACTIVE, -2).
%% NO_TIMEOUT = std::numeric_limits<int64_t>::max()
%% Reference: consensus/params.h BIP9Deployment::NO_TIMEOUT
-define(NO_TIMEOUT, 9223372036854775807).

%% ETS table for caching deployment states
-define(VERSIONBITS_CACHE, beamchain_versionbits_cache).

%%% -------------------------------------------------------------------
%%% Deployment record
%%%
%%% Mirrors Consensus::BIP9Deployment (consensus/params.h):
%%%   bit, nStartTime, nTimeout, min_activation_height, period, threshold
%%% -------------------------------------------------------------------

-record(deployment, {
    name            :: atom(),
    bit             :: 0..28,
    start_time      :: integer(),        %% unix timestamp or ALWAYS_ACTIVE/NEVER_ACTIVE
    timeout         :: integer(),        %% unix timestamp or NO_TIMEOUT
    min_activation_height :: non_neg_integer(),
    %% Per-deployment period and threshold (Core: BIP9Deployment.period / .threshold)
    period    :: pos_integer(),          %% retarget period length in blocks (default 2016)
    threshold :: non_neg_integer()       %% signalling threshold in blocks
}).

%%% -------------------------------------------------------------------
%%% Deployment state
%%% -------------------------------------------------------------------

-type deployment_state() :: defined | started | locked_in | active | failed.

%%% -------------------------------------------------------------------
%%% API
%%% -------------------------------------------------------------------

%% @doc Initialize the ETS cache for versionbits states.
%% Called during application startup.
-spec init_cache() -> ok.
init_cache() ->
    case ets:whereis(?VERSIONBITS_CACHE) of
        undefined ->
            ets:new(?VERSIONBITS_CACHE, [
                set, public, named_table,
                {read_concurrency, true},
                {write_concurrency, true}
            ]);
        _ ->
            ok
    end,
    ok.

%% @doc Get the deployment state for a deployment at the current chain tip.
%% HeightGetter is a function (Height) -> {ok, BlockIndex} | not_found
%% where BlockIndex contains at least #{height, header, median_time_past}.
-spec get_deployment_state(atom(), atom(), fun()) -> deployment_state().
get_deployment_state(Network, DeploymentName, HeightGetter) ->
    case beamchain_chainstate:get_tip() of
        {ok, {_Hash, Height}} ->
            get_deployment_state_at_height(Network, DeploymentName, Height, HeightGetter);
        not_found ->
            %% No blocks yet, all deployments are defined
            defined
    end.

%% @doc Get the deployment state at a specific height.
-spec get_deployment_state_at_height(atom(), atom(), integer(), fun()) -> deployment_state().
get_deployment_state_at_height(_Network, _DeploymentName, Height, _HeightGetter)
  when Height < 0 ->
    defined;
get_deployment_state_at_height(Network, DeploymentName, Height, HeightGetter) ->
    Deployment = deployment_params(Network, DeploymentName),
    get_state_for(Deployment, Network, Height, HeightGetter).

%% @doc Get signaling statistics for the current period.
%% Returns {Count, Elapsed, Possible} where:
%% - Count = number of blocks signaling
%% - Elapsed = blocks in current period so far
%% - Possible = whether threshold can still be reached
-spec get_state_statistics(atom(), atom(), integer(), fun()) ->
    {non_neg_integer(), non_neg_integer(), boolean()}.
get_state_statistics(Network, DeploymentName, Height, HeightGetter) ->
    Deployment = deployment_params(Network, DeploymentName),
    %% Use per-deployment period and threshold (Core: BIP9Deployment.period/.threshold)
    Period    = Deployment#deployment.period,
    Threshold = Deployment#deployment.threshold,

    %% Find start of current period
    %% Reference: versionbits.cpp GetStateStatisticsFor line 129
    %%   blocks_in_period = 1 + (pindex->nHeight % stats.period)
    PeriodStart = Height - (Height rem Period),
    Elapsed = Height - PeriodStart + 1,

    %% Count signaling blocks in current period
    Count = count_signaling(Deployment, PeriodStart, Height, HeightGetter),

    %% Can threshold still be reached?
    %% Reference: versionbits.cpp line 152
    %%   stats.possible = (stats.period - stats.threshold) >= (stats.elapsed - count)
    Remaining = Period - Elapsed,
    Possible = (Count + Remaining) >= Threshold,

    {Count, Elapsed, Possible}.

%% @doc Get deployment parameters for a specific deployment.
-spec deployment_params(atom(), atom()) -> #deployment{}.
deployment_params(Network, DeploymentName) ->
    Deployments = deployments(Network),
    case lists:keyfind(DeploymentName, #deployment.name, Deployments) of
        false -> error({unknown_deployment, DeploymentName});
        Dep -> Dep
    end.

%% @doc Get all deployments for a network.
-spec deployments(atom()) -> [#deployment{}].
deployments(mainnet) ->
    %% Reference: chainparams.cpp CMainParams — vDeployments[]
    [
        %% CSV deployment (BIP68, BIP112, BIP113)
        #deployment{
            name = csv,
            bit = 0,
            start_time = 1462060800,     %% May 1st, 2016
            timeout = 1493596800,        %% May 1st, 2017
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        },
        %% SegWit deployment (BIP141, BIP143, BIP147)
        #deployment{
            name = segwit,
            bit = 1,
            start_time = 1479168000,     %% Nov 15th, 2016
            timeout = 1510704000,        %% Nov 15th, 2017
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        },
        %% Taproot deployment (BIPs 340, 341, 342)
        #deployment{
            name = taproot,
            bit = 2,
            start_time = 1619222400,     %% Apr 24th, 2021
            timeout = 1628640000,        %% Aug 11th, 2021
            min_activation_height = 709632,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        },
        %% TESTDUMMY — not enforced on mainnet but present for completeness
        %% Reference: chainparams.cpp CMainParams vDeployments[DEPLOYMENT_TESTDUMMY]
        #deployment{
            name = testdummy,
            bit = 28,
            start_time = ?NEVER_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        }
    ];

deployments(testnet) ->
    %% Reference: chainparams.cpp CTestNetParams — vDeployments[]
    [
        #deployment{
            name = csv,
            bit = 0,
            start_time = 1456790400,     %% Mar 1st, 2016
            timeout = 1493596800,        %% May 1st, 2017
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = segwit,
            bit = 1,
            start_time = 1462060800,     %% May 1st, 2016
            timeout = 1493596800,        %% May 1st, 2017
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = taproot,
            bit = 2,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = testdummy,
            bit = 28,
            start_time = ?NEVER_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        }
    ];

deployments(testnet4) ->
    %% All soft forks are always active on testnet4
    %% Reference: chainparams.cpp CTestNet4Params — vDeployments[]
    [
        #deployment{
            name = csv,
            bit = 0,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = segwit,
            bit = 1,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = taproot,
            bit = 2,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = testdummy,
            bit = 28,
            start_time = ?NEVER_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        }
    ];

deployments(regtest) ->
    %% All soft forks are always active on regtest
    %% Reference: chainparams.cpp CRegTestParams — vDeployments[]
    %% Note: regtest uses period=144 for TESTDUMMY per Core; others use 2016.
    [
        #deployment{
            name = csv,
            bit = 0,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = segwit,
            bit = 1,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = taproot,
            bit = 2,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?TESTNET_THRESHOLD
        },
        #deployment{
            name = testdummy,
            bit = 28,
            start_time = ?NEVER_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = 144,               %% Core CRegTestParams: period=144 for testdummy
            threshold = 108             %% 75% of 144
        }
    ];

deployments(signet) ->
    %% All soft forks are always active on signet
    %% Reference: chainparams.cpp SigNetParams — vDeployments[]
    [
        #deployment{
            name = csv,
            bit = 0,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        },
        #deployment{
            name = segwit,
            bit = 1,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        },
        #deployment{
            name = taproot,
            bit = 2,
            start_time = ?ALWAYS_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        },
        #deployment{
            name = testdummy,
            bit = 28,
            start_time = ?NEVER_ACTIVE,
            timeout = ?NO_TIMEOUT,
            min_activation_height = 0,
            period = ?DEFAULT_PERIOD,
            threshold = ?MAINNET_THRESHOLD
        }
    ].

%% @doc Return a list of maps describing all deployments for a network.
%% Each map contains: name (binary), bit, start_time, timeout,
%% min_activation_height.  This avoids exposing the #deployment record
%% to callers that do not include the versionbits header.
-spec deployment_maps(atom()) -> [map()].
deployment_maps(Network) ->
    [#{ name                  => atom_to_binary(D#deployment.name, utf8),
        name_atom             => D#deployment.name,
        bit                   => D#deployment.bit,
        start_time            => D#deployment.start_time,
        timeout               => D#deployment.timeout,
        min_activation_height => D#deployment.min_activation_height,
        period                => D#deployment.period,
        threshold             => D#deployment.threshold }
     || D <- deployments(Network)].

%% @doc Check if a block should signal for a deployment.
%% Returns true if deployment is in STARTED or LOCKED_IN state.
-spec signal_bit(atom(), atom(), fun()) -> boolean().
signal_bit(Network, DeploymentName, HeightGetter) ->
    State = get_deployment_state(Network, DeploymentName, HeightGetter),
    State =:= started orelse State =:= locked_in.

%%% -------------------------------------------------------------------
%%% Internal: State machine
%%% -------------------------------------------------------------------

%% Get state for a deployment at a specific height.
%% Uses caching at period boundaries for efficiency.
%%
%% BIP9 state machine:
%% - State is evaluated at period boundaries (every 2016 blocks)
%% - State for period N (blocks [N*2016, (N+1)*2016-1]) is computed from:
%%   1. The state at the start of period N (which was computed from period N-1)
%%   2. The MTP of block (N*2016 - 1) to check start/timeout
%%   3. Block versions in period N-1 to check threshold
-spec get_state_for(#deployment{}, atom(), integer(), fun()) -> deployment_state().
get_state_for(#deployment{start_time = ?ALWAYS_ACTIVE}, _Network, _Height, _HeightGetter) ->
    active;
get_state_for(#deployment{start_time = ?NEVER_ACTIVE}, _Network, _Height, _HeightGetter) ->
    failed;
get_state_for(Deployment, Network, Height, HeightGetter) ->
    %% Find which period this height is in and compute state for that period.
    %% Use per-deployment period (Core: BIP9Deployment.period).
    %% Period 0: blocks 0..Period-1, Period 1: blocks Period..2*Period-1, etc.
    Period = Deployment#deployment.period,
    PeriodNum = Height div Period,

    case PeriodNum =:= 0 of
        true ->
            %% First period: no retarget boundary has been crossed yet.
            %% BIP9: "The genesis block is by definition in this state."
            defined;
        false ->
            %% State for this period was computed at the end of previous period.
            %% Cache key includes the period number.
            CacheKey = {Network, Deployment#deployment.name, PeriodNum},
            case ets:lookup(?VERSIONBITS_CACHE, CacheKey) of
                [{_, CachedState}] ->
                    CachedState;
                [] ->
                    %% Compute state by walking back to find last cached state
                    compute_state_with_cache(Deployment, Network, PeriodNum, HeightGetter)
            end
    end.

%% Get the last block height of a period.
%% PeriodLen is the deployment's period length (deployment.period).
-spec period_end_height(integer(), pos_integer()) -> integer().
period_end_height(PeriodNum, PeriodLen) ->
    (PeriodNum + 1) * PeriodLen - 1.

%% Compute state by walking back through periods, caching as we go.
%% TargetPeriod is the period number we want state for.
-spec compute_state_with_cache(#deployment{}, atom(), integer(), fun()) -> deployment_state().
compute_state_with_cache(Deployment, Network, TargetPeriod, HeightGetter) ->
    %% Walk back to find the most recent cached state or period 0
    {StartPeriod, StartState} = walk_back(Deployment, Network, TargetPeriod, HeightGetter),

    %% Walk forward, computing and caching states
    walk_forward(Deployment, Network, StartPeriod, StartState, TargetPeriod, HeightGetter).

%% Walk backwards through periods to find a cached state.
-spec walk_back(#deployment{}, atom(), integer(), fun()) -> {integer(), deployment_state()}.
walk_back(Deployment, Network, Period, HeightGetter) ->
    walk_back(Deployment, Network, Period, HeightGetter, []).

walk_back(_Deployment, _Network, Period, _HeightGetter, _ToCompute) when Period =< 0 ->
    %% Reached period 0 or before, start from defined.
    %% BIP9: "The genesis block is by definition in this state."
    {0, defined};
walk_back(Deployment, Network, Period, HeightGetter, ToCompute) ->
    CacheKey = {Network, Deployment#deployment.name, Period},
    case ets:lookup(?VERSIONBITS_CACHE, CacheKey) of
        [{_, CachedState}] ->
            %% Found cached state — stop walking back
            {Period, CachedState};
        [] ->
            PeriodLen = Deployment#deployment.period,
            %% Optimization: if MTP at end of the PREVIOUS period is before
            %% start_time, all earlier periods are also DEFINED.
            %% Reference: versionbits.cpp lines 57-61
            PrevPeriodEnd = period_end_height(Period - 1, PeriodLen),
            case get_median_time_past(PrevPeriodEnd, HeightGetter) of
                {ok, MTP} when MTP < Deployment#deployment.start_time ->
                    %% Before start time; cache as defined and stop.
                    ets:insert(?VERSIONBITS_CACHE, {CacheKey, defined}),
                    {Period, defined};
                _ ->
                    %% Need to walk back further
                    walk_back(Deployment, Network, Period - 1, HeightGetter,
                              [Period | ToCompute])
            end
    end.

%% Walk forward through periods, computing and caching states.
-spec walk_forward(#deployment{}, atom(), integer(), deployment_state(),
                   integer(), fun()) -> deployment_state().
walk_forward(_Deployment, _Network, CurrentPeriod, State, TargetPeriod, _HeightGetter)
  when CurrentPeriod >= TargetPeriod ->
    State;
walk_forward(Deployment, Network, CurrentPeriod, State, TargetPeriod, HeightGetter) ->
    %% Compute state for next period
    NextPeriod = CurrentPeriod + 1,
    NextState = compute_state_for_period(Deployment, Network, State, NextPeriod, HeightGetter),

    %% Cache the computed state
    CacheKey = {Network, Deployment#deployment.name, NextPeriod},
    ets:insert(?VERSIONBITS_CACHE, {CacheKey, NextState}),

    %% Continue to target
    walk_forward(Deployment, Network, NextPeriod, NextState, TargetPeriod, HeightGetter).

%% Compute next state for a period based on previous period's state.
%% PeriodNum is the period we're computing state FOR.
%% PrevState is the state at the start of PeriodNum (computed from PeriodNum-1).
%%
%% Reference: versionbits.cpp AbstractThresholdConditionChecker::GetStateFor
%% lines 76-112 (the switch statement over state).
-spec compute_state_for_period(#deployment{}, atom(), deployment_state(), integer(), fun()) ->
    deployment_state().
compute_state_for_period(_Deployment, _Network, active, _PeriodNum, _HeightGetter) ->
    %% ACTIVE is a terminal state. Reference: versionbits.cpp line 108.
    active;
compute_state_for_period(_Deployment, _Network, failed, _PeriodNum, _HeightGetter) ->
    %% FAILED is a terminal state. Reference: versionbits.cpp line 107.
    failed;
compute_state_for_period(Deployment, _Network, defined, PeriodNum, HeightGetter) ->
    %% DEFINED → STARTED if MTP at end of previous period >= start_time.
    %% Reference: versionbits.cpp lines 77-81.
    PeriodLen = Deployment#deployment.period,
    PrevPeriodEnd = period_end_height(PeriodNum - 1, PeriodLen),
    case get_median_time_past(PrevPeriodEnd, HeightGetter) of
        {ok, MTP} when MTP >= Deployment#deployment.start_time ->
            started;
        _ ->
            defined
    end;
compute_state_for_period(Deployment, _Network, started, PeriodNum, HeightGetter) ->
    %% STARTED: count signaling in previous period FIRST; only check
    %% timeout if the threshold was NOT met.
    %%
    %% IMPORTANT: Core counts BEFORE checking timeout (versionbits.cpp lines
    %% 84-98).  A period that simultaneously meets threshold AND exceeds
    %% timeout must transition to LOCKED_IN, not FAILED.
    %% Previous code checked timeout first — that was a consensus bug.
    PeriodLen = Deployment#deployment.period,
    PrevPeriodEnd   = period_end_height(PeriodNum - 1, PeriodLen),
    PrevPeriodStart = (PeriodNum - 1) * PeriodLen,
    Count = count_signaling(Deployment, PrevPeriodStart, PrevPeriodEnd, HeightGetter),
    Threshold = Deployment#deployment.threshold,
    case Count >= Threshold of
        true ->
            %% Threshold met → LOCKED_IN regardless of timeout.
            %% Reference: versionbits.cpp lines 93-94.
            locked_in;
        false ->
            %% Threshold not met; check timeout.
            %% Reference: versionbits.cpp lines 95-97.
            case get_median_time_past(PrevPeriodEnd, HeightGetter) of
                {ok, MTP} when MTP >= Deployment#deployment.timeout ->
                    failed;
                _ ->
                    started
            end
    end;
compute_state_for_period(Deployment, _Network, locked_in, PeriodNum, _HeightGetter) ->
    %% LOCKED_IN → ACTIVE once the first block of this period is at or past
    %% min_activation_height.
    %% Reference: versionbits.cpp lines 100-103:
    %%   if (pindexPrev->nHeight + 1 >= min_activation_height) stateNext = ACTIVE
    %% pindexPrev->nHeight + 1 = first block of current period = PeriodNum * PeriodLen.
    PeriodLen = Deployment#deployment.period,
    FirstBlockHeight = PeriodNum * PeriodLen,
    case FirstBlockHeight >= Deployment#deployment.min_activation_height of
        true  -> active;
        false -> locked_in
    end.

%% Exported for testing: compute one state transition for period 1.
compute_state(Deployment, Network, PrevState, HeightGetter) ->
    compute_state_for_period(Deployment, Network, PrevState, 1, HeightGetter).

%% Get median time past for a block height.
-spec get_median_time_past(integer(), fun()) -> {ok, integer()} | error.
get_median_time_past(Height, _HeightGetter) when Height < 0 ->
    {ok, 0};
get_median_time_past(Height, HeightGetter) ->
    case HeightGetter(Height) of
        {ok, #{median_time_past := MTP}} ->
            {ok, MTP};
        {ok, #{header := Header}} ->
            %% If MTP not precomputed, use timestamp as approximation
            {ok, Header#block_header.timestamp};
        _ ->
            error
    end.

%% Count blocks signaling for a deployment in a range.
-spec count_signaling(#deployment{}, integer(), integer(), fun()) -> non_neg_integer().
count_signaling(Deployment, StartHeight, EndHeight, HeightGetter) ->
    count_signaling(Deployment, StartHeight, EndHeight, HeightGetter, 0).

count_signaling(_Deployment, Height, EndHeight, _HeightGetter, Count)
  when Height > EndHeight ->
    Count;
count_signaling(Deployment, Height, EndHeight, HeightGetter, Count) ->
    case HeightGetter(Height) of
        {ok, #{header := Header}} ->
            Version = Header#block_header.version,
            NewCount = case version_bits_condition(Version, Deployment#deployment.bit) of
                true -> Count + 1;
                false -> Count
            end,
            count_signaling(Deployment, Height + 1, EndHeight, HeightGetter, NewCount);
        _ ->
            count_signaling(Deployment, Height + 1, EndHeight, HeightGetter, Count)
    end.

%% Check if a block version signals for a specific bit.
%% Requires top 3 bits to be 001 AND the specific bit to be set.
-spec version_bits_condition(integer(), 0..28) -> boolean().
version_bits_condition(Version, Bit) ->
    TopBitsOK = (Version band ?VERSIONBITS_TOP_MASK) =:= ?VERSIONBITS_TOP_BITS,
    BitSet = (Version band (1 bsl Bit)) =/= 0,
    TopBitsOK andalso BitSet.

%% (threshold/1 removed: threshold is now per-deployment via #deployment.threshold)

%%% -------------------------------------------------------------------
%%% compute_block_version/2
%%% Reference: Bitcoin Core versionbits.cpp ComputeBlockVersion()
%%%
%%% Build the version field for the next block to mine.
%%% Start with VERSIONBITS_TOP_BITS (0x20000000), then OR in each
%%% deployment bit that is in STARTED or LOCKED_IN state at the
%%% current tip height.
%%%
%%% This is the Erlang equivalent of:
%%%   int32_t nVersion = VERSIONBITS_TOP_BITS;
%%%   for each deployment:
%%%       if state == LOCKED_IN || state == STARTED:
%%%           nVersion |= (1 << bit)
%%%   return nVersion;
%%% -------------------------------------------------------------------

-spec compute_block_version(non_neg_integer(), map()) -> non_neg_integer().
compute_block_version(TipHeight, Params) ->
    Network = maps:get(network, Params, mainnet),
    HeightGetter = fun(H) -> beamchain_db:get_block_index(H) end,
    Deployments = deployments(Network),
    lists:foldl(fun(D, Version) ->
        State = get_state_for(D, Network, TipHeight, HeightGetter),
        case State =:= locked_in orelse State =:= started of
            true  -> Version bor (1 bsl D#deployment.bit);
            false -> Version
        end
    end, ?VERSIONBITS_TOP_BITS, Deployments).
