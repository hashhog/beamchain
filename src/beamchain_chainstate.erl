-module(beamchain_chainstate).
-behaviour(gen_server).

%% Chain state manager — tracks active chain tip, UTXO cache (ETS),
%% and handles chain reorganizations.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0]).

%% Chain queries
-export([get_tip/0, get_mtp/0, is_synced/0]).

%% UTXO cache — module functions (direct ETS access, no gen_server call)
-export([get_utxo/2, has_utxo/2, add_utxo/3, spend_utxo/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% ETS table names
-define(UTXO_CACHE, beamchain_utxo_cache).
-define(CHAIN_META, beamchain_chain_meta).

%% Flush tuning
-define(DEFAULT_MAX_CACHE_MB, 100).
-define(IBD_FLUSH_INTERVAL, 1000).

-record(state, {
    %% Current chain tip
    tip_hash          :: binary() | undefined,
    tip_height        :: integer(),

    %% Sliding window of last 11 block timestamps (oldest first)
    mtp_timestamps    :: [non_neg_integer()],

    %% Chain params for the active network
    params            :: map(),

    %% Blocks connected since last UTXO cache flush
    blocks_since_flush :: non_neg_integer(),

    %% Max UTXO cache size before forcing a flush (bytes)
    max_cache_bytes   :: non_neg_integer(),

    %% Whether we're in initial block download
    ibd               :: boolean()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Get the current chain tip.
%% Direct ETS read — no gen_server bottleneck.
-spec get_tip() -> {ok, {binary(), non_neg_integer()}} | not_found.
get_tip() ->
    case ets:lookup(?CHAIN_META, tip) of
        [{tip, Hash, Height}] -> {ok, {Hash, Height}};
        [] -> not_found
    end.

%% @doc Get the median time past for the current chain tip.
-spec get_mtp() -> non_neg_integer().
get_mtp() ->
    gen_server:call(?SERVER, get_mtp).

%% @doc Check if the chain tip is within 1 hour of current time.
-spec is_synced() -> boolean().
is_synced() ->
    gen_server:call(?SERVER, is_synced).

%%% ===================================================================
%%% UTXO cache (public ETS, called from any process)
%%% ===================================================================

%% @doc Look up a UTXO. Checks ETS cache first, falls through to RocksDB.
-spec get_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
get_utxo(Txid, Vout) ->
    Key = {Txid, Vout},
    case ets:lookup(?UTXO_CACHE, Key) of
        [{Key, Utxo}] ->
            {ok, Utxo};
        [] ->
            %% Fall through to RocksDB
            case beamchain_db:get_utxo(Txid, Vout) of
                {ok, Utxo} ->
                    %% Cache for future lookups
                    ets:insert(?UTXO_CACHE, {Key, Utxo}),
                    {ok, Utxo};
                not_found ->
                    not_found
            end
    end.

%% @doc Check if a UTXO exists. Checks ETS first.
-spec has_utxo(binary(), non_neg_integer()) -> boolean().
has_utxo(Txid, Vout) ->
    Key = {Txid, Vout},
    case ets:member(?UTXO_CACHE, Key) of
        true -> true;
        false -> beamchain_db:has_utxo(Txid, Vout)
    end.

%% @doc Add a UTXO to the cache. Write-through to RocksDB.
-spec add_utxo(binary(), non_neg_integer(), #utxo{}) -> ok.
add_utxo(Txid, Vout, Utxo) ->
    Key = {Txid, Vout},
    ets:insert(?UTXO_CACHE, {Key, Utxo}),
    %% Write-through: also persist to DB for durability
    beamchain_db:store_utxo(Txid, Vout, Utxo),
    ok.

%% @doc Spend (remove) a UTXO from the cache and DB.
%% Returns the spent UTXO for undo data.
-spec spend_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
spend_utxo(Txid, Vout) ->
    Key = {Txid, Vout},
    case ets:lookup(?UTXO_CACHE, Key) of
        [{Key, Utxo}] ->
            ets:delete(?UTXO_CACHE, Key),
            %% Also remove from DB
            beamchain_db:spend_utxo(Txid, Vout),
            {ok, Utxo};
        [] ->
            %% Not in cache, pass through to DB
            beamchain_db:spend_utxo(Txid, Vout)
    end.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Create ETS tables
    ets:new(?UTXO_CACHE, [set, public, named_table,
                           {read_concurrency, true}]),
    ets:new(?CHAIN_META, [set, public, named_table]),

    %% Load network params
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),

    %% Load chain tip from DB
    {TipHash, TipHeight} = load_chain_tip(),
    case TipHash of
        undefined -> ok;
        _ -> ets:insert(?CHAIN_META, {tip, TipHash, TipHeight})
    end,

    %% Load MTP sliding window (last 11 timestamps)
    MTPTimestamps = load_mtp_timestamps(TipHeight),

    MaxCacheMB = ?DEFAULT_MAX_CACHE_MB,
    logger:info("chainstate: initialized at height ~B", [TipHeight]),

    {ok, #state{
        tip_hash = TipHash,
        tip_height = TipHeight,
        mtp_timestamps = MTPTimestamps,
        params = Params,
        blocks_since_flush = 0,
        max_cache_bytes = MaxCacheMB * 1024 * 1024,
        ibd = true
    }}.

handle_call(get_mtp, _From, #state{mtp_timestamps = Ts} = State) ->
    {reply, compute_mtp(Ts), State};

handle_call(is_synced, _From, #state{mtp_timestamps = []} = State) ->
    {reply, false, State};
handle_call(is_synced, _From, #state{mtp_timestamps = Ts} = State) ->
    Latest = lists:last(Ts),
    Now = erlang:system_time(second),
    {reply, (Now - Latest) < 3600, State};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%% ===================================================================
%%% Internal: initialization
%%% ===================================================================

%% Load chain tip from the database.
load_chain_tip() ->
    case beamchain_db:get_chain_tip() of
        {ok, #{hash := Hash, height := Height}} ->
            {Hash, Height};
        not_found ->
            {undefined, -1}
    end.

%% Load last 11 timestamps for MTP computation (oldest first).
load_mtp_timestamps(Height) when Height < 0 ->
    [];
load_mtp_timestamps(Height) ->
    collect_timestamps(Height, 11, []).

collect_timestamps(_Height, 0, Acc) ->
    Acc;
collect_timestamps(Height, _N, Acc) when Height < 0 ->
    Acc;
collect_timestamps(Height, N, Acc) ->
    case beamchain_db:get_block_index(Height) of
        {ok, #{header := Header}} ->
            Ts = Header#block_header.timestamp,
            collect_timestamps(Height - 1, N - 1, [Ts | Acc]);
        not_found ->
            Acc
    end.

%%% ===================================================================
%%% Internal: MTP computation
%%% ===================================================================

%% Compute the median of a list of timestamps.
compute_mtp([]) ->
    0;
compute_mtp(Timestamps) ->
    Sorted = lists:sort(Timestamps),
    lists:nth((length(Sorted) div 2) + 1, Sorted).
