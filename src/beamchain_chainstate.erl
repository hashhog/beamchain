-module(beamchain_chainstate).
-behaviour(gen_server).

%% Chain state manager — tracks active chain tip, UTXO cache (ETS),
%% and handles chain reorganizations.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0, start_link/1, start_link/2]).

%% Chain queries
-export([get_tip/0, get_mtp/0, is_synced/0]).
-export([get_tip_height/0]).

%% UTXO cache — module functions (direct ETS access, no gen_server call)
-export([get_utxo/2, has_utxo/2, add_utxo/3, spend_utxo/2]).

%% Block connection / disconnection
-export([connect_block/1, disconnect_block/0, reorganize/1]).

%% Flush
-export([flush/0]).

%% Cache statistics
-export([cache_stats/0, cache_memory_usage/0]).

%% assumeUTXO support
-export([load_snapshot/1, compute_utxo_hash/0]).
-export([is_snapshot_chainstate/0, get_snapshot_base_height/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% ETS table names
-define(UTXO_CACHE, beamchain_utxo_cache).
-define(UTXO_DIRTY, beamchain_utxo_dirty).
-define(UTXO_FRESH, beamchain_utxo_fresh).  %% Entries that don't exist in RocksDB
-define(UTXO_SPENT, beamchain_utxo_spent).
-define(CHAIN_META, beamchain_chain_meta).

%% Flush tuning
-define(DEFAULT_MAX_CACHE_MB, 450).
-define(IBD_MAX_CACHE_MB, 1024).
-define(IBD_FLUSH_INTERVAL, 2000).

%% Estimated cache entry count threshold (3 million entries ~ 450MB)
%% Each UTXO entry is roughly 150 bytes on average (key + value + ETS overhead)
-define(DEFAULT_MAX_CACHE_ENTRIES, 3000000).

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

    %% Max UTXO cache entries before forcing a flush
    max_cache_entries :: non_neg_integer(),

    %% Running estimate of dynamic memory usage (bytes)
    cache_usage_bytes :: non_neg_integer(),

    %% Whether we're in initial block download
    ibd               :: boolean(),

    %% assumeUTXO support
    chainstate_role   :: main | snapshot | background,
    snapshot_base_height :: non_neg_integer() | undefined,
    snapshot_base_hash :: binary() | undefined
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [main], []).

%% @doc Start a named chainstate with a specific role.
%% Role can be: main, snapshot, or background.
start_link(Role) when Role =:= main; Role =:= background ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Role], []).

%% @doc Start a snapshot chainstate with preloaded UTXO data.
%% SnapshotData = #{base_hash, num_coins, coins}
start_link(snapshot, SnapshotData) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [snapshot, SnapshotData], []).

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

%% @doc Get just the tip height.
-spec get_tip_height() -> {ok, integer()} | not_found.
get_tip_height() ->
    case get_tip() of
        {ok, {_Hash, Height}} -> {ok, Height};
        not_found -> not_found
    end.

%% @doc Connect a block to the chain tip.
%% Validates the block, updates UTXOs, and advances the tip.
-spec connect_block(#block{}) -> ok | {error, term()}.
connect_block(Block) ->
    gen_server:call(?SERVER, {connect_block, Block}, 300000).

%% @doc Disconnect the current tip block.
%% Restores spent UTXOs from undo data and moves the tip back one.
-spec disconnect_block() -> ok | {error, term()}.
disconnect_block() ->
    gen_server:call(?SERVER, disconnect_block, 30000).

%% @doc Reorganize to a new chain.
%% NewBlocks = ordered list from fork point+1 to new tip.
%% Returns {ok, DisconnectedTxs} where DisconnectedTxs are the
%% non-coinbase transactions from the disconnected blocks (for mempool).
-spec reorganize([#block{}]) -> {ok, [#transaction{}]} | {error, term()}.
reorganize(NewBlocks) ->
    gen_server:call(?SERVER, {reorganize, NewBlocks}, 120000).

%% @doc Flush dirty UTXO cache entries to RocksDB.
-spec flush() -> ok.
flush() ->
    gen_server:call(?SERVER, flush, 60000).

%%% ===================================================================
%%% assumeUTXO API
%%% ===================================================================

%% @doc Load a UTXO snapshot from file and activate it.
%% Returns {ok, Height} on success where Height is the snapshot base height.
-spec load_snapshot(string()) -> {ok, non_neg_integer()} | {error, term()}.
load_snapshot(Path) ->
    gen_server:call(?SERVER, {load_snapshot, Path}, infinity).

%% @doc Compute the SHA256 hash of the current UTXO set.
%% Used to verify snapshot integrity after background validation.
-spec compute_utxo_hash() -> binary().
compute_utxo_hash() ->
    gen_server:call(?SERVER, compute_utxo_hash, 300000).

%% @doc Check if this chainstate was loaded from a snapshot.
-spec is_snapshot_chainstate() -> boolean().
is_snapshot_chainstate() ->
    gen_server:call(?SERVER, is_snapshot_chainstate).

%% @doc Get the base height of the snapshot, if this is a snapshot chainstate.
-spec get_snapshot_base_height() -> {ok, non_neg_integer()} | not_snapshot.
get_snapshot_base_height() ->
    gen_server:call(?SERVER, get_snapshot_base_height).

%%% ===================================================================
%%% UTXO cache (public ETS, called from any process)
%%%
%%% Write-behind strategy: new/modified UTXOs are written only to ETS
%%% and tracked in UTXO_DIRTY. Spent UTXOs are tracked in UTXO_SPENT.
%%% Periodically (or on shutdown) we flush dirty entries to RocksDB
%%% and delete spent entries from RocksDB in a single WriteBatch.
%%% ===================================================================

%% @doc Look up a UTXO. Checks ETS cache first, falls through to RocksDB.
%% Cache misses from RocksDB are added to cache (not dirty, not fresh).
-spec get_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
get_utxo(Txid, Vout) ->
    Key = {Txid, Vout},
    case ets:lookup(?UTXO_CACHE, Key) of
        [{Key, Utxo}] ->
            {ok, Utxo};
        [] ->
            %% If it was spent in cache (pending flush), it's gone
            case ets:member(?UTXO_SPENT, Key) of
                true ->
                    not_found;
                false ->
                    %% Fall through to RocksDB (cache miss)
                    case beamchain_db:get_utxo(Txid, Vout) of
                        {ok, Utxo} ->
                            %% Cache for future lookups. NOT dirty, NOT fresh
                            %% since it already exists in RocksDB.
                            add_utxo_from_disk(Txid, Vout, Utxo),
                            {ok, Utxo};
                        not_found ->
                            not_found
                    end
            end
    end.

%% @doc Check if a UTXO exists. Checks ETS first.
-spec has_utxo(binary(), non_neg_integer()) -> boolean().
has_utxo(Txid, Vout) ->
    Key = {Txid, Vout},
    case ets:member(?UTXO_CACHE, Key) of
        true -> true;
        false ->
            case ets:member(?UTXO_SPENT, Key) of
                true -> false;
                false -> beamchain_db:has_utxo(Txid, Vout)
            end
    end.

%% @doc Add a UTXO to the cache (write-behind, not persisted until flush).
%% New UTXOs created in this session are marked FRESH (don't exist in RocksDB).
%% If marked FRESH and spent before flush, we can skip both the DB write and delete.
-spec add_utxo(binary(), non_neg_integer(), #utxo{}) -> ok.
add_utxo(Txid, Vout, Utxo) ->
    Key = {Txid, Vout},
    ets:insert(?UTXO_CACHE, {Key, Utxo}),
    ets:insert(?UTXO_DIRTY, {Key}),
    %% Mark as FRESH (doesn't exist in RocksDB yet)
    %% This enables the optimization where spending a FRESH UTXO skips DB ops
    ets:insert(?UTXO_FRESH, {Key}),
    %% If it was pending a DB delete, cancel that (reorg case)
    ets:delete(?UTXO_SPENT, Key),
    ok.

%% @doc Add a UTXO from disk (for cache miss fills). Not marked FRESH or DIRTY.
-spec add_utxo_from_disk(binary(), non_neg_integer(), #utxo{}) -> ok.
add_utxo_from_disk(Txid, Vout, Utxo) ->
    Key = {Txid, Vout},
    ets:insert(?UTXO_CACHE, {Key, Utxo}),
    %% Not dirty (matches what's in RocksDB), not fresh (exists in RocksDB)
    ok.

%% @doc Spend (remove) a UTXO from the cache.
%% Returns the spent UTXO for undo data.
%%
%% FRESH flag optimization (like Bitcoin Core's CCoinsViewCache):
%% - If the UTXO is FRESH (created in cache, not yet in RocksDB), spending it
%%   means we just delete it from cache — no DB operations needed at all.
%% - If the UTXO is not FRESH (loaded from RocksDB), we schedule a DB delete.
-spec spend_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
spend_utxo(Txid, Vout) ->
    Key = {Txid, Vout},
    case ets:lookup(?UTXO_CACHE, Key) of
        [{Key, Utxo}] ->
            ets:delete(?UTXO_CACHE, Key),
            IsFresh = ets:member(?UTXO_FRESH, Key),
            case IsFresh of
                true ->
                    %% FRESH optimization: UTXO was created in cache and never
                    %% persisted to RocksDB. We can just forget it entirely —
                    %% no need to write it or schedule a delete.
                    ets:delete(?UTXO_DIRTY, Key),
                    ets:delete(?UTXO_FRESH, Key);
                false ->
                    %% Not fresh: either loaded from RocksDB or modified.
                    %% Schedule a DB delete on flush.
                    ets:delete(?UTXO_DIRTY, Key),
                    ets:insert(?UTXO_SPENT, {Key})
            end,
            {ok, Utxo};
        [] ->
            %% Not in cache, try RocksDB
            case beamchain_db:get_utxo(Txid, Vout) of
                {ok, Utxo} ->
                    %% Schedule DB delete on flush
                    ets:insert(?UTXO_SPENT, {Key}),
                    {ok, Utxo};
                not_found ->
                    not_found
            end
    end.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    init([main]);

init([main]) ->
    init_chainstate(main, undefined);

init([background]) ->
    init_chainstate(background, undefined);

init([snapshot, SnapshotData]) ->
    init_chainstate(snapshot, SnapshotData).

%% Common initialization for all chainstate roles
init_chainstate(Role, SnapshotData) ->
    %% Create ETS tables (only for main chainstate, others reuse)
    case Role of
        main ->
            %% UTXO cache: read_concurrency for parallel reads during validation
            ets:new(?UTXO_CACHE, [set, public, named_table,
                                   {read_concurrency, true},
                                   {write_concurrency, true}]),
            %% Dirty/fresh/spent: write_concurrency since many processes update these
            ets:new(?UTXO_DIRTY, [set, public, named_table,
                                   {write_concurrency, true}]),
            ets:new(?UTXO_FRESH, [set, public, named_table,
                                   {write_concurrency, true}]),
            ets:new(?UTXO_SPENT, [set, public, named_table,
                                   {write_concurrency, true}]),
            ets:new(?CHAIN_META, [set, public, named_table,
                                   {read_concurrency, true}]);
        _ ->
            %% Snapshot and background chainstates reuse the main ETS tables
            ok
    end,

    %% Load network params
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),

    %% Initialize based on role
    {TipHash, TipHeight, SnapshotBaseHeight, SnapshotBaseHash} =
        case {Role, SnapshotData} of
            {snapshot, #{base_hash := BaseHash, coins := Coins}} ->
                %% Load snapshot UTXOs into cache
                populate_utxo_cache_from_snapshot(Coins),
                %% Get snapshot base height from chain params
                case beamchain_chain_params:get_assumeutxo_by_hash(BaseHash, Network) of
                    {ok, Height, _} ->
                        logger:info("chainstate: loading snapshot at height ~B", [Height]),
                        {BaseHash, Height, Height, BaseHash};
                    not_found ->
                        logger:warning("chainstate: unknown snapshot base hash"),
                        {BaseHash, 0, 0, BaseHash}
                end;
            {background, _} ->
                %% Background chainstate starts from genesis
                logger:info("chainstate: starting background validation from genesis"),
                {undefined, -1, undefined, undefined};
            {main, _} ->
                %% Main chainstate loads from DB
                {H, Ht} = load_chain_tip(),
                case H of
                    undefined -> ok;
                    _ -> ets:insert(?CHAIN_META, {tip, H, Ht})
                end,
                {H, Ht, undefined, undefined}
        end,

    %% Load MTP sliding window (last 11 timestamps)
    MTPTimestamps = case Role of
        background -> [];
        _ -> load_mtp_timestamps(TipHeight)
    end,

    %% Start with large cache for IBD, shrink when caught up
    MaxCacheMB = ?IBD_MAX_CACHE_MB,
    logger:info("chainstate (~p): initialized at height ~B (cache ~BMB)",
                [Role, TipHeight, MaxCacheMB]),

    {ok, #state{
        tip_hash = TipHash,
        tip_height = TipHeight,
        mtp_timestamps = MTPTimestamps,
        params = Params,
        blocks_since_flush = 0,
        max_cache_bytes = MaxCacheMB * 1024 * 1024,
        max_cache_entries = ?DEFAULT_MAX_CACHE_ENTRIES,
        cache_usage_bytes = 0,
        ibd = true,
        chainstate_role = Role,
        snapshot_base_height = SnapshotBaseHeight,
        snapshot_base_hash = SnapshotBaseHash
    }}.

handle_call(get_mtp, _From, #state{mtp_timestamps = Ts} = State) ->
    {reply, compute_mtp(Ts), State};

handle_call(is_synced, _From, #state{mtp_timestamps = []} = State) ->
    {reply, false, State};
handle_call(is_synced, _From, #state{mtp_timestamps = Ts} = State) ->
    Latest = lists:last(Ts),
    Now = erlang:system_time(second),
    {reply, (Now - Latest) < 3600, State};

handle_call({connect_block, Block}, _From, State) ->
    case do_connect_block(Block, State) of
        {ok, State2} ->
            {reply, ok, State2};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call(disconnect_block, _From, State) ->
    case do_disconnect_block(State) of
        {ok, State2} ->
            {reply, ok, State2};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({reorganize, NewBlocks}, _From, State) ->
    case do_reorganize(NewBlocks, State) of
        {ok, State2, DisconnectedTxs} ->
            {reply, {ok, DisconnectedTxs}, State2};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call(flush, _From, State) ->
    State2 = do_flush(State),
    {reply, ok, State2};

%% assumeUTXO support
handle_call({load_snapshot, Path}, _From, State) ->
    case do_load_snapshot(Path, State) of
        {ok, State2, Height} ->
            {reply, {ok, Height}, State2};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call(compute_utxo_hash, _From, State) ->
    Hash = do_compute_utxo_hash(),
    {reply, Hash, State};

handle_call(is_snapshot_chainstate, _From,
            #state{chainstate_role = Role} = State) ->
    {reply, Role =:= snapshot, State};

handle_call(get_snapshot_base_height, _From,
            #state{snapshot_base_height = Height} = State) ->
    case Height of
        undefined -> {reply, not_snapshot, State};
        H -> {reply, {ok, H}, State}
    end;

handle_call(get_tip_height, _From, #state{tip_height = Height} = State) ->
    {reply, {ok, Height}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    logger:info("chainstate: flushing UTXO cache on shutdown"),
    do_flush(State),
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
%%% Internal: connect block
%%% ===================================================================

do_connect_block(#block{header = Header} = Block,
                 #state{tip_height = TipHeight, params = Params} = State) ->
    Height = TipHeight + 1,

    %% Build PrevIndex for validation
    PrevIndex = case TipHeight < 0 of
        true ->
            %% Genesis block — no previous block
            #{height => -1, header => undefined,
              chainwork => <<0:256>>, status => 2};
        false ->
            case beamchain_db:get_block_index(TipHeight) of
                {ok, PI} -> PI;
                not_found -> error({missing_prev_index, TipHeight})
            end
    end,

    %% Full consensus validation + UTXO update
    case beamchain_validation:connect_block(Block, Height, PrevIndex, Params) of
        ok ->
            BlockHash = beamchain_serialize:block_hash(Header),

            %% Update chain tip in ETS for fast reads
            ets:insert(?CHAIN_META, {tip, BlockHash, Height}),

            %% Update MTP sliding window
            NewMTP = update_mtp_connect(Header#block_header.timestamp,
                                         State#state.mtp_timestamps),

            BlocksSinceFlush = State#state.blocks_since_flush + 1,
            State2 = State#state{
                tip_hash = BlockHash,
                tip_height = Height,
                mtp_timestamps = NewMTP,
                blocks_since_flush = BlocksSinceFlush
            },
            State3 = maybe_check_ibd(State2),
            State4 = maybe_flush(State3),

            %% ZMQ notification for block connect
            beamchain_zmq:notify_block(Block, connect),

            {ok, State4};
        {error, Reason} ->
            {error, Reason}
    end.

%% Append a new timestamp to the MTP window, keeping at most 11.
update_mtp_connect(Timestamp, Timestamps) ->
    Updated = Timestamps ++ [Timestamp],
    case length(Updated) > 11 of
        true -> tl(Updated);
        false -> Updated
    end.

%% Check if we've left IBD based on the tip timestamp.
maybe_check_ibd(#state{mtp_timestamps = []} = State) ->
    State;
maybe_check_ibd(#state{ibd = true, mtp_timestamps = Ts} = State) ->
    Latest = lists:last(Ts),
    Now = erlang:system_time(second),
    case (Now - Latest) < 3600 of
        true ->
            logger:info("chainstate: leaving IBD at height ~B, "
                        "shrinking cache to ~BMB (~B max entries)",
                        [State#state.tip_height, ?DEFAULT_MAX_CACHE_MB,
                         ?DEFAULT_MAX_CACHE_ENTRIES]),
            %% Flush and shrink cache for normal operation
            State2 = do_flush(State),
            State2#state{
                ibd = false,
                max_cache_bytes = ?DEFAULT_MAX_CACHE_MB * 1024 * 1024,
                max_cache_entries = ?DEFAULT_MAX_CACHE_ENTRIES
            };
        false ->
            State
    end;
maybe_check_ibd(State) ->
    State.

%%% ===================================================================
%%% Internal: disconnect block
%%% ===================================================================

do_disconnect_block(#state{tip_hash = undefined}) ->
    {error, no_tip};
do_disconnect_block(#state{tip_hash = TipHash, tip_height = TipHeight,
                            params = Params} = State) ->
    %% Get the tip block from DB
    case beamchain_db:get_block(TipHash) of
        {ok, Block} ->
            %% Call validation to reverse the block's UTXO changes
            case beamchain_validation:disconnect_block(Block, TipHeight, Params) of
                ok ->
                    %% Move tip back to previous block
                    PrevHash = Block#block.header#block_header.prev_hash,
                    PrevHeight = TipHeight - 1,

                    ets:insert(?CHAIN_META, {tip, PrevHash, PrevHeight}),
                    beamchain_db:set_chain_tip(PrevHash, PrevHeight),

                    %% Update MTP: drop newest, restore oldest if possible
                    NewMTP = update_mtp_disconnect(PrevHeight,
                                                    State#state.mtp_timestamps),

                    %% ZMQ notification for block disconnect
                    beamchain_zmq:notify_block(Block, disconnect),

                    {ok, State#state{
                        tip_hash = PrevHash,
                        tip_height = PrevHeight,
                        mtp_timestamps = NewMTP
                    }};
                {error, Reason} ->
                    {error, Reason}
            end;
        not_found ->
            {error, tip_block_not_found}
    end.

%% Remove the newest timestamp from MTP window and try to restore
%% the oldest one that fell off when we connected this block.
update_mtp_disconnect(_NewTipHeight, []) ->
    [];
update_mtp_disconnect(NewTipHeight, Timestamps) ->
    %% Drop the last timestamp (the disconnected block's)
    Trimmed = lists:sublist(Timestamps, length(Timestamps) - 1),
    %% Try to restore the timestamp that was dropped when this block
    %% was originally connected. It would be at height NewTipHeight - 10.
    RestoreHeight = NewTipHeight - 10,
    case RestoreHeight >= 0 of
        true ->
            case beamchain_db:get_block_index(RestoreHeight) of
                {ok, #{header := Hdr}} ->
                    [Hdr#block_header.timestamp | Trimmed];
                not_found ->
                    Trimmed
            end;
        false ->
            Trimmed
    end.

%%% ===================================================================
%%% Internal: chain reorganization
%%% ===================================================================

%% Reorganize the chain to include NewBlocks.
%% NewBlocks must be ordered from fork_point+1 to new tip.
do_reorganize([], State) ->
    {ok, State, []};
do_reorganize(NewBlocks, State) ->
    %% The first new block's prev_hash is our fork point
    [FirstBlock | _] = NewBlocks,
    ForkHash = FirstBlock#block.header#block_header.prev_hash,

    logger:info("chainstate: reorganizing to fork point ~s",
                [hash_hex(ForkHash)]),

    %% Step 1: disconnect blocks from current tip back to fork point
    case disconnect_to(ForkHash, State, []) of
        {ok, State2, DisconnectedTxs} ->
            logger:info("chainstate: disconnected ~B blocks, connecting ~B new",
                        [length(DisconnectedTxs), length(NewBlocks)]),

            %% Step 2: connect the new chain
            case connect_blocks(NewBlocks, State2) of
                {ok, State3} ->
                    {ok, State3, DisconnectedTxs};
                {error, Reason} ->
                    %% Failed to connect new chain — critical error.
                    %% In a production node we'd try to reconnect the old chain.
                    logger:error("chainstate: reorg failed on connect: ~p",
                                 [Reason]),
                    {error, {reorg_connect_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {reorg_disconnect_failed, Reason}}
    end.

%% Disconnect blocks until tip_hash == TargetHash.
disconnect_to(TargetHash, #state{tip_hash = TargetHash} = State, AccTxs) ->
    {ok, State, AccTxs};
disconnect_to(_TargetHash, #state{tip_height = H} = _State, _AccTxs)
  when H < 0 ->
    {error, fork_point_not_found};
disconnect_to(TargetHash, State, AccTxs) ->
    %% Get the tip block to collect its transactions
    case beamchain_db:get_block(State#state.tip_hash) of
        {ok, Block} ->
            %% Collect non-coinbase txs for mempool re-submission
            NonCbTxs = [Tx || Tx <- Block#block.transactions,
                         not beamchain_validation:is_coinbase_tx(Tx)],
            case do_disconnect_block(State) of
                {ok, State2} ->
                    disconnect_to(TargetHash, State2, AccTxs ++ NonCbTxs);
                {error, Reason} ->
                    {error, Reason}
            end;
        not_found ->
            {error, tip_block_not_found}
    end.

%% Connect a list of blocks in order.
connect_blocks([], State) ->
    {ok, State};
connect_blocks([Block | Rest], State) ->
    case do_connect_block(Block, State) of
        {ok, State2} ->
            connect_blocks(Rest, State2);
        {error, Reason} ->
            {error, Reason}
    end.

%% Format hash for logging.
hash_hex(<<H:4/binary, _/binary>>) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B:8>> <= H]) ++ "...";
hash_hex(_) -> "???".

%%% ===================================================================
%%% Internal: UTXO cache flush
%%% ===================================================================

%% Decide whether to flush based on IBD interval, entry count, or memory size.
maybe_flush(#state{ibd = true, blocks_since_flush = N} = State)
  when N >= ?IBD_FLUSH_INTERVAL ->
    do_flush(State);
maybe_flush(#state{ibd = false, max_cache_bytes = MaxBytes,
                    max_cache_entries = MaxEntries} = State) ->
    %% In normal operation, flush if cache exceeds limits
    CacheEntries = ets:info(?UTXO_CACHE, size),
    CacheBytes = cache_memory_usage(),
    case CacheEntries > MaxEntries orelse CacheBytes > MaxBytes of
        true ->
            logger:info("chainstate: flushing cache (~B entries, ~.1fMB)",
                        [CacheEntries, CacheBytes / 1024 / 1024]),
            do_flush(State);
        false ->
            State
    end;
maybe_flush(State) ->
    State.

%% Flush dirty entries to RocksDB in a single write batch.
%% After flush, all entries become "clean" (match what's in RocksDB).
do_flush(#state{tip_hash = undefined} = State) ->
    State;
do_flush(#state{tip_hash = TipHash, tip_height = TipHeight} = State) ->
    DirtyCount = ets:info(?UTXO_DIRTY, size),
    SpentCount = ets:info(?UTXO_SPENT, size),
    FreshCount = ets:info(?UTXO_FRESH, size),
    case DirtyCount =:= 0 andalso SpentCount =:= 0 of
        true ->
            %% Nothing to flush
            State#state{blocks_since_flush = 0};
        false ->
            %% Write HEAD_BLOCKS marker (crash recovery sentinel)
            Marker = <<TipHash/binary, TipHeight:64/big>>,
            beamchain_db:put_meta(<<"HEAD_BLOCKS">>, Marker),

            %% Build write batch
            Ops = build_flush_ops(),

            %% Add chain tip and flush height to the batch
            TipValue = <<TipHash:32/binary, TipHeight:64/big>>,
            AllOps = Ops ++ [
                {put, meta, <<"chain_tip">>, TipValue},
                {put, meta, <<"utxo_flush_height">>,
                 <<TipHeight:64/big>>}
            ],

            case beamchain_db:write_batch(AllOps) of
                ok ->
                    %% Clear dirty/fresh/spent tracking tables.
                    %% After flush, all cached entries match RocksDB (clean).
                    %% FRESH entries are no longer fresh (they're now in RocksDB).
                    ets:delete_all_objects(?UTXO_DIRTY),
                    ets:delete_all_objects(?UTXO_FRESH),
                    ets:delete_all_objects(?UTXO_SPENT),

                    %% Remove crash recovery marker
                    beamchain_db:put_meta(<<"HEAD_BLOCKS">>, <<>>),

                    logger:debug("chainstate: flushed ~B dirty (~B fresh), ~B spent "
                                 "at height ~B",
                                 [DirtyCount, FreshCount, SpentCount, TipHeight]),
                    State#state{blocks_since_flush = 0};
                {error, Reason} ->
                    logger:error("chainstate: flush failed: ~p", [Reason]),
                    State
            end
    end.

%% Build the list of write batch operations from dirty/spent tables.
build_flush_ops() ->
    %% Dirty entries: write UTXO to chainstate CF
    DirtyOps = ets:foldl(fun({Key}, Acc) ->
        case ets:lookup(?UTXO_CACHE, Key) of
            [{Key, Utxo}] ->
                {Txid, Vout} = Key,
                OutpointKey = <<Txid:32/binary, Vout:32/big>>,
                Value = encode_utxo(Utxo),
                [{put, chainstate, OutpointKey, Value} | Acc];
            [] ->
                %% Entry was removed between dirty mark and flush
                Acc
        end
    end, [], ?UTXO_DIRTY),

    %% Spent entries: delete from chainstate CF
    SpentOps = ets:foldl(fun({Key}, Acc) ->
        {Txid, Vout} = Key,
        OutpointKey = <<Txid:32/binary, Vout:32/big>>,
        [{delete, chainstate, OutpointKey} | Acc]
    end, [], ?UTXO_SPENT),

    DirtyOps ++ SpentOps.

%% Encode UTXO to binary (same format as beamchain_db).
encode_utxo(#utxo{value = Value, script_pubkey = Script,
                   is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    <<Value:64/little, Height:32/little, CoinbaseFlag:8, Script/binary>>.

%%% ===================================================================
%%% UTXO cache statistics
%%% ===================================================================

%% @doc Get cache statistics.
-spec cache_stats() -> map().
cache_stats() ->
    CacheSize = ets:info(?UTXO_CACHE, size),
    DirtyCount = ets:info(?UTXO_DIRTY, size),
    FreshCount = ets:info(?UTXO_FRESH, size),
    SpentCount = ets:info(?UTXO_SPENT, size),
    MemoryBytes = cache_memory_usage(),
    #{
        cache_entries => CacheSize,
        dirty_entries => DirtyCount,
        fresh_entries => FreshCount,
        pending_deletes => SpentCount,
        memory_bytes => MemoryBytes,
        memory_mb => MemoryBytes / 1024 / 1024
    }.

%% @doc Get approximate cache memory usage in bytes.
%% Uses ETS memory info * word size for accurate estimate.
-spec cache_memory_usage() -> non_neg_integer().
cache_memory_usage() ->
    WordSize = erlang:system_info(wordsize),
    CacheMem = ets:info(?UTXO_CACHE, memory) * WordSize,
    DirtyMem = ets:info(?UTXO_DIRTY, memory) * WordSize,
    FreshMem = ets:info(?UTXO_FRESH, memory) * WordSize,
    SpentMem = ets:info(?UTXO_SPENT, memory) * WordSize,
    CacheMem + DirtyMem + FreshMem + SpentMem.

%%% ===================================================================
%%% Internal: MTP computation
%%% ===================================================================

%% Compute the median of a list of timestamps.
compute_mtp([]) ->
    0;
compute_mtp(Timestamps) ->
    Sorted = lists:sort(Timestamps),
    lists:nth((length(Sorted) div 2) + 1, Sorted).

%%% ===================================================================
%%% Internal: assumeUTXO support
%%% ===================================================================

%% Load a UTXO snapshot from file
do_load_snapshot(Path, State) ->
    Network = beamchain_config:network(),

    %% Parse the snapshot file
    case beamchain_snapshot:load_snapshot(Path) of
        {ok, #{base_hash := BaseHash, num_coins := NumCoins, coins := Coins} = SnapshotData} ->
            %% Verify the snapshot against known parameters
            case beamchain_snapshot:verify_snapshot(SnapshotData, Network) of
                ok ->
                    %% Look up the snapshot height
                    case beamchain_chain_params:get_assumeutxo_by_hash(BaseHash, Network) of
                        {ok, Height, _} ->
                            logger:info("chainstate: loading ~B coins from snapshot at height ~B",
                                        [NumCoins, Height]),

                            %% Populate the UTXO cache
                            populate_utxo_cache_from_snapshot(Coins),

                            %% Update state
                            State2 = State#state{
                                tip_hash = BaseHash,
                                tip_height = Height,
                                chainstate_role = snapshot,
                                snapshot_base_height = Height,
                                snapshot_base_hash = BaseHash
                            },

                            %% Update ETS chain meta
                            ets:insert(?CHAIN_META, {tip, BaseHash, Height}),

                            %% Start background validation
                            spawn(fun() -> start_background_validation() end),

                            {ok, State2, Height};
                        not_found ->
                            {error, {unknown_snapshot_base, BaseHash}}
                    end;
                {error, Reason} ->
                    {error, {snapshot_verification_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {snapshot_load_failed, Reason}}
    end.

%% Populate the UTXO cache from snapshot coins
populate_utxo_cache_from_snapshot(Coins) ->
    %% Clear existing cache entries
    ets:delete_all_objects(?UTXO_CACHE),
    ets:delete_all_objects(?UTXO_DIRTY),
    ets:delete_all_objects(?UTXO_FRESH),
    ets:delete_all_objects(?UTXO_SPENT),

    %% Insert all coins from snapshot
    lists:foreach(fun({Txid, Vout, Utxo}) ->
        Key = {Txid, Vout},
        ets:insert(?UTXO_CACHE, {Key, Utxo}),
        %% Mark as DIRTY so they get flushed to RocksDB
        ets:insert(?UTXO_DIRTY, {Key}),
        %% Mark as FRESH since they don't exist in RocksDB yet
        ets:insert(?UTXO_FRESH, {Key})
    end, Coins),

    NumCoins = length(Coins),
    logger:info("chainstate: loaded ~B coins into cache", [NumCoins]),
    ok.

%% Compute the SHA256 hash of all UTXOs in the cache
do_compute_utxo_hash() ->
    %% Collect all UTXOs from cache in deterministic order
    AllEntries = ets:tab2list(?UTXO_CACHE),

    %% Sort by outpoint key
    Sorted = lists:sort(fun({Key1, _}, {Key2, _}) ->
        Key1 =< Key2
    end, AllEntries),

    %% Hash all entries
    HashCtx = crypto:hash_init(sha256),
    FinalCtx = lists:foldl(fun({{Txid, Vout}, Utxo}, Ctx) ->
        CoinBin = serialize_coin_for_hash(Txid, Vout, Utxo),
        crypto:hash_update(Ctx, CoinBin)
    end, HashCtx, Sorted),

    crypto:hash_final(FinalCtx).

%% Serialize a coin for hashing (deterministic format)
serialize_coin_for_hash(Txid, Vout, #utxo{value = Value, script_pubkey = Script,
                                          is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    <<Txid:32/binary, Vout:32/big, Value:64/little, Height:32/little,
      CoinbaseFlag:8, Script/binary>>.

%% Start background validation chainstate
start_background_validation() ->
    %% Wait a bit for the main chainstate to be fully initialized
    timer:sleep(1000),

    %% Start the background chainstate via supervisor
    case beamchain_chainstate_sup:start_background_chainstate() of
        {ok, _Pid} ->
            logger:info("chainstate: started background validation"),
            ok;
        {error, {already_started, _}} ->
            logger:info("chainstate: background validation already running"),
            ok;
        {error, Reason} ->
            logger:warning("chainstate: failed to start background validation: ~p",
                           [Reason]),
            {error, Reason}
    end.
