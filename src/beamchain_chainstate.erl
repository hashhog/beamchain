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

%% Block connection / disconnection
-export([connect_block/1, disconnect_block/0, reorganize/1]).

%% Flush
-export([flush/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% ETS table names
-define(UTXO_CACHE, beamchain_utxo_cache).
-define(UTXO_DIRTY, beamchain_utxo_dirty).
-define(UTXO_SPENT, beamchain_utxo_spent).
-define(CHAIN_META, beamchain_chain_meta).

%% Flush tuning
-define(DEFAULT_MAX_CACHE_MB, 200).
-define(IBD_MAX_CACHE_MB, 1024).
-define(IBD_FLUSH_INTERVAL, 10000).

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

%% @doc Connect a block to the chain tip.
%% Validates the block, updates UTXOs, and advances the tip.
-spec connect_block(#block{}) -> ok | {error, term()}.
connect_block(Block) ->
    gen_server:call(?SERVER, {connect_block, Block}, 60000).

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
%%% UTXO cache (public ETS, called from any process)
%%%
%%% Write-behind strategy: new/modified UTXOs are written only to ETS
%%% and tracked in UTXO_DIRTY. Spent UTXOs are tracked in UTXO_SPENT.
%%% Periodically (or on shutdown) we flush dirty entries to RocksDB
%%% and delete spent entries from RocksDB in a single WriteBatch.
%%% ===================================================================

%% @doc Look up a UTXO. Checks ETS cache first, falls through to RocksDB.
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
                    %% Fall through to RocksDB
                    case beamchain_db:get_utxo(Txid, Vout) of
                        {ok, Utxo} ->
                            %% Cache for future lookups
                            ets:insert(?UTXO_CACHE, {Key, Utxo}),
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
-spec add_utxo(binary(), non_neg_integer(), #utxo{}) -> ok.
add_utxo(Txid, Vout, Utxo) ->
    Key = {Txid, Vout},
    ets:insert(?UTXO_CACHE, {Key, Utxo}),
    ets:insert(?UTXO_DIRTY, {Key}),
    %% If it was pending a DB delete, cancel that
    ets:delete(?UTXO_SPENT, Key),
    ok.

%% @doc Spend (remove) a UTXO from the cache.
%% Returns the spent UTXO for undo data.
-spec spend_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
spend_utxo(Txid, Vout) ->
    Key = {Txid, Vout},
    case ets:lookup(?UTXO_CACHE, Key) of
        [{Key, Utxo}] ->
            ets:delete(?UTXO_CACHE, Key),
            case ets:member(?UTXO_DIRTY, Key) of
                true ->
                    %% Was freshly created, never persisted — just forget it
                    ets:delete(?UTXO_DIRTY, Key);
                false ->
                    %% Was loaded from RocksDB — schedule a DB delete on flush
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
    %% Create ETS tables
    %% UTXO cache: read_concurrency for parallel reads during validation
    ets:new(?UTXO_CACHE, [set, public, named_table,
                           {read_concurrency, true},
                           {write_concurrency, true}]),
    %% Dirty/spent: write_concurrency since many processes update these
    ets:new(?UTXO_DIRTY, [set, public, named_table,
                           {write_concurrency, true}]),
    ets:new(?UTXO_SPENT, [set, public, named_table,
                           {write_concurrency, true}]),
    ets:new(?CHAIN_META, [set, public, named_table,
                           {read_concurrency, true}]),

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

    %% Start with large cache for IBD, shrink when caught up
    MaxCacheMB = ?IBD_MAX_CACHE_MB,
    logger:info("chainstate: initialized at height ~B (cache ~BMB)",
                [TipHeight, MaxCacheMB]),

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
                {ok, PI} -> PI#{height => TipHeight};
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
                        "shrinking cache to ~BMB",
                        [State#state.tip_height, ?DEFAULT_MAX_CACHE_MB]),
            %% Flush and shrink cache for normal operation
            State2 = do_flush(State),
            State2#state{
                ibd = false,
                max_cache_bytes = ?DEFAULT_MAX_CACHE_MB * 1024 * 1024
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

%% Decide whether to flush based on IBD interval or cache size.
maybe_flush(#state{ibd = true, blocks_since_flush = N} = State)
  when N >= ?IBD_FLUSH_INTERVAL ->
    do_flush(State);
maybe_flush(#state{ibd = false} = State) ->
    %% In normal operation, flush if cache exceeds max size
    CacheBytes = ets:info(?UTXO_CACHE, memory) * erlang:system_info(wordsize),
    case CacheBytes > State#state.max_cache_bytes of
        true -> do_flush(State);
        false -> State
    end;
maybe_flush(State) ->
    State.

%% Flush dirty entries to RocksDB in a single write batch.
do_flush(#state{tip_hash = undefined} = State) ->
    State;
do_flush(#state{tip_hash = TipHash, tip_height = TipHeight} = State) ->
    DirtyCount = ets:info(?UTXO_DIRTY, size),
    SpentCount = ets:info(?UTXO_SPENT, size),
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
                    %% Clear dirty/spent tracking
                    ets:delete_all_objects(?UTXO_DIRTY),
                    ets:delete_all_objects(?UTXO_SPENT),

                    %% Remove crash recovery marker
                    beamchain_db:put_meta(<<"HEAD_BLOCKS">>, <<>>),

                    logger:debug("chainstate: flushed ~B dirty, ~B spent "
                                 "at height ~B",
                                 [DirtyCount, SpentCount, TipHeight]),
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
%%% Internal: MTP computation
%%% ===================================================================

%% Compute the median of a list of timestamps.
compute_mtp([]) ->
    0;
compute_mtp(Timestamps) ->
    Sorted = lists:sort(Timestamps),
    lists:nth((length(Sorted) div 2) + 1, Sorted).
