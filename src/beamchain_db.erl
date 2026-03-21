-module(beamchain_db).
-behaviour(gen_server).

-include("beamchain.hrl").
-include_lib("kernel/include/file.hrl").

%% API
-export([start_link/0, stop/0]).

%% Block storage
-export([store_block/2, get_block/1, get_block_by_height/1, has_block/1]).

%% Flat file block storage
-export([write_block/2, read_block/1, get_block_file_info/0]).

%% UTXO set
-export([get_utxo/2, store_utxo/3, spend_utxo/2, has_utxo/2]).

%% Block index
-export([store_block_index/5, get_block_index/1, get_block_index_by_hash/1]).
-export([update_block_status/2, get_all_block_indexes/0]).

%% Block status constants (Bitcoin Core compatible)
%% These correspond to bits in the nStatus field of CBlockIndex.
-define(BLOCK_VALID_HEADER, 1).         %% Parsed, version ok, hash satisfies claimed PoW
-define(BLOCK_VALID_TREE, 2).           %% Valid header, parent is known
-define(BLOCK_VALID_TRANSACTIONS, 3).   %% All txs loaded and parseable
-define(BLOCK_VALID_CHAIN, 4).          %% All txs valid for this block and all parents
-define(BLOCK_VALID_SCRIPTS, 5).        %% All script/signature verification passed
-define(BLOCK_HAVE_DATA, 8).            %% Block data stored in blk*.dat
-define(BLOCK_HAVE_UNDO, 16).           %% Block undo data available
-define(BLOCK_FAILED_VALID, 32).        %% Block or ancestor failed validation
-define(BLOCK_FAILED_CHILD, 64).        %% Descends from a failed block (unused in Core)

-export_type([block_status/0]).
-type block_status() :: non_neg_integer().

%% Chain tip (fully validated blocks)
-export([get_chain_tip/0, set_chain_tip/2]).

%% Header tip (headers-only sync progress)
-export([get_header_tip/0, set_header_tip/2]).

%% Transaction index
-export([store_tx_index/4, get_tx_location/1]).

%% Undo data
-export([store_undo/2, get_undo/1, delete_undo/1]).

%% Batch writes
-export([write_batch/1]).

%% Generic metadata and stats
-export([get_meta/1, put_meta/2, get_db_stats/0]).

%% Pruning
-export([prune_block_files/0, is_block_pruned/1, trigger_pruning/1]).

%% Block height/time indexes
-export([get_hash_by_height/1, get_blocks_in_time_range/2]).
-export([store_block_stats/2, get_block_stats/1]).
-export([get_cumulative_tx_count/1, store_cumulative_tx_count/2]).
-export([index_block/3, unindex_block/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% Column family names
-define(CF_DEFAULT, "default").
-define(CF_BLOCKS, "blocks").
-define(CF_BLOCK_INDEX, "block_index").
-define(CF_CHAINSTATE, "chainstate").
-define(CF_TX_INDEX, "tx_index").
-define(CF_META, "meta").
-define(CF_UNDO, "undo").

%% Flat file constants
-define(MAX_BLOCKFILE_SIZE, 134217728).  %% 128 MB
-define(BLOCK_INDEX_ETS, beamchain_block_index).

%% Block index ETS tables
-define(HEIGHT_TO_HASH_ETS, beamchain_height_to_hash).
-define(TIME_INDEX_ETS, beamchain_time_index).
-define(BLOCK_STATS_ETS, beamchain_block_stats).

%% Pruning constants
-define(MIN_PRUNE_TARGET_MB, 550).  %% Minimum disk usage in MB
-define(REORG_SAFETY_BLOCKS, 288).  %% Keep at least 2 days of blocks

-record(state, {
    db_handle   :: rocksdb:db_handle() | undefined,
    cf_blocks   :: rocksdb:cf_handle() | undefined,
    cf_block_idx :: rocksdb:cf_handle() | undefined,
    cf_chainstate :: rocksdb:cf_handle() | undefined,
    cf_tx_index :: rocksdb:cf_handle() | undefined,
    cf_meta     :: rocksdb:cf_handle() | undefined,
    cf_undo     :: rocksdb:cf_handle() | undefined,
    data_dir    :: string(),
    %% Flat file state
    blocks_dir  :: string() | undefined,
    current_file :: non_neg_integer(),
    current_pos  :: non_neg_integer(),
    write_fd    :: file:fd() | undefined,
    network_magic :: binary(),
    %% Pruning state
    prune_target :: non_neg_integer(),  %% Target disk usage in bytes (0 = disabled)
    pruned_files :: sets:set(non_neg_integer()),  %% Set of pruned file numbers
    file_info :: #{non_neg_integer() => #{size => non_neg_integer(),
                                           height_first => non_neg_integer(),
                                           height_last => non_neg_integer()}}
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

stop() ->
    gen_server:stop(?SERVER).

%% @doc Store a block with its height
-spec store_block(#block{}, non_neg_integer()) -> ok | {error, term()}.
store_block(Block, Height) ->
    gen_server:call(?SERVER, {store_block, Block, Height}, 30000).

%% @doc Get a block by hash
-spec get_block(binary()) -> {ok, #block{}} | not_found.
get_block(Hash) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {get_block, Hash}).

%% @doc Get a block by height
-spec get_block_by_height(non_neg_integer()) -> {ok, #block{}} | not_found.
get_block_by_height(Height) ->
    gen_server:call(?SERVER, {get_block_by_height, Height}).

%% @doc Check if a block exists
-spec has_block(binary()) -> boolean().
has_block(Hash) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {has_block, Hash}).

%% @doc Get a UTXO by outpoint
-spec get_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
get_utxo(Txid, Vout) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {get_utxo, Txid, Vout}, infinity).

%% @doc Store a UTXO
-spec store_utxo(binary(), non_neg_integer(), #utxo{}) -> ok.
store_utxo(Txid, Vout, Utxo) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {store_utxo, Txid, Vout, Utxo}, infinity).

%% @doc Spend (remove) a UTXO, returns the spent UTXO for undo data
-spec spend_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
spend_utxo(Txid, Vout) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {spend_utxo, Txid, Vout}, infinity).

%% @doc Check if a UTXO exists
-spec has_utxo(binary(), non_neg_integer()) -> boolean().
has_utxo(Txid, Vout) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {has_utxo, Txid, Vout}, infinity).

%% @doc Store block index entry (header metadata for a given height)
-spec store_block_index(non_neg_integer(), binary(), #block_header{},
                        binary(), integer()) -> ok.
store_block_index(Height, Hash, Header, Chainwork, Status) ->
    gen_server:call(?SERVER, {store_block_index, Height, Hash, Header,
                              Chainwork, Status}, 30000).

%% @doc Get block index by height
-spec get_block_index(non_neg_integer()) ->
    {ok, #{hash => binary(), header => #block_header{},
           chainwork => binary(), status => integer()}} | not_found.
get_block_index(Height) ->
    gen_server:call(?SERVER, {get_block_index, Height}, 30000).

%% @doc Get block index by hash (reverse lookup)
-spec get_block_index_by_hash(binary()) ->
    {ok, #{height => integer(), header => #block_header{},
           chainwork => binary(), status => integer()}} | not_found.
get_block_index_by_hash(Hash) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {get_block_index_by_hash, Hash}, 30000).

%% @doc Update block index status (for invalidateblock/reconsiderblock)
-spec update_block_status(binary(), non_neg_integer()) -> ok | {error, term()}.
update_block_status(Hash, NewStatus) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {update_block_status, Hash, NewStatus}, 30000).

%% @doc Get all block index entries (for finding descendants)
-spec get_all_block_indexes() -> {ok, [map()]} | {error, term()}.
get_all_block_indexes() ->
    gen_server:call(?SERVER, get_all_block_indexes, 60000).

%% @doc Get the current chain tip
-spec get_chain_tip() -> {ok, #{hash => binary(), height => integer()}} | not_found.
get_chain_tip() ->
    gen_server:call(?SERVER, get_chain_tip).

%% @doc Set the chain tip
-spec set_chain_tip(binary(), non_neg_integer()) -> ok.
set_chain_tip(Hash, Height) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {set_chain_tip, Hash, Height}, 30000).

%% @doc Get the current header tip (headers-only sync progress)
-spec get_header_tip() -> {ok, #{hash => binary(), height => integer()}} | not_found.
get_header_tip() ->
    gen_server:call(?SERVER, get_header_tip).

%% @doc Set the header tip
-spec set_header_tip(binary(), non_neg_integer()) -> ok.
set_header_tip(Hash, Height) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {set_header_tip, Hash, Height}).

%% @doc Store transaction index entry
-spec store_tx_index(binary(), binary(), non_neg_integer(),
                     non_neg_integer()) -> ok.
store_tx_index(Txid, BlockHash, Height, Position) ->
    gen_server:call(?SERVER, {store_tx_index, Txid, BlockHash, Height, Position}, 30000).

%% @doc Get transaction location (which block, height, position)
-spec get_tx_location(binary()) ->
    {ok, #{block_hash => binary(), height => integer(),
           position => integer()}} | not_found.
get_tx_location(Txid) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {get_tx_location, Txid}).

%% @doc Store undo data for a block (spent UTXOs, for reorgs)
-spec store_undo(binary(), binary()) -> ok.
store_undo(BlockHash, UndoData) when byte_size(BlockHash) =:= 32 ->
    gen_server:call(?SERVER, {store_undo, BlockHash, UndoData}).

%% @doc Get undo data for a block
-spec get_undo(binary()) -> {ok, binary()} | not_found.
get_undo(BlockHash) when byte_size(BlockHash) =:= 32 ->
    gen_server:call(?SERVER, {get_undo, BlockHash}).

%% @doc Delete undo data for a block (after successful reorg)
-spec delete_undo(binary()) -> ok.
delete_undo(BlockHash) when byte_size(BlockHash) =:= 32 ->
    gen_server:call(?SERVER, {delete_undo, BlockHash}).

%% @doc Atomic batch write across column families
%% Ops = [{put, CF, Key, Value} | {delete, CF, Key}]
%% CF is one of: blocks, block_index, chainstate, tx_index, meta, undo
-spec write_batch([tuple()]) -> ok | {error, term()}.
write_batch(Ops) ->
    gen_server:call(?SERVER, {write_batch, Ops}, infinity).

%% @doc Get a value from the meta column family
-spec get_meta(binary()) -> {ok, binary()} | not_found.
get_meta(Key) when is_binary(Key) ->
    gen_server:call(?SERVER, {get_meta, Key}, 30000).

%% @doc Put a value in the meta column family
-spec put_meta(binary(), binary()) -> ok.
put_meta(Key, Value) when is_binary(Key), is_binary(Value) ->
    gen_server:call(?SERVER, {put_meta, Key, Value}, 60000).

%% @doc Get database statistics
-spec get_db_stats() -> map().
get_db_stats() ->
    gen_server:call(?SERVER, get_db_stats).

%% @doc Write a block to flat file storage.
%% Returns {ok, {FileNum, Offset, Size}} on success.
%% The block is prefixed with network magic (4 bytes) and size (4 bytes LE).
-spec write_block(#block{}, non_neg_integer()) ->
    {ok, {non_neg_integer(), non_neg_integer(), non_neg_integer()}} | {error, term()}.
write_block(Block, Height) ->
    gen_server:call(?SERVER, {write_block_flat, Block, Height}, 30000).

%% @doc Read a block from flat file storage by hash.
%% Looks up the block index to find file/offset, then reads from disk.
-spec read_block(binary()) -> {ok, #block{}} | not_found | {error, term()}.
read_block(Hash) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {read_block_flat, Hash}).

%% @doc Get current flat file info (for debugging/monitoring).
-spec get_block_file_info() -> map().
get_block_file_info() ->
    gen_server:call(?SERVER, get_block_file_info).

%% @doc Prune old block files to reduce disk usage.
%% Deletes the oldest blk*.dat and rev*.dat files until disk usage
%% is below the prune target, while keeping at least 288 blocks.
%% Returns the number of files pruned.
-spec prune_block_files() -> {ok, non_neg_integer()} | {error, term()}.
prune_block_files() ->
    gen_server:call(?SERVER, prune_block_files, 60000).

%% @doc Check if a block has been pruned.
%% Returns true if the block data has been deleted.
-spec is_block_pruned(binary()) -> boolean().
is_block_pruned(Hash) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {is_block_pruned, Hash}).

%% @doc Trigger pruning check after connecting a block at given height.
%% Called by chainstate after block connection if pruning is enabled.
-spec trigger_pruning(non_neg_integer()) -> ok.
trigger_pruning(Height) ->
    gen_server:cast(?SERVER, {trigger_pruning, Height}).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    DataDir = beamchain_config:datadir(),
    DbPath = filename:join(DataDir, "chaindata"),
    BlocksDir = filename:join(DataDir, "blocks"),
    ok = filelib:ensure_dir(filename:join(DbPath, "dummy")),
    ok = filelib:ensure_dir(filename:join(BlocksDir, "dummy")),

    DbOpts = [
        {create_if_missing, true},
        {create_missing_column_families, true},
        {max_open_files, 256},
        {write_buffer_size, 64 * 1024 * 1024},
        {max_write_buffer_number, 3},
        {target_file_size_base, 64 * 1024 * 1024},
        {max_bytes_for_level_base, 256 * 1024 * 1024}
    ],
    CFOpts = [],
    CFDescriptors = [
        {?CF_DEFAULT, CFOpts},
        {?CF_BLOCKS, CFOpts},
        {?CF_BLOCK_INDEX, CFOpts},
        {?CF_CHAINSTATE, CFOpts},
        {?CF_TX_INDEX, CFOpts},
        {?CF_META, CFOpts},
        {?CF_UNDO, CFOpts}
    ],
    case rocksdb:open(DbPath, DbOpts, CFDescriptors) of
        {ok, DbHandle, [_DefaultCF, BlocksCF, BlockIdxCF,
                         ChainstateCF, TxIndexCF, MetaCF, UndoCF]} ->
            %% Initialize flat file block index ETS table
            case ets:info(?BLOCK_INDEX_ETS) of
                undefined ->
                    ets:new(?BLOCK_INDEX_ETS, [named_table, set, public,
                                                {read_concurrency, true}]);
                _ -> ok
            end,

            %% Initialize height-to-hash ETS table
            case ets:info(?HEIGHT_TO_HASH_ETS) of
                undefined ->
                    ets:new(?HEIGHT_TO_HASH_ETS, [named_table, set, public,
                                                   {read_concurrency, true}]);
                _ -> ok
            end,

            %% Initialize time index ETS table (ordered_set for range queries)
            case ets:info(?TIME_INDEX_ETS) of
                undefined ->
                    ets:new(?TIME_INDEX_ETS, [named_table, ordered_set, public,
                                               {read_concurrency, true}]);
                _ -> ok
            end,

            %% Initialize block stats ETS table
            case ets:info(?BLOCK_STATS_ETS) of
                undefined ->
                    ets:new(?BLOCK_STATS_ETS, [named_table, set, public,
                                                {read_concurrency, true}]);
                _ -> ok
            end,

            %% Load block index from disk if it exists
            BlockIndexPath = filename:join(BlocksDir, "block_index.ets"),
            case filelib:is_regular(BlockIndexPath) of
                true ->
                    case ets:file2tab(BlockIndexPath) of
                        {ok, _} -> ok;
                        {error, Reason} ->
                            logger:warning("Failed to load block index: ~p", [Reason])
                    end;
                false -> ok
            end,

            %% Determine current file number and position
            {CurrentFile, CurrentPos} = find_current_blockfile(BlocksDir),

            %% Get network magic
            NetworkMagic = beamchain_config:magic(),

            %% Get pruning config (convert MB to bytes)
            PruneTargetMB = beamchain_config:prune_target(),
            PruneTargetBytes = PruneTargetMB * 1024 * 1024,

            %% Load pruned files set from meta if it exists
            PrunedFiles = load_pruned_files(DbHandle, MetaCF),

            %% Build file info map
            FileInfo = scan_block_files(BlocksDir, CurrentFile),

            State = #state{
                db_handle = DbHandle,
                cf_blocks = BlocksCF,
                cf_block_idx = BlockIdxCF,
                cf_chainstate = ChainstateCF,
                cf_tx_index = TxIndexCF,
                cf_meta = MetaCF,
                cf_undo = UndoCF,
                data_dir = DbPath,
                blocks_dir = BlocksDir,
                current_file = CurrentFile,
                current_pos = CurrentPos,
                write_fd = undefined,
                network_magic = NetworkMagic,
                prune_target = PruneTargetBytes,
                pruned_files = PrunedFiles,
                file_info = FileInfo
            },
            logger:info("beamchain_db: opened rocksdb at ~s, blocks at ~s (file ~p, pos ~p)",
                        [DbPath, BlocksDir, CurrentFile, CurrentPos]),
            {ok, State};
        {error, Reason} ->
            logger:error("beamchain_db: failed to open rocksdb: ~p", [Reason]),
            {stop, {db_open_failed, Reason}}
    end.

%% Block storage
handle_call({store_block, Block, _Height}, _From,
            #state{db_handle = Db, cf_blocks = CF} = State) ->
    Hash = block_hash(Block),
    BlockBin = beamchain_serialize:encode_block(Block),
    %% Store block data keyed by hash only.
    %% Height→hash mapping is handled by store_block_index.
    Result = rocksdb:put(Db, CF, Hash, BlockBin, []),
    {reply, Result, State};

handle_call({get_block, Hash}, _From,
            #state{db_handle = Db, cf_blocks = CF} = State) ->
    Result = case rocksdb:get(Db, CF, Hash, []) of
        {ok, BlockBin} ->
            {Block, <<>>} = beamchain_serialize:decode_block(BlockBin),
            {ok, Block};
        not_found ->
            not_found;
        {error, _} = Err ->
            Err
    end,
    {reply, Result, State};

handle_call({get_block_by_height, Height}, _From,
            #state{db_handle = Db, cf_blocks = BlocksCF,
                   cf_block_idx = IdxCF} = State) ->
    HeightKey = encode_height(Height),
    Result = case rocksdb:get(Db, IdxCF, HeightKey, []) of
        {ok, Bin} ->
            %% Block index entries contain: hash(32) | header(80) | ...
            %% Extract the hash from the first 32 bytes
            <<Hash:32/binary, _/binary>> = Bin,
            case rocksdb:get(Db, BlocksCF, Hash, []) of
                {ok, BlockBin} ->
                    {Block, <<>>} = beamchain_serialize:decode_block(BlockBin),
                    {ok, Block};
                not_found ->
                    not_found
            end;
        not_found ->
            not_found
    end,
    {reply, Result, State};

handle_call({has_block, Hash}, _From,
            #state{db_handle = Db, cf_blocks = CF} = State) ->
    Result = case rocksdb:get(Db, CF, Hash, []) of
        {ok, _} -> true;
        not_found -> false
    end,
    {reply, Result, State};

%% UTXO operations
handle_call({store_utxo, Txid, Vout, Utxo}, _From,
            #state{db_handle = Db, cf_chainstate = CF} = State) ->
    Key = encode_outpoint(Txid, Vout),
    Value = encode_utxo(Utxo),
    Result = rocksdb:put(Db, CF, Key, Value, []),
    {reply, Result, State};

handle_call({get_utxo, Txid, Vout}, _From,
            #state{db_handle = Db, cf_chainstate = CF} = State) ->
    Key = encode_outpoint(Txid, Vout),
    Result = case rocksdb:get(Db, CF, Key, []) of
        {ok, Bin} -> {ok, decode_utxo(Bin)};
        not_found -> not_found
    end,
    {reply, Result, State};

handle_call({spend_utxo, Txid, Vout}, _From,
            #state{db_handle = Db, cf_chainstate = CF} = State) ->
    Key = encode_outpoint(Txid, Vout),
    Result = case rocksdb:get(Db, CF, Key, []) of
        {ok, Bin} ->
            Utxo = decode_utxo(Bin),
            rocksdb:delete(Db, CF, Key, []),
            {ok, Utxo};
        not_found ->
            not_found
    end,
    {reply, Result, State};

handle_call({has_utxo, Txid, Vout}, _From,
            #state{db_handle = Db, cf_chainstate = CF} = State) ->
    Key = encode_outpoint(Txid, Vout),
    Result = case rocksdb:get(Db, CF, Key, []) of
        {ok, _} -> true;
        not_found -> false
    end,
    {reply, Result, State};

%% Block index operations
handle_call({store_block_index, Height, Hash, Header, Chainwork, Status},
            _From, #state{db_handle = Db, cf_block_idx = CF,
                          cf_meta = MetaCF} = State) ->
    HeightKey = encode_height(Height),
    Value = encode_block_index_entry(Hash, Header, Chainwork, Status),
    rocksdb:put(Db, CF, HeightKey, Value, []),
    %% Reverse index: hash -> height for lookup by hash
    HashKey = <<"blkidx:", Hash/binary>>,
    rocksdb:put(Db, MetaCF, HashKey, HeightKey, []),
    {reply, ok, State};

handle_call({get_block_index, Height}, _From,
            #state{db_handle = Db, cf_block_idx = CF} = State) ->
    HeightKey = encode_height(Height),
    Result = case rocksdb:get(Db, CF, HeightKey, []) of
        {ok, Bin} ->
            Entry = decode_block_index_entry(Bin),
            {ok, Entry#{height => Height}};
        not_found ->
            not_found
    end,
    {reply, Result, State};

handle_call({get_block_index_by_hash, Hash}, _From,
            #state{db_handle = Db, cf_block_idx = CF,
                   cf_meta = MetaCF} = State) ->
    HashKey = <<"blkidx:", Hash/binary>>,
    Result = case rocksdb:get(Db, MetaCF, HashKey, []) of
        {ok, HeightKey} ->
            <<Height:64/big>> = HeightKey,
            case rocksdb:get(Db, CF, HeightKey, []) of
                {ok, Bin} ->
                    Entry = decode_block_index_entry(Bin),
                    {ok, Entry#{height => Height}};
                not_found ->
                    not_found
            end;
        not_found ->
            not_found
    end,
    {reply, Result, State};

%% Chain tip metadata
handle_call(get_chain_tip, _From,
            #state{db_handle = Db, cf_meta = CF} = State) ->
    Result = case rocksdb:get(Db, CF, <<"chain_tip">>, []) of
        {ok, <<Hash:32/binary, Height:64/big>>} ->
            {ok, #{hash => Hash, height => Height}};
        not_found ->
            not_found
    end,
    {reply, Result, State};

handle_call({set_chain_tip, Hash, Height}, _From,
            #state{db_handle = Db, cf_meta = CF} = State) ->
    Value = <<Hash:32/binary, Height:64/big>>,
    Result = rocksdb:put(Db, CF, <<"chain_tip">>, Value, []),
    {reply, Result, State};

%% Header tip metadata
handle_call(get_header_tip, _From,
            #state{db_handle = Db, cf_meta = CF} = State) ->
    Result = case rocksdb:get(Db, CF, <<"header_tip">>, []) of
        {ok, <<Hash:32/binary, Height:64/big>>} ->
            {ok, #{hash => Hash, height => Height}};
        not_found ->
            not_found
    end,
    {reply, Result, State};

handle_call({set_header_tip, Hash, Height}, _From,
            #state{db_handle = Db, cf_meta = CF} = State) ->
    Value = <<Hash:32/binary, Height:64/big>>,
    Result = rocksdb:put(Db, CF, <<"header_tip">>, Value, []),
    {reply, Result, State};

%% Transaction index
handle_call({store_tx_index, Txid, BlockHash, Height, Position}, _From,
            #state{db_handle = Db, cf_tx_index = CF} = State) ->
    Value = <<BlockHash:32/binary, Height:64/big, Position:32/big>>,
    Result = rocksdb:put(Db, CF, Txid, Value, []),
    {reply, Result, State};

handle_call({get_tx_location, Txid}, _From,
            #state{db_handle = Db, cf_tx_index = CF} = State) ->
    Result = case rocksdb:get(Db, CF, Txid, []) of
        {ok, <<BlockHash:32/binary, Height:64/big, Position:32/big>>} ->
            {ok, #{block_hash => BlockHash, height => Height,
                   position => Position}};
        not_found ->
            not_found
    end,
    {reply, Result, State};

%% Undo data
handle_call({store_undo, BlockHash, UndoData}, _From,
            #state{db_handle = Db, cf_undo = CF} = State) ->
    Result = rocksdb:put(Db, CF, BlockHash, UndoData, []),
    {reply, Result, State};

handle_call({get_undo, BlockHash}, _From,
            #state{db_handle = Db, cf_undo = CF} = State) ->
    Result = case rocksdb:get(Db, CF, BlockHash, []) of
        {ok, UndoData} -> {ok, UndoData};
        not_found -> not_found
    end,
    {reply, Result, State};

handle_call({delete_undo, BlockHash}, _From,
            #state{db_handle = Db, cf_undo = CF} = State) ->
    Result = rocksdb:delete(Db, CF, BlockHash, []),
    {reply, Result, State};

%% Batch writes
handle_call({write_batch, Ops}, _From, State) ->
    WriteActions = lists:map(fun(Op) -> resolve_batch_op(Op, State) end, Ops),
    Result = rocksdb:write(State#state.db_handle, WriteActions, []),
    {reply, Result, State};

%% Generic metadata
handle_call({get_meta, Key}, _From,
            #state{db_handle = Db, cf_meta = CF} = State) ->
    Result = case rocksdb:get(Db, CF, Key, []) of
        {ok, Value} -> {ok, Value};
        not_found -> not_found
    end,
    {reply, Result, State};

handle_call({put_meta, Key, Value}, _From,
            #state{db_handle = Db, cf_meta = CF} = State) ->
    Result = rocksdb:put(Db, CF, Key, Value, []),
    {reply, Result, State};

%% Database stats
handle_call(get_db_stats, _From,
            #state{db_handle = Db, data_dir = DataDir} = State) ->
    Stats = #{
        data_dir => DataDir,
        rocksdb_stats => case rocksdb:stats(Db) of
            {ok, S} -> S;
            _ -> <<"unavailable">>
        end
    },
    {reply, Stats, State};

%% Flat file block storage
handle_call({write_block_flat, Block, _Height}, _From, State) ->
    case do_write_block_flat(Block, State) of
        {ok, Location, NewState} ->
            {reply, {ok, Location}, NewState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({read_block_flat, Hash}, _From, State) ->
    %% Check if block is pruned first
    case check_block_pruned(Hash, State) of
        true ->
            {reply, {error, block_pruned}, State};
        false ->
            Result = do_read_block_flat(Hash, State),
            {reply, Result, State}
    end;

handle_call(get_block_file_info, _From,
            #state{blocks_dir = BlocksDir, current_file = CurrentFile,
                   current_pos = CurrentPos, prune_target = PruneTarget,
                   pruned_files = PrunedFiles, file_info = FileInfo} = State) ->
    Info = #{
        blocks_dir => BlocksDir,
        current_file => CurrentFile,
        current_pos => CurrentPos,
        max_file_size => ?MAX_BLOCKFILE_SIZE,
        index_size => ets:info(?BLOCK_INDEX_ETS, size),
        prune_target_mb => PruneTarget div (1024 * 1024),
        pruned_file_count => sets:size(PrunedFiles),
        tracked_files => maps:size(FileInfo)
    },
    {reply, Info, State};

%% Pruning operations
handle_call(prune_block_files, _From, State) ->
    case do_prune_files(State) of
        {ok, Count, NewState} ->
            {reply, {ok, Count}, NewState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({is_block_pruned, Hash}, _From, State) ->
    Result = check_block_pruned(Hash, State),
    {reply, Result, State};

%% Update block index status (for invalidateblock/reconsiderblock)
handle_call({update_block_status, Hash, NewStatus}, _From,
            #state{db_handle = Db, cf_block_idx = CF, cf_meta = MetaCF} = State) ->
    %% First look up the height from the reverse index
    HashKey = <<"blkidx:", Hash/binary>>,
    Result = case rocksdb:get(Db, MetaCF, HashKey, []) of
        {ok, HeightKey} ->
            %% Get the current entry
            case rocksdb:get(Db, CF, HeightKey, []) of
                {ok, Bin} ->
                    Entry = decode_block_index_entry(Bin),
                    %% Re-encode with new status
                    #{hash := H, header := Header, chainwork := Chainwork} = Entry,
                    NewValue = encode_block_index_entry(H, Header, Chainwork, NewStatus),
                    case rocksdb:put(Db, CF, HeightKey, NewValue, []) of
                        ok -> ok;
                        Error -> Error
                    end;
                not_found ->
                    {error, block_index_not_found}
            end;
        not_found ->
            {error, block_not_found}
    end,
    {reply, Result, State};

%% Get all block indexes (for finding descendants during invalidation)
handle_call(get_all_block_indexes, _From,
            #state{db_handle = Db, cf_block_idx = CF} = State) ->
    %% Iterate over all block index entries
    Result = case rocksdb:iterator(Db, CF, []) of
        {ok, Iter} ->
            Entries = collect_block_indexes(rocksdb:iterator_move(Iter, first), Iter, []),
            rocksdb:iterator_close(Iter),
            {ok, Entries};
        Error ->
            Error
    end,
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast({trigger_pruning, Height}, #state{prune_target = PruneTarget} = State)
  when PruneTarget > 0 ->
    %% Only prune if we're past the reorg safety window
    case Height > ?REORG_SAFETY_BLOCKS of
        true ->
            case do_prune_files(State) of
                {ok, Count, NewState} when Count > 0 ->
                    logger:info("beamchain_db: pruned ~p block files after height ~p",
                                [Count, Height]),
                    {noreply, NewState};
                {ok, 0, _} ->
                    {noreply, State};
                {error, _Reason} ->
                    {noreply, State}
            end;
        false ->
            {noreply, State}
    end;

handle_cast({trigger_pruning, _Height}, State) ->
    %% Pruning disabled
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{db_handle = undefined}) ->
    ok;
terminate(_Reason, #state{db_handle = DbHandle, write_fd = WriteFd,
                          blocks_dir = BlocksDir}) ->
    logger:info("beamchain_db: closing rocksdb"),
    %% Close write file descriptor
    case WriteFd of
        undefined -> ok;
        Fd -> file:close(Fd)
    end,
    %% Persist block index to disk
    case BlocksDir of
        undefined -> ok;
        _ -> persist_block_index(BlocksDir)
    end,
    rocksdb:close(DbHandle),
    ok.

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

%% @doc Encode height as 8-byte big-endian for sorted storage
encode_height(Height) ->
    <<Height:64/big>>.

%% @doc Compute block hash
block_hash(#block{hash = Hash}) when is_binary(Hash), byte_size(Hash) =:= 32 ->
    Hash;
block_hash(#block{header = Header}) ->
    beamchain_serialize:block_hash(Header).

%% @doc Encode outpoint as key: txid(32) ++ vout(4 big-endian)
encode_outpoint(Txid, Vout) ->
    <<Txid:32/binary, Vout:32/big>>.

%% @doc Encode a UTXO record to binary for storage
%% Format: value(8 LE) | height(4 LE) | is_coinbase(1) | script_pubkey(rest)
encode_utxo(#utxo{value = Value, script_pubkey = Script,
                  is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    <<Value:64/little, Height:32/little, CoinbaseFlag:8, Script/binary>>.

%% @doc Decode a UTXO from stored binary
decode_utxo(<<Value:64/little, Height:32/little, CoinbaseFlag:8,
              Script/binary>>) ->
    #utxo{
        value = Value,
        script_pubkey = Script,
        is_coinbase = CoinbaseFlag =:= 1,
        height = Height
    }.

%% @doc Encode a block index entry for storage
%% Format: hash(32) | header(80) | chainwork_len(2) | chainwork(var) | status(4)
encode_block_index_entry(Hash, Header, Chainwork, Status) ->
    HeaderBin = beamchain_serialize:encode_block_header(Header),
    CWLen = byte_size(Chainwork),
    <<Hash:32/binary, HeaderBin:80/binary,
      CWLen:16/big, Chainwork:CWLen/binary,
      Status:32/little>>.

%% @doc Decode a block index entry
decode_block_index_entry(<<Hash:32/binary, HeaderBin:80/binary,
                           CWLen:16/big, Rest/binary>>) ->
    <<Chainwork:CWLen/binary, Status:32/little>> = Rest,
    {Header, <<>>} = beamchain_serialize:decode_block_header(HeaderBin),
    #{hash => Hash, header => Header,
      chainwork => Chainwork, status => Status}.

%% @doc Collect all block index entries from iterator
collect_block_indexes({error, _}, _Iter, Acc) ->
    lists:reverse(Acc);
collect_block_indexes({ok, Key, Value}, Iter, Acc) ->
    <<Height:64/big>> = Key,
    Entry = decode_block_index_entry(Value),
    collect_block_indexes(rocksdb:iterator_move(Iter, next), Iter,
                          [Entry#{height => Height} | Acc]).

%% @doc Resolve a batch operation's CF name to a CF handle
resolve_batch_op({put, CF, Key, Value}, State) ->
    {put, cf_handle(CF, State), Key, Value};
resolve_batch_op({delete, CF, Key}, State) ->
    {delete, cf_handle(CF, State), Key}.

%% @doc Map column family name atom to handle
cf_handle(blocks, #state{cf_blocks = H}) -> H;
cf_handle(block_index, #state{cf_block_idx = H}) -> H;
cf_handle(chainstate, #state{cf_chainstate = H}) -> H;
cf_handle(tx_index, #state{cf_tx_index = H}) -> H;
cf_handle(meta, #state{cf_meta = H}) -> H;
cf_handle(undo, #state{cf_undo = H}) -> H.

%%% ===================================================================
%%% Flat file block storage helpers
%%% ===================================================================

%% @doc Find current blockfile number and write position.
%% Scans for existing blk*.dat files and returns the highest file
%% number and its current size. If no files exist, returns {0, 0}.
-spec find_current_blockfile(string()) ->
    {non_neg_integer(), non_neg_integer()}.
find_current_blockfile(BlocksDir) ->
    %% Find all blk*.dat files
    Pattern = filename:join(BlocksDir, "blk*.dat"),
    Files = filelib:wildcard(Pattern),
    case Files of
        [] ->
            {0, 0};
        _ ->
            %% Extract file numbers and find max
            FileNums = lists:filtermap(fun(Path) ->
                Basename = filename:basename(Path, ".dat"),
                case Basename of
                    "blk" ++ NumStr ->
                        case catch list_to_integer(NumStr) of
                            N when is_integer(N) -> {true, N};
                            _ -> false
                        end;
                    _ -> false
                end
            end, Files),
            case FileNums of
                [] -> {0, 0};
                _ ->
                    MaxFile = lists:max(FileNums),
                    FilePath = blockfile_path(BlocksDir, MaxFile),
                    case file:read_file_info(FilePath) of
                        {ok, #file_info{size = Size}} -> {MaxFile, Size};
                        _ -> {MaxFile, 0}
                    end
            end
    end.

%% @doc Generate path to a block file.
-spec blockfile_path(string(), non_neg_integer()) -> string().
blockfile_path(BlocksDir, FileNum) ->
    Filename = io_lib:format("blk~5..0B.dat", [FileNum]),
    filename:join(BlocksDir, lists:flatten(Filename)).

%% @doc Write a block to flat file storage.
%% Format: <<Magic:4/binary, Size:32/little, BlockData/binary>>
-spec do_write_block_flat(#block{}, #state{}) ->
    {ok, {non_neg_integer(), non_neg_integer(), non_neg_integer()}, #state{}} |
    {error, term()}.
do_write_block_flat(Block, #state{blocks_dir = BlocksDir,
                                   current_file = CurrentFile,
                                   current_pos = CurrentPos,
                                   write_fd = WriteFd0,
                                   network_magic = Magic} = State) ->
    Hash = block_hash(Block),
    BlockData = beamchain_serialize:encode_block(Block),
    BlockSize = byte_size(BlockData),
    %% Header: 4-byte magic + 4-byte size (little-endian)
    HeaderSize = 8,
    TotalSize = HeaderSize + BlockSize,

    %% Check if we need to start a new file
    {FileNum, WritePos, WriteFd1, State1} =
        case CurrentPos + TotalSize > ?MAX_BLOCKFILE_SIZE of
            true ->
                %% Close current file, open new one
                case WriteFd0 of
                    undefined -> ok;
                    OldFd -> file:close(OldFd)
                end,
                NewFileNum = CurrentFile + 1,
                {NewFileNum, 0, undefined,
                 State#state{current_file = NewFileNum, current_pos = 0,
                             write_fd = undefined}};
            false ->
                {CurrentFile, CurrentPos, WriteFd0, State}
        end,

    %% Ensure we have an open file descriptor
    case WriteFd1 of
        undefined ->
            FilePath = blockfile_path(BlocksDir, FileNum),
            case file:open(FilePath, [raw, binary, append]) of
                {ok, NewFd} ->
                    write_block_data(NewFd, Magic, BlockSize, BlockData, Hash,
                                     FileNum, WritePos, State1);
                {error, Reason} ->
                    {error, {open_failed, Reason}}
            end;
        ExistingFd ->
            write_block_data(ExistingFd, Magic, BlockSize, BlockData, Hash,
                             FileNum, WritePos, State1)
    end.

%% @doc Helper to actually write block data and update state.
-spec write_block_data(file:fd(), binary(), non_neg_integer(), binary(),
                        binary(), non_neg_integer(), non_neg_integer(),
                        #state{}) ->
    {ok, {non_neg_integer(), non_neg_integer(), non_neg_integer()}, #state{}} |
    {error, term()}.
write_block_data(Fd, Magic, BlockSize, BlockData, Hash, FileNum, WritePos, State) ->
    %% Write header: magic + size (little-endian)
    Header = <<Magic:4/binary, BlockSize:32/little>>,
    case file:write(Fd, Header) of
        ok ->
            case file:write(Fd, BlockData) of
                ok ->
                    TotalSize = 8 + BlockSize,
                    %% Store in ETS index: Hash -> {FileNum, Offset, Size}
                    %% Offset points to start of block data (after header)
                    DataOffset = WritePos + 8,
                    ets:insert(?BLOCK_INDEX_ETS, {Hash, {FileNum, DataOffset, BlockSize}}),
                    NewPos = WritePos + TotalSize,
                    Location = {FileNum, DataOffset, BlockSize},
                    {ok, Location, State#state{current_pos = NewPos, write_fd = Fd}};
                {error, Reason} ->
                    {error, {write_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {write_header_failed, Reason}}
    end.

%% @doc Read a block from flat file storage by hash.
-spec do_read_block_flat(binary(), #state{}) ->
    {ok, #block{}} | not_found | {error, term()}.
do_read_block_flat(Hash, #state{blocks_dir = BlocksDir, network_magic = Magic}) ->
    case ets:lookup(?BLOCK_INDEX_ETS, Hash) of
        [{Hash, {FileNum, Offset, Size}}] ->
            FilePath = blockfile_path(BlocksDir, FileNum),
            case file:open(FilePath, [raw, binary, read]) of
                {ok, Fd} ->
                    Result = try
                        %% Read block data from offset
                        case file:pread(Fd, Offset, Size) of
                            {ok, BlockData} when byte_size(BlockData) =:= Size ->
                                %% Verify magic by reading header (offset - 8)
                                case file:pread(Fd, Offset - 8, 8) of
                                    {ok, <<ReadMagic:4/binary, ReadSize:32/little>>} ->
                                        case ReadMagic =:= Magic andalso ReadSize =:= Size of
                                            true ->
                                                {Block, <<>>} = beamchain_serialize:decode_block(BlockData),
                                                {ok, Block};
                                            false ->
                                                {error, {magic_mismatch, ReadMagic, Magic}}
                                        end;
                                    {ok, _} ->
                                        {error, invalid_header};
                                    eof ->
                                        {error, unexpected_eof};
                                    {error, Reason} ->
                                        {error, {pread_header_failed, Reason}}
                                end;
                            {ok, _} ->
                                {error, size_mismatch};
                            eof ->
                                {error, unexpected_eof};
                            {error, Reason} ->
                                {error, {pread_failed, Reason}}
                        end
                    catch
                        _:Err ->
                            {error, {decode_failed, Err}}
                    after
                        file:close(Fd)
                    end,
                    Result;
                {error, Reason} ->
                    {error, {open_failed, Reason}}
            end;
        [] ->
            not_found
    end.

%% @doc Persist block index ETS table to disk.
-spec persist_block_index(string()) -> ok | {error, term()}.
persist_block_index(BlocksDir) ->
    IndexPath = filename:join(BlocksDir, "block_index.ets"),
    case ets:tab2file(?BLOCK_INDEX_ETS, IndexPath) of
        ok ->
            logger:info("beamchain_db: persisted block index to ~s", [IndexPath]),
            ok;
        {error, Reason} ->
            logger:error("beamchain_db: failed to persist block index: ~p", [Reason]),
            {error, Reason}
    end.

%%% ===================================================================
%%% Pruning helpers
%%% ===================================================================

%% @doc Generate path to an undo (rev) file.
-spec revfile_path(string(), non_neg_integer()) -> string().
revfile_path(BlocksDir, FileNum) ->
    Filename = io_lib:format("rev~5..0B.dat", [FileNum]),
    filename:join(BlocksDir, lists:flatten(Filename)).

%% @doc Load the set of pruned file numbers from metadata.
-spec load_pruned_files(rocksdb:db_handle(), rocksdb:cf_handle()) ->
    sets:set(non_neg_integer()).
load_pruned_files(Db, MetaCF) ->
    case rocksdb:get(Db, MetaCF, <<"pruned_files">>, []) of
        {ok, Bin} ->
            try binary_to_term(Bin)
            catch _:_ -> sets:new()
            end;
        not_found ->
            sets:new()
    end.

%% @doc Save the set of pruned file numbers to metadata.
-spec save_pruned_files(rocksdb:db_handle(), rocksdb:cf_handle(),
                        sets:set(non_neg_integer())) -> ok.
save_pruned_files(Db, MetaCF, PrunedFiles) ->
    Bin = term_to_binary(PrunedFiles),
    rocksdb:put(Db, MetaCF, <<"pruned_files">>, Bin, []).

%% @doc Scan block files to build file info map.
-spec scan_block_files(string(), non_neg_integer()) ->
    #{non_neg_integer() => #{size => non_neg_integer()}}.
scan_block_files(BlocksDir, MaxFile) ->
    scan_block_files(BlocksDir, 0, MaxFile, #{}).

scan_block_files(_BlocksDir, N, MaxFile, Acc) when N > MaxFile ->
    Acc;
scan_block_files(BlocksDir, N, MaxFile, Acc) ->
    FilePath = blockfile_path(BlocksDir, N),
    case file:read_file_info(FilePath) of
        {ok, #file_info{size = Size}} ->
            Info = #{size => Size},
            scan_block_files(BlocksDir, N + 1, MaxFile, Acc#{N => Info});
        {error, _} ->
            %% File doesn't exist, skip it
            scan_block_files(BlocksDir, N + 1, MaxFile, Acc)
    end.

%% @doc Calculate total disk usage of block and undo files.
-spec calculate_disk_usage(string(), #{non_neg_integer() => map()},
                           sets:set(non_neg_integer())) -> non_neg_integer().
calculate_disk_usage(BlocksDir, FileInfo, PrunedFiles) ->
    maps:fold(fun(FileNum, #{size := BlkSize}, Total) ->
        case sets:is_element(FileNum, PrunedFiles) of
            true ->
                %% Already pruned, don't count
                Total;
            false ->
                %% Add block file size
                RevPath = revfile_path(BlocksDir, FileNum),
                RevSize = case file:read_file_info(RevPath) of
                    {ok, #file_info{size = S}} -> S;
                    _ -> 0
                end,
                Total + BlkSize + RevSize
        end
    end, 0, FileInfo).

%% @doc Check if a block has been pruned by looking up its file number.
-spec check_block_pruned(binary(), #state{}) -> boolean().
check_block_pruned(Hash, #state{pruned_files = PrunedFiles}) ->
    case ets:lookup(?BLOCK_INDEX_ETS, Hash) of
        [{Hash, {FileNum, _Offset, _Size}}] ->
            sets:is_element(FileNum, PrunedFiles);
        [{Hash, {FileNum, _Offset, _Size, pruned}}] ->
            %% Explicitly marked as pruned
            true orelse sets:is_element(FileNum, PrunedFiles);
        [] ->
            %% Block not in index - could be pruned or never stored
            false
    end.

%% @doc Get the current chain height from meta.
-spec get_current_height(rocksdb:db_handle(), rocksdb:cf_handle()) ->
    non_neg_integer() | undefined.
get_current_height(Db, MetaCF) ->
    case rocksdb:get(Db, MetaCF, <<"chain_tip">>, []) of
        {ok, <<_Hash:32/binary, Height:64/big>>} -> Height;
        not_found -> undefined
    end.

%% @doc Perform the actual pruning operation.
%% Deletes oldest block files until disk usage is below target.
-spec do_prune_files(#state{}) ->
    {ok, non_neg_integer(), #state{}} | {error, term()}.
do_prune_files(#state{prune_target = 0} = State) ->
    %% Pruning disabled
    {ok, 0, State};
do_prune_files(#state{prune_target = Target, blocks_dir = BlocksDir,
                      file_info = FileInfo, pruned_files = PrunedFiles,
                      db_handle = Db, cf_meta = MetaCF,
                      current_file = CurrentFile} = State) ->
    %% Get current chain height
    case get_current_height(Db, MetaCF) of
        undefined ->
            %% No chain tip yet, nothing to prune
            {ok, 0, State};
        ChainHeight when ChainHeight =< ?REORG_SAFETY_BLOCKS ->
            %% Not enough blocks yet
            {ok, 0, State};
        ChainHeight ->
            %% Calculate current disk usage
            CurrentUsage = calculate_disk_usage(BlocksDir, FileInfo, PrunedFiles),
            case CurrentUsage =< Target of
                true ->
                    %% Already below target
                    {ok, 0, State};
                false ->
                    %% Need to prune - find files we can delete
                    %% Get min height we must keep (for reorg safety)
                    MinKeepHeight = ChainHeight - ?REORG_SAFETY_BLOCKS,

                    %% Find prunable files (not already pruned, not in safety window)
                    PrunableFiles = find_prunable_files(BlocksDir, FileInfo,
                                                         PrunedFiles, MinKeepHeight,
                                                         CurrentFile),

                    %% Prune files until below target
                    {Pruned, NewUsage, NewPrunedFiles} =
                        prune_until_target(BlocksDir, PrunableFiles, CurrentUsage,
                                           Target, PrunedFiles),

                    case Pruned of
                        [] ->
                            {ok, 0, State};
                        _ ->
                            %% Update ETS index to mark blocks as pruned
                            mark_blocks_pruned(Pruned),

                            %% Save pruned files set
                            save_pruned_files(Db, MetaCF, NewPrunedFiles),

                            logger:info("beamchain_db: pruned ~p files, usage: ~pMB -> ~pMB",
                                        [length(Pruned), CurrentUsage div (1024*1024),
                                         NewUsage div (1024*1024)]),

                            {ok, length(Pruned),
                             State#state{pruned_files = NewPrunedFiles}}
                    end
            end
    end.

%% @doc Find files that can be pruned (sorted by file number, oldest first).
-spec find_prunable_files(string(), #{non_neg_integer() => map()},
                          sets:set(non_neg_integer()), non_neg_integer(),
                          non_neg_integer()) -> [{non_neg_integer(), non_neg_integer()}].
find_prunable_files(BlocksDir, FileInfo, PrunedFiles, MinKeepHeight, CurrentFile) ->
    %% Build list of {FileNum, MaxHeight, Size} for each file
    FileList = maps:fold(fun(FileNum, #{size := Size}, Acc) ->
        case sets:is_element(FileNum, PrunedFiles) of
            true ->
                %% Already pruned
                Acc;
            false when FileNum >= CurrentFile ->
                %% Don't prune the current write file
                Acc;
            false ->
                %% Check if file contains blocks we need to keep
                %% We need to scan the ETS index to find max height in this file
                MaxHeight = find_max_height_in_file(FileNum),
                case MaxHeight of
                    undefined ->
                        %% No blocks found for this file
                        [{FileNum, Size} | Acc];
                    H when H < MinKeepHeight ->
                        %% All blocks in file are old enough to prune
                        RevPath = revfile_path(BlocksDir, FileNum),
                        RevSize = case file:read_file_info(RevPath) of
                            {ok, #file_info{size = S}} -> S;
                            _ -> 0
                        end,
                        [{FileNum, Size + RevSize} | Acc];
                    _ ->
                        %% File contains blocks we need to keep
                        Acc
                end
        end
    end, [], FileInfo),
    %% Sort by file number (oldest first)
    lists:sort(fun({A, _}, {B, _}) -> A =< B end, FileList).

%% @doc Find the maximum block height stored in a given file.
-spec find_max_height_in_file(non_neg_integer()) -> non_neg_integer() | undefined.
find_max_height_in_file(FileNum) ->
    %% Scan ETS table to find max height for blocks in this file
    %% This is not efficient but pruning is infrequent
    ets:foldl(fun({_Hash, {FN, _Offset, _Size}}, MaxHeight) when FN =:= FileNum ->
        %% We don't store height in the ETS entry, so we need to look it up
        %% For now, we'll use the file number as a rough proxy
        %% (files are written sequentially, so higher file number = higher blocks)
        %% A more accurate implementation would track height ranges per file
        case MaxHeight of
            undefined -> 0;
            H -> H
        end;
    ({_Hash, {FN, _Offset, _Size, pruned}}, MaxHeight) when FN =:= FileNum ->
        MaxHeight;
    (_, MaxHeight) ->
        MaxHeight
    end, undefined, ?BLOCK_INDEX_ETS).

%% @doc Prune files until disk usage is below target.
-spec prune_until_target(string(), [{non_neg_integer(), non_neg_integer()}],
                         non_neg_integer(), non_neg_integer(),
                         sets:set(non_neg_integer())) ->
    {[non_neg_integer()], non_neg_integer(), sets:set(non_neg_integer())}.
prune_until_target(_BlocksDir, [], CurrentUsage, _Target, PrunedFiles) ->
    {[], CurrentUsage, PrunedFiles};
prune_until_target(_BlocksDir, _Files, CurrentUsage, Target, PrunedFiles)
  when CurrentUsage =< Target ->
    {[], CurrentUsage, PrunedFiles};
prune_until_target(BlocksDir, [{FileNum, Size} | Rest], CurrentUsage, Target, PrunedFiles) ->
    %% Delete block and undo files
    BlkPath = blockfile_path(BlocksDir, FileNum),
    RevPath = revfile_path(BlocksDir, FileNum),

    %% Delete files
    _ = file:delete(BlkPath),
    _ = file:delete(RevPath),

    NewUsage = CurrentUsage - Size,
    NewPrunedFiles = sets:add_element(FileNum, PrunedFiles),

    case NewUsage =< Target of
        true ->
            {[FileNum], NewUsage, NewPrunedFiles};
        false ->
            {Pruned, FinalUsage, FinalPrunedFiles} =
                prune_until_target(BlocksDir, Rest, NewUsage, Target, NewPrunedFiles),
            {[FileNum | Pruned], FinalUsage, FinalPrunedFiles}
    end.

%% @doc Update ETS index entries to mark blocks as pruned.
-spec mark_blocks_pruned([non_neg_integer()]) -> ok.
mark_blocks_pruned(FileNums) ->
    FileNumSet = sets:from_list(FileNums),
    ets:foldl(fun({Hash, {FileNum, Offset, Size}}, _Acc) ->
        case sets:is_element(FileNum, FileNumSet) of
            true ->
                %% Mark as pruned
                ets:insert(?BLOCK_INDEX_ETS, {Hash, {FileNum, Offset, Size, pruned}});
            false ->
                ok
        end;
    (_, Acc) ->
        Acc
    end, ok, ?BLOCK_INDEX_ETS),
    ok.

%%% ===================================================================
%%% Block height/time index functions
%%% ===================================================================

%% @doc Get block hash by height using ETS lookup.
%% Falls back to RocksDB if not in ETS.
-spec get_hash_by_height(non_neg_integer()) -> {ok, binary()} | not_found.
get_hash_by_height(Height) ->
    case ets:lookup(?HEIGHT_TO_HASH_ETS, Height) of
        [{Height, Hash}] ->
            {ok, Hash};
        [] ->
            %% Fall back to block_index in RocksDB
            case get_block_index(Height) of
                {ok, #{hash := Hash}} ->
                    %% Cache it for future lookups
                    ets:insert(?HEIGHT_TO_HASH_ETS, {Height, Hash}),
                    {ok, Hash};
                not_found ->
                    not_found
            end
    end.

%% @doc Get all block hashes within a time range (inclusive).
%% Returns list of {Timestamp, Height, Hash} tuples sorted by timestamp.
-spec get_blocks_in_time_range(non_neg_integer(), non_neg_integer()) ->
    [{non_neg_integer(), non_neg_integer(), binary()}].
get_blocks_in_time_range(FromTime, ToTime) ->
    %% Use ETS select on ordered_set for efficient range query
    MatchSpec = [{{{'$1', '$2'}, '$3'},
                  [{'>=', '$1', FromTime}, {'=<', '$1', ToTime}],
                  [{{'$1', '$2', '$3'}}]}],
    ets:select(?TIME_INDEX_ETS, MatchSpec).

%% @doc Store block statistics in ETS cache.
%% Stats is a map with keys like txcount, total_weight, total_fee, etc.
-spec store_block_stats(binary(), map()) -> ok.
store_block_stats(Hash, Stats) when byte_size(Hash) =:= 32 ->
    ets:insert(?BLOCK_STATS_ETS, {Hash, Stats}),
    ok.

%% @doc Get cached block statistics.
-spec get_block_stats(binary()) -> {ok, map()} | not_found.
get_block_stats(Hash) when byte_size(Hash) =:= 32 ->
    case ets:lookup(?BLOCK_STATS_ETS, Hash) of
        [{Hash, Stats}] -> {ok, Stats};
        [] -> not_found
    end.

%% @doc Get cumulative transaction count up to a given height.
%% Stored in meta CF for persistence.
-spec get_cumulative_tx_count(non_neg_integer()) -> {ok, non_neg_integer()} | not_found.
get_cumulative_tx_count(Height) ->
    Key = <<"cumtx:", (integer_to_binary(Height))/binary>>,
    case get_meta(Key) of
        {ok, <<Count:64/big>>} -> {ok, Count};
        not_found -> not_found
    end.

%% @doc Store cumulative transaction count for a height.
-spec store_cumulative_tx_count(non_neg_integer(), non_neg_integer()) -> ok.
store_cumulative_tx_count(Height, Count) ->
    Key = <<"cumtx:", (integer_to_binary(Height))/binary>>,
    Value = <<Count:64/big>>,
    put_meta(Key, Value).

%% @doc Update height and time indexes when connecting a block.
%% Called by chainstate during block connection.
-spec index_block(non_neg_integer(), binary(), non_neg_integer()) -> ok.
index_block(Height, Hash, Timestamp) ->
    %% Update height -> hash mapping
    ets:insert(?HEIGHT_TO_HASH_ETS, {Height, Hash}),
    %% Update time index: {Timestamp, Height} -> Hash
    ets:insert(?TIME_INDEX_ETS, {{Timestamp, Height}, Hash}),
    ok.

%% @doc Remove height and time indexes when disconnecting a block.
%% Called by chainstate during block disconnection.
-spec unindex_block(non_neg_integer(), non_neg_integer()) -> ok.
unindex_block(Height, Timestamp) ->
    ets:delete(?HEIGHT_TO_HASH_ETS, Height),
    ets:delete(?TIME_INDEX_ETS, {Timestamp, Height}),
    ok.
