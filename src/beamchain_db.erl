-module(beamchain_db).
-behaviour(gen_server).

-include("beamchain.hrl").

%% API
-export([start_link/0, stop/0]).

%% Block storage
-export([store_block/2, get_block/1, get_block_by_height/1, has_block/1]).

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

-record(state, {
    db_handle   :: rocksdb:db_handle() | undefined,
    cf_blocks   :: rocksdb:cf_handle() | undefined,
    cf_block_idx :: rocksdb:cf_handle() | undefined,
    cf_chainstate :: rocksdb:cf_handle() | undefined,
    cf_tx_index :: rocksdb:cf_handle() | undefined,
    cf_meta     :: rocksdb:cf_handle() | undefined,
    cf_undo     :: rocksdb:cf_handle() | undefined,
    data_dir    :: string()
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
    gen_server:call(?SERVER, {store_block, Block, Height}).

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

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    DataDir = beamchain_config:datadir(),
    DbPath = filename:join(DataDir, "chaindata"),
    ok = filelib:ensure_dir(filename:join(DbPath, "dummy")),

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
            State = #state{
                db_handle = DbHandle,
                cf_blocks = BlocksCF,
                cf_block_idx = BlockIdxCF,
                cf_chainstate = ChainstateCF,
                cf_tx_index = TxIndexCF,
                cf_meta = MetaCF,
                cf_undo = UndoCF,
                data_dir = DbPath
            },
            logger:info("beamchain_db: opened rocksdb at ~s", [DbPath]),
            {ok, State};
        {error, Reason} ->
            logger:error("beamchain_db: failed to open rocksdb: ~p", [Reason]),
            {stop, {db_open_failed, Reason}}
    end.

%% Block storage
handle_call({store_block, Block, Height}, _From,
            #state{db_handle = Db, cf_blocks = CF} = State) ->
    Hash = block_hash(Block),
    BlockBin = beamchain_serialize:encode_block(Block),
    %% Store block data keyed by hash
    Result = rocksdb:put(Db, CF, Hash, BlockBin, []),
    %% Also store height -> hash mapping in block_index for lookup by height
    HeightKey = encode_height(Height),
    rocksdb:put(Db, State#state.cf_block_idx, HeightKey,
                Hash, []),
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
        {ok, Hash} ->
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

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{db_handle = undefined}) ->
    ok;
terminate(_Reason, #state{db_handle = DbHandle}) ->
    logger:info("beamchain_db: closing rocksdb"),
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
