-module(beamchain_db).
-behaviour(gen_server).

-include("beamchain.hrl").

%% API
-export([start_link/0, stop/0]).

%% Block storage
-export([store_block/2, get_block/1, get_block_by_height/1, has_block/1]).

%% UTXO set
-export([get_utxo/2, store_utxo/3, spend_utxo/2, has_utxo/2]).

%% Block index
-export([store_block_index/5, get_block_index/1, get_block_index_by_hash/1]).

%% Chain tip
-export([get_chain_tip/0, set_chain_tip/2]).

%% Transaction index
-export([store_tx_index/4, get_tx_location/1]).

%% Undo data
-export([store_undo/2, get_undo/1]).

%% Batch writes
-export([write_batch/1]).

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

%% @doc Get a UTXO by outpoint
-spec get_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
get_utxo(Txid, Vout) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {get_utxo, Txid, Vout}).

%% @doc Store a UTXO
-spec store_utxo(binary(), non_neg_integer(), #utxo{}) -> ok.
store_utxo(Txid, Vout, Utxo) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {store_utxo, Txid, Vout, Utxo}).

%% @doc Spend (remove) a UTXO, returns the spent UTXO for undo data
-spec spend_utxo(binary(), non_neg_integer()) -> {ok, #utxo{}} | not_found.
spend_utxo(Txid, Vout) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {spend_utxo, Txid, Vout}).

%% @doc Check if a UTXO exists
-spec has_utxo(binary(), non_neg_integer()) -> boolean().
has_utxo(Txid, Vout) when byte_size(Txid) =:= 32 ->
    gen_server:call(?SERVER, {has_utxo, Txid, Vout}).

%% @doc Store block index entry (header metadata for a given height)
-spec store_block_index(non_neg_integer(), binary(), #block_header{},
                        binary(), integer()) -> ok.
store_block_index(Height, Hash, Header, Chainwork, Status) ->
    gen_server:call(?SERVER, {store_block_index, Height, Hash, Header,
                              Chainwork, Status}).

%% @doc Get block index by height
-spec get_block_index(non_neg_integer()) ->
    {ok, #{hash => binary(), header => #block_header{},
           chainwork => binary(), status => integer()}} | not_found.
get_block_index(Height) ->
    gen_server:call(?SERVER, {get_block_index, Height}).

%% @doc Get block index by hash (reverse lookup)
-spec get_block_index_by_hash(binary()) ->
    {ok, #{height => integer(), header => #block_header{},
           chainwork => binary(), status => integer()}} | not_found.
get_block_index_by_hash(Hash) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {get_block_index_by_hash, Hash}).

%% @doc Get the current chain tip
-spec get_chain_tip() -> {ok, #{hash => binary(), height => integer()}} | not_found.
get_chain_tip() ->
    gen_server:call(?SERVER, get_chain_tip).

%% @doc Set the chain tip
-spec set_chain_tip(binary(), non_neg_integer()) -> ok.
set_chain_tip(Hash, Height) when byte_size(Hash) =:= 32 ->
    gen_server:call(?SERVER, {set_chain_tip, Hash, Height}).

%% @doc Store transaction index entry
-spec store_tx_index(binary(), binary(), non_neg_integer(),
                     non_neg_integer()) -> ok.
store_tx_index(Txid, BlockHash, Height, Position) ->
    gen_server:call(?SERVER, {store_tx_index, Txid, BlockHash, Height, Position}).

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

%% @doc Atomic batch write across column families
%% Ops = [{put, CF, Key, Value} | {delete, CF, Key}]
%% CF is one of: blocks, block_index, chainstate, tx_index, meta, undo
-spec write_batch([tuple()]) -> ok | {error, term()}.
write_batch(Ops) ->
    gen_server:call(?SERVER, {write_batch, Ops}).

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
            #state{db_handle = Db, cf_blocks = CF,
                   cf_block_idx = IdxCF} = State) ->
    Hash = block_hash(Block),
    BlockBin = beamchain_serialize:encode_block(Block),
    %% Store block data keyed by hash
    Result = rocksdb:put(Db, CF, Hash, BlockBin, []),
    %% Store height -> hash in block_index for height lookup
    HeightKey = encode_height(Height),
    rocksdb:put(Db, IdxCF, HeightKey, Hash, []),
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
            {ok, decode_block_index_entry(Bin)};
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

%% Batch writes
handle_call({write_batch, Ops}, _From, State) ->
    WriteActions = lists:map(fun(Op) -> resolve_batch_op(Op, State) end, Ops),
    Result = rocksdb:write(State#state.db_handle, WriteActions, []),
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
