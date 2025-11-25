-module(beamchain_db).
-behaviour(gen_server).

-include("beamchain.hrl").

%% API
-export([start_link/0, stop/0]).

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
