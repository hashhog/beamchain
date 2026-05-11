-module(beamchain_blockfilter_index).
-behaviour(gen_server).

%%% -------------------------------------------------------------------
%%% BIP-157 persistent block filter index for the *basic* filter type.
%%%
%%% Stores per-block:
%%%   - the encoded GCS filter bytes (BIP-158)
%%%   - the cfheader (chained dSHA256(filter_hash || prev_header))
%%%   - height -> block_hash mapping for fast range queries
%%%
%%% Storage layout:
%%%   <datadir>/indexes/blockfilter/basic/  (its own RocksDB instance)
%%%
%%%   Key prefixes (1 byte):
%%%     'F' || block_hash (32B) -> filter_bytes (varint-prefixed payload)
%%%     'H' || block_hash (32B) -> cfheader (32B)
%%%     'h' || height (4B BE)   -> block_hash (32B)
%%%     'M' || meta_key         -> meta_value
%%%       meta_key = "tip_header"      -> 32B cfheader
%%%       meta_key = "tip_height"      -> 4B LE height
%%%
%%% This module is started ONLY when BEAMCHAIN_BLOCKFILTERINDEX=1 (or
%%% blockfilterindex=1 in the config file).  It registers
%%% beamchain_blockfilter_index as a named gen_server; callers should
%%% probe is_enabled/0 before invoking operations.
%%%
%%% Reference: bitcoin-core/src/index/blockfilterindex.cpp
%%% -------------------------------------------------------------------

-include("beamchain.hrl").

-export([start_link/0, stop/0, is_enabled/0]).

%% Operations
-export([add_block/2, add_block/3, remove_block/2, remove_block/1,
         get_filter/1, get_header/1, get_block_hash_by_height/1,
         get_height_by_hash/1,
         tip_header/0, tip_height/0]).

%% BIP-157 P2P helpers
-export([get_filter_range/2, get_header_range/2, get_checkpoints/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

%% Key prefixes
-define(P_FILTER, $F).
-define(P_HEADER, $H).
-define(P_HEIGHT, $h).
-define(P_META,   $M).
%% BUG-5 fix: reverse index block_hash → height for O(1) stop_hash lookup.
%% Without this, stop_hash_to_height in peer_manager was O(tip), exposing a
%% DoS vector (getcfcheckpt with stop_hash not in the index forces a full
%% reverse scan).  Core resolves via m_chainman.m_blockman.LookupBlockIndex
%% which is O(1) hash-table lookup.
%% bitcoin-core/src/net_processing.cpp:3280.
-define(P_HASH_TO_HEIGHT, $r).

%% Meta keys
-define(META_TIP_HEADER, <<"tip_header">>).
-define(META_TIP_HEIGHT, <<"tip_height">>).

-record(state, {
    db        :: rocksdb:db_handle() | undefined,
    enabled   :: boolean(),
    filter_type :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

stop() ->
    case whereis(?SERVER) of
        undefined -> ok;
        _ -> gen_server:stop(?SERVER)
    end.

%% @doc True if the filter index is configured AND running.
-spec is_enabled() -> boolean().
is_enabled() ->
    case whereis(?SERVER) of
        undefined -> false;
        Pid when is_pid(Pid) ->
            case (catch gen_server:call(?SERVER, is_enabled, 5000)) of
                true  -> true;
                _     -> false
            end
    end.

%% @doc Build, store, and return {filter_bytes, cfheader} for *Block*
%% at *Height*, fetching prevout scripts from the on-disk undo data.
%% Idempotent — calling for the same hash overwrites the cached entry,
%% but the cfheader is recomputed against the current tip header so
%% callers must apply blocks in canonical chain order during normal
%% operation.
-spec add_block(#block{}, non_neg_integer()) ->
    {ok, {binary(), binary()}} | {error, term()}.
add_block(Block, Height) ->
    add_block(Block, Height, undefined).

%% @doc Same as add_block/2 but takes an explicit list of prevout
%% scriptPubKeys (in input-traversal order, skipping the coinbase).
%% Used during block-connect when undo data has not yet been flushed
%% to disk.
-spec add_block(#block{}, non_neg_integer(),
                [binary()] | undefined) ->
    {ok, {binary(), binary()}} | {error, term()}.
add_block(Block, Height, PrevScripts) ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ ->
            gen_server:call(?SERVER,
                {add_block, Block, Height, PrevScripts}, 60000)
    end.

%% @doc Remove a filter index entry (used during block-disconnect for
%% reorgs).  The caller is responsible for restoring the tip header
%% via the returned previous-header value.
-spec remove_block(binary(), non_neg_integer()) ->
    ok | {error, term()}.
remove_block(BlockHash, Height) ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ ->
            gen_server:call(?SERVER,
                {remove_block, BlockHash, Height}, 30000)
    end.

remove_block(BlockHash) ->
    remove_block(BlockHash, undefined).

%% @doc Return raw GCS filter bytes for *BlockHash*, or `not_found`.
-spec get_filter(binary()) -> {ok, binary()} | not_found.
get_filter(BlockHash) when byte_size(BlockHash) =:= 32 ->
    case whereis(?SERVER) of
        undefined -> not_found;
        _         -> gen_server:call(?SERVER, {get_filter, BlockHash}, 5000)
    end.

%% @doc Return cfheader (32B) for *BlockHash*, or `not_found`.
-spec get_header(binary()) -> {ok, binary()} | not_found.
get_header(BlockHash) when byte_size(BlockHash) =:= 32 ->
    case whereis(?SERVER) of
        undefined -> not_found;
        _         -> gen_server:call(?SERVER, {get_header, BlockHash}, 5000)
    end.

%% @doc Return the block hash indexed at *Height*, or `not_found`.
-spec get_block_hash_by_height(non_neg_integer()) ->
    {ok, binary()} | not_found.
get_block_hash_by_height(Height) ->
    case whereis(?SERVER) of
        undefined -> not_found;
        _         ->
            gen_server:call(?SERVER, {get_hash_by_height, Height}, 5000)
    end.

%% @doc Return the height at which *BlockHash* was indexed, or `not_found`.
%% O(1) lookup via the reverse hash→height index.
%% BUG-5 fix: this supersedes the O(tip) reverse scan in stop_hash_to_height.
%% bitcoin-core equivalent: m_chainman.m_blockman.LookupBlockIndex(stop_hash).
-spec get_height_by_hash(binary()) -> {ok, non_neg_integer()} | not_found.
get_height_by_hash(BlockHash) when byte_size(BlockHash) =:= 32 ->
    case whereis(?SERVER) of
        undefined -> not_found;
        _         ->
            gen_server:call(?SERVER, {get_height_by_hash, BlockHash}, 5000)
    end.

%% @doc Current cfheader chain tip (32B).  Returns 32 zero bytes when
%% the index is empty.
-spec tip_header() -> binary().
tip_header() ->
    case whereis(?SERVER) of
        undefined -> beamchain_blockfilter:genesis_prev_header();
        _ ->
            case (catch gen_server:call(?SERVER, tip_header, 5000)) of
                {ok, H} when is_binary(H) -> H;
                _ -> beamchain_blockfilter:genesis_prev_header()
            end
    end.

-spec tip_height() -> integer().
tip_height() ->
    case whereis(?SERVER) of
        undefined -> -1;
        _ ->
            case (catch gen_server:call(?SERVER, tip_height, 5000)) of
                {ok, H} when is_integer(H) -> H;
                _ -> -1
            end
    end.

%%% -------------------------------------------------------------------
%%% BIP-157 P2P helpers
%%% -------------------------------------------------------------------

%% @doc Return up to 1000 (Hash, FilterBytes) pairs for the inclusive
%% height range [StartHeight, StopHeight], where StopHeight is the
%% height of *StopHash*.  Returns {error, _} if the range is invalid.
-spec get_filter_range(non_neg_integer(), binary()) ->
    {ok, [{binary(), binary()}]} | {error, term()}.
get_filter_range(StartHeight, StopHash)
  when byte_size(StopHash) =:= 32 ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ ->
            gen_server:call(?SERVER,
                {get_filter_range, StartHeight, StopHash}, 30000)
    end.

%% @doc Return prev-cfheader (the header at StartHeight-1) plus a list
%% of filter_hashes for the heights [StartHeight, StopHeight].  Caps
%% the response at 2000 hashes per BIP-157.
-spec get_header_range(non_neg_integer(), binary()) ->
    {ok, {binary(), [binary()]}} | {error, term()}.
get_header_range(StartHeight, StopHash)
  when byte_size(StopHash) =:= 32 ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ ->
            gen_server:call(?SERVER,
                {get_header_range, StartHeight, StopHash}, 30000)
    end.

%% @doc Return the cfheaders at every multiple of 1000 below the height
%% of *StopHash* (1000, 2000, …, last <= stop_height).  Used by
%% getcfcheckpt / cfcheckpt.
-spec get_checkpoints(non_neg_integer(), binary()) ->
    {ok, [binary()]} | {error, term()}.
get_checkpoints(StopHeight, StopHash)
  when byte_size(StopHash) =:= 32 ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ ->
            gen_server:call(?SERVER,
                {get_checkpoints, StopHeight, StopHash}, 30000)
    end.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    case beamchain_config:blockfilterindex_enabled() of
        false ->
            %% Stay alive but disabled — callers can probe is_enabled/0
            %% without crashing.  This lets the supervisor keep us
            %% mounted under the standard rest_for_one tree.
            {ok, #state{db = undefined, enabled = false,
                        filter_type =
                            beamchain_blockfilter:basic_filter_type()}};
        true ->
            DataDir = beamchain_config:datadir(),
            Path = filename:join(
                [DataDir, "indexes", "blockfilter", "basic"]),
            ok = filelib:ensure_dir(filename:join(Path, "dummy")),
            Opts = [
                {create_if_missing, true},
                {max_open_files, 64}
            ],
            case rocksdb:open(Path, Opts) of
                {ok, Db} ->
                    logger:info("blockfilter_index: opened ~s", [Path]),
                    {ok, #state{
                        db = Db,
                        enabled = true,
                        filter_type =
                            beamchain_blockfilter:basic_filter_type()
                    }};
                {error, Reason} ->
                    logger:error("blockfilter_index: open failed ~p",
                                 [Reason]),
                    {ok, #state{db = undefined, enabled = false,
                                filter_type =
                                    beamchain_blockfilter:basic_filter_type()}}
            end
    end.

handle_call(is_enabled, _From, State) ->
    {reply, State#state.enabled, State};
handle_call({add_block, _Block, _Height, _Prev}, _From,
            #state{enabled = false} = State) ->
    {reply, {error, index_disabled}, State};
handle_call({add_block, Block, Height, PrevScripts}, _From,
            #state{db = Db} = State) ->
    Reply =
        try
            BlockHash = block_hash_internal(Block),
            FilterBytes = case PrevScripts of
                undefined ->
                    beamchain_blockfilter:build_basic_filter(
                        Block#block{hash = BlockHash});
                _ ->
                    beamchain_blockfilter:build_basic_filter(
                        Block#block{hash = BlockHash}, PrevScripts)
            end,
            PrevHeader = read_tip_header(Db),
            Header = beamchain_blockfilter:compute_header(
                FilterBytes, PrevHeader),
            ok = put_kv(Db, fkey(BlockHash), FilterBytes),
            ok = put_kv(Db, hkey(BlockHash), Header),
            ok = put_kv(Db, height_key(Height), BlockHash),
            %% BUG-5 fix: maintain reverse hash→height index for O(1) lookup.
            ok = put_kv(Db, rkey(BlockHash), <<Height:32/little>>),
            ok = put_kv(Db, mkey(?META_TIP_HEADER), Header),
            ok = put_kv(Db, mkey(?META_TIP_HEIGHT),
                        <<Height:32/little>>),
            {ok, {FilterBytes, Header}}
        catch
            Class:Reason:_ST ->
                logger:warning("blockfilter_index: add_block failed: "
                               "~p:~p", [Class, Reason]),
                {error, {Class, Reason}}
        end,
    {reply, Reply, State};
handle_call({remove_block, _BlockHash, _Height}, _From,
            #state{enabled = false} = State) ->
    {reply, {error, index_disabled}, State};
handle_call({remove_block, BlockHash, Height}, _From,
            #state{db = Db} = State) ->
    Reply =
        try
            %% Capture prev-tip-header so we can roll the chain back.
            PrevTip =
                case Height of
                    undefined ->
                        undefined;
                    H when H > 0 ->
                        case lookup_height_internal(Db, H - 1) of
                            {ok, PrevHash} ->
                                case get_kv(Db, hkey(PrevHash)) of
                                    {ok, PH} -> PH;
                                    not_found ->
                                        beamchain_blockfilter:
                                            genesis_prev_header()
                                end;
                            not_found ->
                                beamchain_blockfilter:genesis_prev_header()
                        end;
                    _ ->
                        beamchain_blockfilter:genesis_prev_header()
                end,
            ok = delete_kv(Db, fkey(BlockHash)),
            ok = delete_kv(Db, hkey(BlockHash)),
            %% BUG-5 fix: also remove from the reverse hash→height index.
            ok = delete_kv(Db, rkey(BlockHash)),
            case Height of
                undefined -> ok;
                _ -> ok = delete_kv(Db, height_key(Height))
            end,
            case PrevTip of
                undefined -> ok;
                _ ->
                    ok = put_kv(Db, mkey(?META_TIP_HEADER), PrevTip),
                    case Height of
                        undefined -> ok;
                        _ when Height > 0 ->
                            ok = put_kv(Db, mkey(?META_TIP_HEIGHT),
                                        <<(Height - 1):32/little>>);
                        _ ->
                            ok = delete_kv(Db, mkey(?META_TIP_HEIGHT))
                    end
            end,
            ok
        catch
            Class:Reason:_ST ->
                logger:warning("blockfilter_index: remove_block failed: "
                               "~p:~p", [Class, Reason]),
                {error, {Class, Reason}}
        end,
    {reply, Reply, State};
handle_call({get_filter, BH}, _From, #state{db = Db} = State) ->
    {reply, get_kv_ok(Db, fkey(BH)), State};
handle_call({get_header, BH}, _From, #state{db = Db} = State) ->
    {reply, get_kv_ok(Db, hkey(BH)), State};
handle_call({get_hash_by_height, Height}, _From,
            #state{db = Db} = State) ->
    {reply, lookup_height_internal(Db, Height), State};
handle_call({get_height_by_hash, BlockHash}, _From,
            #state{db = Db} = State) ->
    {reply, lookup_hash_internal(Db, BlockHash), State};
handle_call(tip_header, _From, #state{db = Db} = State) ->
    {reply, {ok, read_tip_header(Db)}, State};
handle_call(tip_height, _From, #state{db = Db} = State) ->
    {reply, {ok, read_tip_height(Db)}, State};
handle_call({get_filter_range, StartH, StopHash}, _From,
            #state{db = Db} = State) ->
    Reply = do_filter_range(Db, StartH, StopHash, 1000),
    {reply, Reply, State};
handle_call({get_header_range, StartH, StopHash}, _From,
            #state{db = Db} = State) ->
    Reply = do_header_range(Db, StartH, StopHash, 2000),
    {reply, Reply, State};
handle_call({get_checkpoints, StopHeight, StopHash}, _From,
            #state{db = Db} = State) ->
    Reply = do_checkpoints(Db, StopHeight, StopHash),
    {reply, Reply, State};
handle_call(_Msg, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{db = undefined}) -> ok;
terminate(_Reason, #state{db = Db}) ->
    catch rocksdb:close(Db),
    ok.

code_change(_Old, State, _Extra) ->
    {ok, State}.

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

block_hash_internal(#block{hash = H}) when byte_size(H) =:= 32 -> H;
block_hash_internal(#block{header = Header}) ->
    beamchain_serialize:block_hash(Header).

fkey(BH) -> <<?P_FILTER, BH/binary>>.
hkey(BH) -> <<?P_HEADER, BH/binary>>.
height_key(H) when is_integer(H), H >= 0 ->
    <<?P_HEIGHT, H:32/big>>.
mkey(MK) -> <<?P_META, MK/binary>>.
%% BUG-5 fix: reverse hash→height index key.
rkey(BH) -> <<?P_HASH_TO_HEIGHT, BH/binary>>.

put_kv(undefined, _K, _V) -> ok;
put_kv(Db, K, V) ->
    rocksdb:put(Db, K, V, []).

delete_kv(undefined, _K) -> ok;
delete_kv(Db, K) ->
    rocksdb:delete(Db, K, []).

get_kv(undefined, _K) -> not_found;
get_kv(Db, K) ->
    case rocksdb:get(Db, K, []) of
        {ok, V} -> {ok, V};
        not_found -> not_found
    end.

get_kv_ok(Db, K) ->
    case get_kv(Db, K) of
        {ok, V} -> {ok, V};
        _       -> not_found
    end.

read_tip_header(undefined) ->
    beamchain_blockfilter:genesis_prev_header();
read_tip_header(Db) ->
    case get_kv(Db, mkey(?META_TIP_HEADER)) of
        {ok, H} when byte_size(H) =:= 32 -> H;
        _ -> beamchain_blockfilter:genesis_prev_header()
    end.

read_tip_height(undefined) -> -1;
read_tip_height(Db) ->
    case get_kv(Db, mkey(?META_TIP_HEIGHT)) of
        {ok, <<H:32/little>>} -> H;
        _ -> -1
    end.

lookup_height_internal(undefined, _) -> not_found;
lookup_height_internal(Db, Height) when is_integer(Height), Height >= 0 ->
    case get_kv(Db, height_key(Height)) of
        {ok, BH} when byte_size(BH) =:= 32 -> {ok, BH};
        _ -> not_found
    end;
lookup_height_internal(_, _) -> not_found.

%% BUG-5 fix: O(1) reverse hash→height lookup via the 'r' index.
%% Replaces the O(tip) scan in stop_hash_to_height.
lookup_hash_internal(undefined, _) -> not_found;
lookup_hash_internal(Db, BlockHash) when byte_size(BlockHash) =:= 32 ->
    case get_kv(Db, rkey(BlockHash)) of
        {ok, <<H:32/little>>} -> {ok, H};
        _ -> not_found
    end;
lookup_hash_internal(_, _) -> not_found.

%% --- BIP-157 range queries ---

do_filter_range(undefined, _, _, _) -> {error, index_disabled};
do_filter_range(Db, StartHeight, StopHash, Cap) ->
    case range_heights(Db, StartHeight, StopHash, Cap) of
        {ok, Heights} ->
            collect_filters(Db, Heights, []);
        Err -> Err
    end.

collect_filters(_Db, [], Acc) -> {ok, lists:reverse(Acc)};
collect_filters(Db, [H | Rest], Acc) ->
    case lookup_height_internal(Db, H) of
        {ok, BH} ->
            case get_kv(Db, fkey(BH)) of
                {ok, FB} -> collect_filters(Db, Rest,
                                            [{BH, FB} | Acc]);
                not_found -> {error, {missing_filter, H, BH}}
            end;
        not_found -> {error, {missing_height, H}}
    end.

do_header_range(undefined, _, _, _) -> {error, index_disabled};
do_header_range(Db, StartHeight, StopHash, Cap) ->
    case range_heights(Db, StartHeight, StopHash, Cap) of
        {ok, Heights} ->
            PrevHeader =
                case StartHeight of
                    0 -> beamchain_blockfilter:genesis_prev_header();
                    _ ->
                        case lookup_height_internal(Db, StartHeight - 1) of
                            {ok, PrevHash} ->
                                case get_kv(Db, hkey(PrevHash)) of
                                    {ok, PH} -> PH;
                                    not_found ->
                                        beamchain_blockfilter:
                                            genesis_prev_header()
                                end;
                            not_found ->
                                beamchain_blockfilter:genesis_prev_header()
                        end
                end,
            collect_filter_hashes(Db, Heights, PrevHeader, []);
        Err -> Err
    end.

collect_filter_hashes(_Db, [], PrevHeader, Acc) ->
    {ok, {PrevHeader, lists:reverse(Acc)}};
collect_filter_hashes(Db, [H | Rest], PrevHeader, Acc) ->
    case lookup_height_internal(Db, H) of
        {ok, BH} ->
            case get_kv(Db, fkey(BH)) of
                {ok, FB} ->
                    FH = beamchain_blockfilter:filter_hash(FB),
                    collect_filter_hashes(Db, Rest, PrevHeader,
                                          [FH | Acc]);
                not_found -> {error, {missing_filter, H, BH}}
            end;
        not_found -> {error, {missing_height, H}}
    end.

do_checkpoints(undefined, _, _) -> {error, index_disabled};
do_checkpoints(Db, StopHeight, StopHash) ->
    %% BUG-5b fix: validate that StopHash is actually in the indexed chain.
    %% Previously _StopHash was silently ignored, allowing a peer to receive
    %% checkpoint headers anchored to the wrong stop hash.  Core validates via
    %% LookupBlockIndex + BlockRequestAllowed before serving checkpoints.
    %% bitcoin-core/src/net_processing.cpp:3395-3401.
    case verify_stop_hash(Db, StopHeight, StopHash) of
        ok ->
            case StopHeight of
                H when is_integer(H), H >= 0 ->
                    Last = (H div 1000) * 1000,
                    Heights = case Last of
                        0 -> [];
                        _ -> lists:seq(1000, Last, 1000)
                    end,
                    collect_checkpoints(Db, Heights, [])
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Verify that the block hash indexed at StopHeight equals StopHash.
%% This ensures the stop_hash from the P2P request is on our indexed chain.
verify_stop_hash(_Db, _StopHeight, undefined) ->
    ok;
verify_stop_hash(Db, StopHeight, StopHash) when is_integer(StopHeight),
                                                 StopHeight >= 0,
                                                 byte_size(StopHash) =:= 32 ->
    case lookup_hash_internal(Db, StopHash) of
        {ok, StopHeight} -> ok;
        {ok, _OtherHeight} -> {error, stop_hash_height_mismatch};
        not_found -> {error, stop_hash_not_indexed}
    end;
verify_stop_hash(_, _, _) ->
    {error, invalid_stop_height}.

collect_checkpoints(_Db, [], Acc) -> {ok, lists:reverse(Acc)};
collect_checkpoints(Db, [H | Rest], Acc) ->
    case lookup_height_internal(Db, H) of
        {ok, BH} ->
            case get_kv(Db, hkey(BH)) of
                {ok, Header} ->
                    collect_checkpoints(Db, Rest, [Header | Acc]);
                not_found -> {error, {missing_header, H, BH}}
            end;
        not_found -> {error, {missing_height, H}}
    end.

%% Compute the inclusive height range [StartHeight, StopHeight] given
%% the height of *StopHash*, capped at *Cap*.
%% BUG-5 fix: use the O(1) reverse hash→height index instead of the
%% previous O(tip - stop_height) reverse scan.
range_heights(Db, StartHeight, StopHash, Cap) ->
    case lookup_hash_internal(Db, StopHash) of
        not_found -> {error, stop_hash_not_indexed};
        {ok, StopHeight} when StopHeight < StartHeight ->
            {error, range_inverted};
        {ok, StopHeight} ->
            Count = StopHeight - StartHeight + 1,
            Effective = min(Count, Cap),
            {ok, lists:seq(StartHeight,
                          StartHeight + Effective - 1)}
    end.
