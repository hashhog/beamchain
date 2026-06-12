-module(beamchain_txospenderindex).
-behaviour(gen_server).

%%% -------------------------------------------------------------------
%%% Persistent, reorg-safe txospenderindex (Bitcoin Core -txospenderindex).
%%%
%%% For every input of every NON-coinbase transaction in a connected block
%%% this index records a single key mapping the SPENT outpoint -> the
%%% SPENDING transaction (its txid, the hash of the confirming block, and
%%% the full wire-serialized spending tx so gettxspendingprevout's
%%% return_spending_tx option can be answered without a second lookup). It
%%% is the data source for the CONFIRMED-spend path of the
%%% gettxspendingprevout RPC.
%%%
%%% Mirrors bitcoin-core/src/index/txospenderindex.{h,cpp}
%%% (CustomAppend / CustomRemove / BuildSpenderPositions / FindSpender).
%%% Core keys a per-DB-salted siphash(outpoint) -> CDiskTxPos and reads the
%%% spending tx back off the flat block files on lookup. The
%%% txospenderindex.cpp header comment notes a from-scratch implementation
%%% may legitimately store outpoint -> spending-tx directly; that is the
%%% faithful equivalent and is what this index does. NO salt and NO
%%% separate undo data are needed: the disconnect path RE-DERIVES the same
%%% keys from the disconnected block's OWN inputs and erases them, exactly
%%% like Core's CustomRemove(BuildSpenderPositions(block)).
%%%
%%% This module is the exact structural analogue of
%%% beamchain_coinstatsindex / beamchain_blockfilter_index: a default-off
%%% gen_server with its own RocksDB instance, hooked at the SAME primary
%%% block connect/disconnect points in beamchain_chainstate. Because that
%%% single canonical connect (do_connect_block) / disconnect
%%% (do_disconnect_block) pair is reused by the LIVE reorg path
%%% (do_reorganize_atomic -> disconnect_to/connect_blocks) AND by
%%% invalidateblock / reconsiderblock, the index stays correct across all
%%% of them automatically -- exactly like txindex / coinstatsindex.
%%% Disconnect-before-connect is guaranteed by the reorg orchestrator.
%%%
%%% Storage layout: <datadir>/indexes/txospender/  (its own RocksDB)
%%%   Key prefixes (1 byte):
%%%     's' || outpoint_key(36B = txid(32) || vout(4 LE))
%%%                                  -> serialized spender record (value)
%%%     'M' || meta_key             -> meta_value
%%%       meta_key = "tip_height" -> 4B LE height
%%%       meta_key = "tip_hash"   -> 32B internal block hash
%%%
%%% The outpoint itself is the key (36 bytes); an outpoint is spent at most
%%% once on a single chain, so each key holds at most one record and undo
%%% is a pure DELETE of the re-derived key (no collision handling needed --
%%% the simplification the Core header comment explicitly permits).
%%%
%%% Default-off, gated by beamchain_config:txospenderindex_enabled/0,
%%% matching Core's DEFAULT_TXOSPENDERINDEX = false. When disabled the
%%% gen_server is NOT started by node_sup; callers reach it via the same
%%% whereis-guarded API the other indexes use, so add/remove/find are
%%% no-ops (the connect/disconnect path swallows {error,index_not_running}
%%% under catch).
%%% -------------------------------------------------------------------

-include("beamchain.hrl").

-export([start_link/0, stop/0, is_enabled/0]).

%% Maintenance ops (hooked from chainstate connect/disconnect).
-export([add_block/2, remove_block/2]).

%% Query ops (gettxspendingprevout / getindexinfo).
-export([find_spender/2, tip_height/0]).

%% Startup reconciliation core, exported for standalone unit testing.
-export([reconcile_index/3]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

%% Key prefixes.
-define(P_SPEND, $s).
-define(P_META,  $M).

-define(META_TIP_HEIGHT, <<"tip_height">>).
-define(META_TIP_HASH,   <<"tip_hash">>).

-record(state, {
    db      :: rocksdb:db_handle() | undefined,
    enabled :: boolean()
}).

%% Decoded value of a spender-index entry.
-record(spender, {
    spending_txid :: binary(),   %% 32B internal byte order
    block_hash    :: binary(),   %% 32B internal byte order
    spending_tx   :: binary()    %% full wire-serialized spending tx (witness)
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

%% @doc True iff the txospenderindex is configured AND running.
-spec is_enabled() -> boolean().
is_enabled() ->
    case whereis(?SERVER) of
        undefined -> false;
        Pid when is_pid(Pid) ->
            case (catch gen_server:call(?SERVER, is_enabled, 5000)) of
                true -> true;
                _    -> false
            end
    end.

%% @doc Apply Block at Height to the index (Core CustomAppend): for every
%% non-coinbase input of every tx, write spent_outpoint -> spending tx.
%% Best-effort and gated on the gen_server being up; returns
%% {error, index_not_running} when not mounted so the chainstate connect
%% path can swallow it (wrapped in catch).
-spec add_block(#block{}, non_neg_integer()) -> ok | {error, term()}.
add_block(Block, Height) ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ -> gen_server:call(?SERVER, {add_block, Block, Height}, 60000)
    end.

%% @doc Roll back the disconnected block (Core CustomRemove): re-derive the
%% block's spend keys from its OWN inputs and erase them, then roll the tip
%% back to Height-1. Best-effort, default-off.
-spec remove_block(#block{}, non_neg_integer()) -> ok | {error, term()}.
remove_block(Block, Height) ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ -> gen_server:call(?SERVER, {remove_block, Block, Height}, 30000)
    end.

%% @doc Find the on-chain tx that spends (PrevTxid, PrevVout). Returns
%% {ok, #{spending_txid, block_hash, spending_tx}} if the outpoint has been
%% spent on-chain, or not_found if unspent on-chain (or disabled). Mirrors
%% Core's TxoSpenderIndex::FindSpender (std::nullopt when unspent).
-spec find_spender(binary(), non_neg_integer()) -> {ok, map()} | not_found.
find_spender(PrevTxid, PrevVout)
  when byte_size(PrevTxid) =:= 32, is_integer(PrevVout), PrevVout >= 0 ->
    case whereis(?SERVER) of
        undefined -> not_found;
        _ -> gen_server:call(?SERVER,
                             {find_spender, PrevTxid, PrevVout}, 30000)
    end;
find_spender(_, _) -> not_found.

%% @doc Highest height the index has reached, or -1 when empty/disabled.
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

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    case beamchain_config:txospenderindex_enabled() of
        false ->
            {ok, #state{db = undefined, enabled = false}};
        true ->
            DataDir = beamchain_config:datadir(),
            Path = filename:join([DataDir, "indexes", "txospender"]),
            ok = filelib:ensure_dir(filename:join(Path, "dummy")),
            Opts = [{create_if_missing, true}, {max_open_files, 64}],
            case rocksdb:open(Path, Opts) of
                {ok, Db} ->
                    logger:info("txospenderindex: opened ~s", [Path]),
                    %% Reconcile against the active chainstate BEFORE
                    %% serving -- identical crash-safety contract to the
                    %% coinstats/filter indexes: the index keeps its OWN
                    %% persisted tip written synchronously per block while
                    %% the chainstate flushes in batches; on an unclean
                    %% exit they diverge and a restart-replay re-firing
                    %% add_block for heights already present would be
                    %% inconsistent. Rewind to the highest common ancestor.
                    catch reconcile_with_chain(Db),
                    {ok, #state{db = Db, enabled = true}};
                {error, Reason} ->
                    logger:error("txospenderindex: open failed ~p", [Reason]),
                    {ok, #state{db = undefined, enabled = false}}
            end
    end.

handle_call(is_enabled, _From, State) ->
    {reply, State#state.enabled, State};

handle_call({add_block, _Block, _Height}, _From,
            #state{enabled = false} = State) ->
    {reply, {error, index_disabled}, State};
handle_call({add_block, Block, Height}, _From, #state{db = Db} = State) ->
    Reply =
        try
            do_add_block(Db, Block, Height)
        catch
            Class:Reason:_ST ->
                logger:warning("txospenderindex: add_block(~B) failed: ~p:~p",
                               [Height, Class, Reason]),
                {error, {Class, Reason}}
        end,
    {reply, Reply, State};

handle_call({remove_block, _Block, _Height}, _From,
            #state{enabled = false} = State) ->
    {reply, {error, index_disabled}, State};
handle_call({remove_block, Block, Height}, _From, #state{db = Db} = State) ->
    Reply =
        try
            do_remove_block(Db, Block, Height)
        catch
            Class:Reason:_ST ->
                logger:warning("txospenderindex: remove_block failed: ~p:~p",
                               [Class, Reason]),
                {error, {Class, Reason}}
        end,
    {reply, Reply, State};

handle_call({find_spender, PrevTxid, PrevVout}, _From,
            #state{db = Db} = State) ->
    {reply, lookup_spender(Db, PrevTxid, PrevVout), State};
handle_call(tip_height, _From, #state{db = Db} = State) ->
    {reply, {ok, read_tip_height(Db)}, State};
handle_call(_Msg, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) -> {noreply, State}.
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, #state{db = undefined}) -> ok;
terminate(_Reason, #state{db = Db}) ->
    catch rocksdb:close(Db),
    ok.

code_change(_Old, State, _Extra) -> {ok, State}.

%%% ===================================================================
%%% CustomAppend / CustomRemove
%%% ===================================================================

%% Re-derive every {outpoint-key, spending-tx} pair from a block's OWN
%% inputs. Mirrors Core BuildSpenderPositions: for each non-coinbase tx,
%% one entry per input. Both the connect (write) and disconnect (erase)
%% paths call this so the keys are a pure function of the block's inputs
%% (no undo data required, reorg-safe).
spender_entries(#block{transactions = Txs}) ->
    lists:flatten(
      [ [{spend_key(H, I), Tx}
         || #tx_in{prev_out = #outpoint{hash = H, index = I}}
                <- Tx#transaction.inputs]
        || Tx <- Txs,
           not beamchain_validation:is_coinbase_tx(Tx) ]).

do_add_block(Db, Block, Height) ->
    BlockHash = block_hash_internal(Block),
    %% Idempotency guard: if this exact height+hash is already the indexed
    %% tip, treat as a no-op (replay-safe). Core's BaseIndex never
    %% re-appends an already-indexed block.
    case {read_tip_height(Db), read_tip_hash(Db)} of
        {Height, BlockHash} ->
            ok;
        _ ->
            %% Genesis (height 0): the single coinbase has a null prevout,
            %% so there is nothing to index -- just record the best
            %% pointer (Core's CustomAppend writes nothing for a
            %% coinbase-only block).
            Entries = case Height of
                0 -> [];
                _ -> spender_entries(Block)
            end,
            lists:foreach(
              fun({Key, Tx}) ->
                  Rec = #spender{
                      spending_txid = beamchain_serialize:tx_hash(Tx),
                      block_hash    = BlockHash,
                      spending_tx   = serialize_tx(Tx)
                  },
                  ok = put_kv(Db, Key, encode_spender(Rec))
              end, Entries),
            set_tip(Db, Height, BlockHash),
            ok
    end.

do_remove_block(Db, Block, Height) when is_integer(Height), Height >= 0 ->
    %% RE-DERIVE the block's spend keys from its OWN inputs and erase them
    %% (Core CustomRemove(BuildSpenderPositions(block))). No undo needed.
    Entries = case Height of
        0 -> [];
        _ -> spender_entries(Block)
    end,
    lists:foreach(
      fun({Key, _Tx}) -> ok = delete_kv(Db, Key) end, Entries),
    %% Roll the tip back to Height-1 (or empty the index at genesis). The
    %% parent hash is the disconnected block's prev_hash.
    case Height of
        0 ->
            ok = delete_kv(Db, mkey(?META_TIP_HEIGHT)),
            ok = delete_kv(Db, mkey(?META_TIP_HASH));
        _ ->
            PrevHash = Block#block.header#block_header.prev_hash,
            set_tip(Db, Height - 1, PrevHash)
    end,
    ok;
do_remove_block(_Db, _Block, _Height) ->
    ok.

%%% ===================================================================
%%% Query
%%% ===================================================================

lookup_spender(undefined, _PrevTxid, _PrevVout) -> not_found;
lookup_spender(Db, PrevTxid, PrevVout) ->
    case get_kv(Db, spend_key(PrevTxid, PrevVout)) of
        {ok, Bin} ->
            #spender{spending_txid = STxid, block_hash = BH,
                     spending_tx = TxBin} = decode_spender(Bin),
            {ok, #{spending_txid => STxid,
                   block_hash    => BH,
                   spending_tx   => TxBin}};
        not_found ->
            not_found
    end.

%%% ===================================================================
%%% Startup reconciliation (BaseIndex::Init -> Rewind)
%%% ===================================================================

reconcile_with_chain(undefined) -> ok;
reconcile_with_chain(Db) ->
    case chain_tip_height() of
        not_found ->
            logger:debug("txospenderindex: chainstate tip unavailable, "
                         "skipping startup reconcile"),
            ok;
        {ok, ChainTipHeight} ->
            ChainHashFun =
                fun(Height) ->
                    case (catch beamchain_db:get_block_index(Height)) of
                        {ok, #{hash := Hash}} when byte_size(Hash) =:= 32 ->
                            {ok, Hash};
                        _ -> not_found
                    end
                end,
            reconcile_index(Db, ChainHashFun, ChainTipHeight)
    end.

chain_tip_height() ->
    case (catch beamchain_chainstate:get_tip()) of
        {ok, {_Hash, Height}} when is_integer(Height), Height >= 0 ->
            {ok, Height};
        _ -> not_found
    end.

%% @doc Rewind the persisted index to the highest common ancestor with the
%% active chain, then erase every disconnected block's spend keys above it.
%% Generic; ChainHashFun :: fun((H) -> {ok,Hash}|not_found).
-spec reconcile_index(rocksdb:db_handle() | undefined,
                      fun((non_neg_integer()) ->
                              {ok, binary()} | not_found),
                      integer()) -> ok.
reconcile_index(undefined, _ChainHashFun, _ChainTipHeight) -> ok;
reconcile_index(Db, ChainHashFun, ChainTipHeight) ->
    IndexTip = read_tip_height(Db),
    case IndexTip < 0 of
        true -> ok;  %% empty index -- nothing to reconcile
        false ->
            StartH = min(IndexTip, ChainTipHeight),
            Ancestor = find_common_ancestor(Db, ChainHashFun, StartH),
            case Ancestor < IndexTip of
                true ->
                    rewind_index_to(Db, IndexTip, Ancestor),
                    logger:info("txospenderindex: reconciled tip ~B -> ~B "
                                "(chain tip ~B, common ancestor ~B)",
                                [IndexTip, Ancestor, ChainTipHeight, Ancestor]),
                    ok;
                false -> ok
            end
    end.

%% The index stores only its tip hash, not a per-height hash chain, so the
%% common-ancestor walk compares the persisted-tip hash at the tip height
%% and otherwise rewinds purely on height (erasing each rewound block's
%% spend keys by reading the block back from the db). This matches Core's
%% BaseIndex::Init Rewind contract: never serve an index tip ahead of, or
%% forked from, the active chainstate.
find_common_ancestor(_Db, _ChainHashFun, H) when H < 0 -> -1;
find_common_ancestor(Db, ChainHashFun, H) ->
    IndexTipHeight = read_tip_height(Db),
    case H =:= IndexTipHeight of
        true ->
            case {read_tip_hash(Db), ChainHashFun(H)} of
                {Hash, {ok, Hash}} when byte_size(Hash) =:= 32 -> H;
                _ -> find_common_ancestor(Db, ChainHashFun, H - 1)
            end;
        false ->
            %% Below the index tip we cannot cheaply compare hashes (the
            %% index keeps no per-height hash). Any height at or below the
            %% chain tip that the chain also has is treated as the common
            %% ancestor -- erasing down to it is always safe (re-add on the
            %% next forward connect is idempotent).
            case ChainHashFun(H) of
                {ok, _} -> H;
                not_found -> find_common_ancestor(Db, ChainHashFun, H - 1)
            end
    end.

rewind_index_to(Db, IndexTip, Ancestor) when IndexTip > Ancestor ->
    lists:foreach(
      fun(H) ->
          %% Best-effort: a transient block-store unavailability during the
          %% boot-time rewind must not abort the whole reconcile -- worst
          %% case a few stale spender keys outlive the rewound block and are
          %% overwritten/idempotently re-asserted on the next forward
          %% connect. The tip pointer (below) is what guards correctness.
          case (catch beamchain_db:get_block_by_height(H)) of
              {ok, Block} ->
                  Entries = spender_entries(Block),
                  lists:foreach(
                    fun({Key, _Tx}) -> ok = delete_kv(Db, Key) end, Entries);
              _ ->
                  ok
          end
      end,
      lists:seq(Ancestor + 1, IndexTip)),
    case Ancestor < 0 of
        true ->
            ok = delete_kv(Db, mkey(?META_TIP_HEIGHT)),
            ok = delete_kv(Db, mkey(?META_TIP_HASH));
        false ->
            case (catch beamchain_db:get_block_by_height(Ancestor)) of
                {ok, B} -> set_tip(Db, Ancestor, block_hash_internal(B));
                _ -> ok = put_kv(Db, mkey(?META_TIP_HEIGHT),
                                 <<Ancestor:32/little>>)
            end
    end,
    ok;
rewind_index_to(_Db, _IndexTip, _Ancestor) -> ok.

%%% ===================================================================
%%% Spender record codec
%%% ===================================================================

%% Self-describing binary:
%%   spending_txid 32B | block_hash 32B | tx_len u32 BE | tx_bytes
encode_spender(#spender{spending_txid = STxid, block_hash = BH,
                        spending_tx = TxBin}) ->
    <<STxid:32/binary, BH:32/binary,
      (byte_size(TxBin)):32/big, TxBin/binary>>.

decode_spender(<<STxid:32/binary, BH:32/binary, Len:32/big, Rest/binary>>) ->
    <<TxBin:Len/binary, _/binary>> = Rest,
    #spender{spending_txid = STxid, block_hash = BH, spending_tx = TxBin}.

%%% ===================================================================
%%% Serialization helpers
%%% ===================================================================

%% Full wire-serialized spending tx (with witness when present), so
%% gettxspendingprevout's return_spending_tx can echo it byte-for-byte.
serialize_tx(Tx) ->
    beamchain_serialize:encode_transaction(Tx, witness).

%%% ===================================================================
%%% RocksDB key/value helpers
%%% ===================================================================

%% Outpoint key: txid(32, internal order) || vout(4 LE). Distinct
%% outpoints never collide; an outpoint is spent at most once on a chain.
spend_key(Txid, Vout) when byte_size(Txid) =:= 32 ->
    <<?P_SPEND, Txid:32/binary, Vout:32/little>>.

mkey(MK) -> <<?P_META, MK/binary>>.

set_tip(Db, Height, Hash) when byte_size(Hash) =:= 32 ->
    ok = put_kv(Db, mkey(?META_TIP_HEIGHT), <<Height:32/little>>),
    ok = put_kv(Db, mkey(?META_TIP_HASH), Hash),
    ok;
set_tip(Db, Height, _Hash) ->
    ok = put_kv(Db, mkey(?META_TIP_HEIGHT), <<Height:32/little>>),
    ok.

read_tip_height(undefined) -> -1;
read_tip_height(Db) ->
    case get_kv(Db, mkey(?META_TIP_HEIGHT)) of
        {ok, <<H:32/little>>} -> H;
        _ -> -1
    end.

read_tip_hash(undefined) -> undefined;
read_tip_hash(Db) ->
    case get_kv(Db, mkey(?META_TIP_HASH)) of
        {ok, <<H:32/binary>>} -> H;
        _ -> undefined
    end.

put_kv(undefined, _K, _V) -> ok;
put_kv(Db, K, V) -> rocksdb:put(Db, K, V, []).

delete_kv(undefined, _K) -> ok;
delete_kv(Db, K) -> rocksdb:delete(Db, K, []).

get_kv(undefined, _K) -> not_found;
get_kv(Db, K) ->
    case rocksdb:get(Db, K, []) of
        {ok, V} -> {ok, V};
        not_found -> not_found
    end.

block_hash_internal(#block{hash = H}) when byte_size(H) =:= 32 -> H;
block_hash_internal(#block{header = Header}) ->
    beamchain_serialize:block_hash(Header).
