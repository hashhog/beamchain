-module(beamchain_coinstatsindex).
-behaviour(gen_server).

%%% -------------------------------------------------------------------
%%% Persistent, reorg-safe coinstatsindex (Bitcoin Core -coinstatsindex).
%%%
%%% Maintains a PER-HEIGHT running UTXO-set commitment so that
%%% `gettxoutsetinfo ("muhash"|"none") <hash_or_height>` can be answered
%%% AS OF any historical block, byte-identical to Bitcoin Core. Mirrors
%%% bitcoin-core/src/index/coinstatsindex.cpp (CustomAppend / CustomRemove
%%% / RevertBlock) and kernel/coinstats.cpp (TxOutSer / MuHash).
%%%
%%% The index is the exact structural analogue of
%%% beamchain_blockfilter_index: a default-off gen_server with its own
%%% RocksDB instance, hooked at the SAME primary block connect/disconnect
%%% points in beamchain_chainstate (so it stays correct through reorgs,
%%% invalidateblock and reconsiderblock automatically — those all reuse
%%% do_connect_block / do_disconnect_block). It does NOT touch the
%%% submitblock RPC path specially; connect/disconnect is the single
%%% canonical maintenance site, exactly like txindex/blockfilterindex.
%%%
%%% Per-block running state (all CUMULATIVE since genesis), Core's DBVal:
%%%   - muhash               (un-finalized MuHash3072 accumulator)
%%%   - transaction_output_count  (== gettxoutsetinfo `txouts`)
%%%   - bogo_size            (== `bogosize`)
%%%   - total_amount         (Σ unspent nValue, sat)
%%%   - total_subsidy        (Σ GetBlockSubsidy over all blocks)
%%%   - total_prevout_spent_amount
%%%   - total_new_outputs_ex_coinbase_amount
%%%   - total_coinbase_amount
%%%   - total_unspendables_{genesis_block,bip30,scripts,unclaimed_rewards}
%%%
%%% Storage layout: <datadir>/indexes/coinstats/  (its own RocksDB)
%%%   Key prefixes (1 byte), mirroring db_key.h:
%%%     't' || height (4B BE)   -> serialized DBVal  (height index)
%%%     's' || block_hash (32B) -> serialized DBVal  (hash index; written
%%%                                 for disconnected blocks so a historical
%%%                                 query by an orphan hash still resolves)
%%%     'r' || block_hash (32B) -> 4B LE height      (reverse hash->height)
%%%     'M' || meta_key         -> meta_value
%%%       meta_key = "tip_height" -> 4B LE height
%%%
%%% This module is started ONLY when BEAMCHAIN_COINSTATSINDEX=1 (or
%%% coinstatsindex=1 in the config). When disabled it stays alive but
%%% inert (db = undefined, enabled = false) so the supervisor keeps it
%%% mounted under the standard rest_for_one tree and callers can probe
%%% is_enabled/0 without crashing.
%%% -------------------------------------------------------------------

-include("beamchain.hrl").

-export([start_link/0, stop/0, is_enabled/0]).

%% Maintenance ops (hooked from chainstate connect/disconnect).
-export([add_block/2, add_block/3, remove_block/1, remove_block/2]).

%% Query ops (gettxoutsetinfo at-height; getindexinfo).
-export([lookup_by_height/1, lookup_by_hash/1, tip_height/0]).

%% Startup reconciliation core, exported for standalone unit testing
%% (drive a synthetic active chain without the full chainstate + db tree).
-export([reconcile_index/3]).

%% Exported for unit testing only.
-export([is_bip30_unspendable/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

%% Key prefixes (db_key.h: DBHeightKey 't', DBHashKey 's').
-define(P_HEIGHT,         $t).
-define(P_HASH,           $s).
-define(P_HASH_TO_HEIGHT, $r).
-define(P_META,           $M).

-define(META_TIP_HEIGHT, <<"tip_height">>).

-record(state, {
    db      :: rocksdb:db_handle() | undefined,
    enabled :: boolean()
}).

%% Per-height DBVal — the full cumulative state Core persists per block.
%% Stored as a self-describing tagged binary (see encode_dbval/1).
-record(dbval, {
    block_hash                          :: binary(),  %% 32B internal order
    muhash                              :: binary(),  %% 768B serialized acc
    txouts            = 0               :: non_neg_integer(),
    bogosize          = 0               :: non_neg_integer(),
    total_amount      = 0               :: integer(),  %% sat
    total_subsidy     = 0               :: integer(),
    total_prevout_spent = 0             :: integer(),
    total_new_outputs = 0               :: integer(),
    total_coinbase    = 0               :: integer(),
    uns_genesis       = 0               :: integer(),
    uns_bip30         = 0               :: integer(),
    uns_scripts       = 0               :: integer(),
    uns_unclaimed     = 0               :: integer()
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

%% @doc True iff the coinstatsindex is configured AND running.
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

%% @doc Apply Block at Height to the running index (Core CustomAppend).
%% Best-effort and gated on the gen_server being up; returns
%% {error, index_not_running} when the index is not mounted so the
%% chainstate connect path can swallow it (it is wrapped in catch).
-spec add_block(#block{}, non_neg_integer()) -> ok | {error, term()}.
add_block(Block, Height) ->
    add_block(Block, Height, undefined).

%% @doc add_block/2 with an explicit list of spent-prevout coins for the
%% block, in forward (tx, input) order skipping the coinbase. Each entry
%% is {Txid, Vout, #utxo{}} — the coin being spent. Used on the connect
%% path where undo data has not yet been flushed to disk; when undefined
%% the index reads the on-disk undo via beamchain_db:get_undo/1.
-spec add_block(#block{}, non_neg_integer(),
                [{binary(), non_neg_integer(), #utxo{}}] | undefined) ->
    ok | {error, term()}.
add_block(Block, Height, SpentCoins) ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ -> gen_server:call(?SERVER,
                             {add_block, Block, Height, SpentCoins}, 60000)
    end.

%% @doc Roll back the disconnected tip block (Core CustomRemove +
%% RevertBlock): copy its DBVal to the hash index, delete the height
%% entry, and reset the tip to Height-1 (whose stored DBVal is already
%% the correct rolled-back state). Best-effort, default-off.
-spec remove_block(binary(), non_neg_integer()) -> ok | {error, term()}.
remove_block(BlockHash, Height) ->
    case whereis(?SERVER) of
        undefined -> {error, index_not_running};
        _ -> gen_server:call(?SERVER,
                             {remove_block, BlockHash, Height}, 30000)
    end.

remove_block(BlockHash) ->
    remove_block(BlockHash, undefined).

%% @doc Look up the per-height stats AS OF Height. Returns a map shaped
%% for the gettxoutsetinfo index path, or not_found if the index has not
%% synced to that height. `not_found` also when disabled.
-spec lookup_by_height(non_neg_integer()) -> {ok, map()} | not_found.
lookup_by_height(Height) when is_integer(Height), Height >= 0 ->
    case whereis(?SERVER) of
        undefined -> not_found;
        _ -> gen_server:call(?SERVER, {lookup_by_height, Height}, 30000)
    end;
lookup_by_height(_) -> not_found.

%% @doc Look up the per-height stats AS OF the block BlockHash (height or
%% hash index). Returns {ok, Map} | not_found.
-spec lookup_by_hash(binary()) -> {ok, map()} | not_found.
lookup_by_hash(BlockHash) when byte_size(BlockHash) =:= 32 ->
    case whereis(?SERVER) of
        undefined -> not_found;
        _ -> gen_server:call(?SERVER, {lookup_by_hash, BlockHash}, 30000)
    end;
lookup_by_hash(_) -> not_found.

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
    case beamchain_config:coinstatsindex_enabled() of
        false ->
            {ok, #state{db = undefined, enabled = false}};
        true ->
            DataDir = beamchain_config:datadir(),
            Path = filename:join([DataDir, "indexes", "coinstats"]),
            ok = filelib:ensure_dir(filename:join(Path, "dummy")),
            Opts = [{create_if_missing, true}, {max_open_files, 64}],
            case rocksdb:open(Path, Opts) of
                {ok, Db} ->
                    logger:info("coinstatsindex: opened ~s", [Path]),
                    %% Genesis (height 0) is processed exactly like Core
                    %% CustomAppend: its coinbase output is unspendable for
                    %% the UTXO commitment, so the genesis muhash is the
                    %% empty accumulator. chainstate connects genesis during
                    %% its own init — which runs BEFORE this gen_server is
                    %% started by node_sup — so the genesis add_block call is
                    %% a no-op (index not yet running). Seed it once on a
                    %% fresh index so the per-height chain is anchored at 0.
                    maybe_index_genesis(Db),
                    %% Reconcile against the active chainstate BEFORE serving
                    %% — identical crash-safety contract to the filter index:
                    %% the index keeps its OWN persisted tip written
                    %% synchronously per block while the chainstate flushes in
                    %% batches; on an unclean exit they diverge and a
                    %% restart-replay re-firing add_block for heights already
                    %% present would corrupt the accumulator chain. Rewind to
                    %% the highest common ancestor first.
                    catch reconcile_with_chain(Db),
                    {ok, #state{db = Db, enabled = true}};
                {error, Reason} ->
                    logger:error("coinstatsindex: open failed ~p", [Reason]),
                    {ok, #state{db = undefined, enabled = false}}
            end
    end.

handle_call(is_enabled, _From, State) ->
    {reply, State#state.enabled, State};

handle_call({add_block, _Block, _Height, _Spent}, _From,
            #state{enabled = false} = State) ->
    {reply, {error, index_disabled}, State};
handle_call({add_block, Block, Height, SpentCoins}, _From,
            #state{db = Db} = State) ->
    Reply =
        try
            do_add_block(Db, Block, Height, SpentCoins)
        catch
            Class:Reason:_ST ->
                logger:warning("coinstatsindex: add_block(~B) failed: ~p:~p",
                               [Height, Class, Reason]),
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
            do_remove_block(Db, BlockHash, Height)
        catch
            Class:Reason:_ST ->
                logger:warning("coinstatsindex: remove_block failed: ~p:~p",
                               [Class, Reason]),
                {error, {Class, Reason}}
        end,
    {reply, Reply, State};

handle_call({lookup_by_height, Height}, _From, #state{db = Db} = State) ->
    {reply, lookup_height_stats(Db, Height), State};
handle_call({lookup_by_hash, BlockHash}, _From, #state{db = Db} = State) ->
    {reply, lookup_hash_stats(Db, BlockHash), State};
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
%%% CustomAppend — forward block application
%%% ===================================================================

%% Seed the genesis DBVal on a fresh index (Core processes height 0 with
%% no tx output added; total_subsidy += subsidy(0); the genesis coinbase
%% reward becomes total_unspendables_genesis_block). Idempotent: skipped
%% if the index already holds any entry.
maybe_index_genesis(undefined) -> ok;
maybe_index_genesis(Db) ->
    case read_tip_height(Db) of
        H when is_integer(H), H >= 0 ->
            ok;  %% already populated — never re-seed
        _ ->
            try
                Network = beamchain_config:network(),
                Genesis = beamchain_chain_params:genesis_block(Network),
                GHash = block_hash_internal(Genesis),
                Subsidy = block_subsidy(0),
                DBVal = #dbval{
                    block_hash    = GHash,
                    muhash        = beamchain_muhash:serialize(
                                      beamchain_muhash:new()),
                    txouts        = 0,
                    bogosize      = 0,
                    total_amount  = 0,
                    total_subsidy = Subsidy,
                    uns_genesis   = Subsidy
                },
                write_height_dbval(Db, 0, DBVal),
                logger:info("coinstatsindex: seeded genesis DBVal"),
                ok
            catch
                Class:Reason:_ST ->
                    logger:warning("coinstatsindex: genesis seed failed: "
                                   "~p:~p", [Class, Reason]),
                    ok
            end
    end.

do_add_block(Db, Block, Height, SpentCoins) ->
    BlockHash = block_hash_internal(Block),
    %% Idempotency / continuity guard: if this exact height is already
    %% indexed with this hash, treat as a no-op (replay-safe). Core's
    %% BaseIndex never re-appends an already-indexed block.
    case lookup_height_dbval(Db, Height) of
        {ok, #dbval{block_hash = BlockHash}} ->
            ok;
        _ ->
            Prev = prev_dbval(Db, Height, Block),
            DBVal = apply_block(Block, Height, BlockHash, SpentCoins, Prev),
            write_height_dbval(Db, Height, DBVal),
            ok = put_kv(Db, rkey(BlockHash), <<Height:32/little>>),
            ok = put_kv(Db, mkey(?META_TIP_HEIGHT), <<Height:32/little>>),
            ok
    end.

%% Resolve the parent DBVal to build height H upon. At H=0 there is no
%% parent (empty accumulator + zero counters). At H>0 the parent is the
%% DBVal stored at H-1; on a fresh/just-rewound index that is the correct
%% rolled-back state.
prev_dbval(_Db, 0, _Block) ->
    #dbval{block_hash = <<0:256>>,
           muhash = beamchain_muhash:serialize(beamchain_muhash:new())};
prev_dbval(Db, Height, _Block) ->
    case lookup_height_dbval(Db, Height - 1) of
        {ok, DBVal} -> DBVal;
        not_found ->
            %% No parent indexed yet — start from empty. This should not
            %% happen on the canonical connect path (blocks arrive in
            %% order) but keeps us robust rather than crashing the connect.
            #dbval{block_hash = <<0:256>>,
                   muhash = beamchain_muhash:serialize(
                              beamchain_muhash:new())}
    end.

%% Build the new DBVal for Block at Height from the parent DBVal Prev.
%% Mirrors index/coinstatsindex.cpp:108-212 exactly.
apply_block(#block{transactions = Txs}, Height, BlockHash, SpentCoins, Prev) ->
    Subsidy = block_subsidy(Height),
    Acc0 = beamchain_muhash:deserialize(Prev#dbval.muhash),
    Base = Prev#dbval{
        block_hash    = BlockHash,
        total_subsidy = Prev#dbval.total_subsidy + Subsidy
    },
    Final =
        case Height of
            0 ->
                %% Genesis: skip all tx processing; the subsidy is the
                %% genesis-block unspendable.
                Base#dbval{
                    muhash      = beamchain_muhash:serialize(Acc0),
                    uns_genesis = Base#dbval.uns_genesis + Subsidy
                };
            _ ->
                Spents = resolve_spent_coins(Txs, SpentCoins, BlockHash),
                {Acc1, Acc} = apply_txs2(Txs, Height, BlockHash, Subsidy,
                                         Spents, Acc0, Base),
                Acc#dbval{muhash = beamchain_muhash:serialize(Acc1)}
        end,
    %% Unclaimed rewards (every block; CustomAppend:181-188):
    %%   unclaimed = (prevout_spent + subsidy_total)
    %%             - (new_outputs + coinbase + temp_unspendable)
    %% where temp_unspendable = genesis + bip30 + scripts + prior_unclaimed.
    TempUnspendable = Final#dbval.uns_genesis + Final#dbval.uns_bip30
        + Final#dbval.uns_scripts + Final#dbval.uns_unclaimed,
    Unclaimed = (Final#dbval.total_prevout_spent + Final#dbval.total_subsidy)
        - (Final#dbval.total_new_outputs + Final#dbval.total_coinbase
           + TempUnspendable),
    UnclaimedNonNeg = max(0, Unclaimed),
    Final#dbval{uns_unclaimed = Final#dbval.uns_unclaimed + UnclaimedNonNeg}.

%% Fold every tx in forward order, threading the muhash accumulator, the
%% (cumulative) DBVal counters AND the remaining spent-prevout list (the
%% coinbase-excluded {Txid,Vout,#utxo} coins in forward (tx,input) order,
%% consumed left to right). Returns {FinalAcc, FinalDBVal}.
%% Core CustomAppend:121-174.
%%
%% BlockHash and Subsidy are threaded for the BIP30 duplicate-coinbase skip
%% (Core:128-131): at mainnet heights 91722 and 91812 the coinbase txids
%% duplicate an earlier coinbase whose outputs became unspendable, so the
%% entire coinbase must be skipped from the muhash / txouts / total_amount /
%% total_coinbase and its value charged to uns_bip30 instead.
apply_txs2([], _Height, _BlockHash, _Subsidy, _Spents, Acc, DBVal) ->
    {Acc, DBVal};
apply_txs2([Tx | Rest], Height, BlockHash, Subsidy, Spents, Acc, DBVal) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    IsCoinbase = beamchain_validation:is_coinbase_tx(Tx),
    case IsCoinbase andalso is_bip30_unspendable(Height, BlockHash) of
        true ->
            %% Skip duplicate-coinbase outputs (BIP30): they overwrote the
            %% prior coinbase, so those earlier outputs are unspendable.
            %% Charge the block subsidy to uns_bip30 and continue.
            %% (Core index/coinstatsindex.cpp:128-131)
            DV1 = DBVal#dbval{uns_bip30 = DBVal#dbval.uns_bip30 + Subsidy},
            apply_txs2(Rest, Height, BlockHash, Subsidy, Spents, Acc, DV1);
        false ->
            {Acc1, DV1} = add_outputs(Tx, Txid, Height, IsCoinbase, Acc, DBVal),
            case IsCoinbase of
                true ->
                    apply_txs2(Rest, Height, BlockHash, Subsidy,
                               Spents, Acc1, DV1);
                false ->
                    NInputs = length(Tx#transaction.inputs),
                    {TxSpents, RestSpents} = take_n(NInputs, Spents),
                    {Acc2, DV2} = remove_prevouts(TxSpents, Acc1, DV1),
                    apply_txs2(Rest, Height, BlockHash, Subsidy,
                               RestSpents, Acc2, DV2)
            end
    end.

%% @doc True iff this block contains a duplicate coinbase whose outputs
%% overwrote (and made unspendable) the earlier coinbase at the same txid.
%% These are the two mainnet blocks identified by Core's IsBIP30Unspendable()
%% (validation.cpp:6195-6199). Block hashes are in INTERNAL byte order
%% (little-endian / reversed from the display hex), matching block_hash_internal/1.
%% Display-hex to internal-order (bytes.fromhex(h)[::-1]):
%%   91722 display: "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
%%   91722 internal: 8e d0 4d 57 f2 f3 cd c6 a6 e5 55 69 dc 16 54 e1
%%                   f2 19 84 7f 66 e7 26 dc a2 71 02 00 00 00 00 00
%%   91812 display: "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
%%   91812 internal: 2f 6f 30 f9 d6 83 de b8 5d 93 14 ef 5d cf 36 af
%%                   66 d9 e3 ce 1a 2b 79 d4 ae f0 0a 00 00 00 00 00
-spec is_bip30_unspendable(non_neg_integer(), binary()) -> boolean().
is_bip30_unspendable(91722,
        <<16#8e, 16#d0, 16#4d, 16#57, 16#f2, 16#f3, 16#cd, 16#c6,
          16#a6, 16#e5, 16#55, 16#69, 16#dc, 16#16, 16#54, 16#e1,
          16#f2, 16#19, 16#84, 16#7f, 16#66, 16#e7, 16#26, 16#dc,
          16#a2, 16#71, 16#02, 16#00, 16#00, 16#00, 16#00, 16#00>>) -> true;
is_bip30_unspendable(91812,
        <<16#2f, 16#6f, 16#30, 16#f9, 16#d6, 16#83, 16#de, 16#b8,
          16#5d, 16#93, 16#14, 16#ef, 16#5d, 16#cf, 16#36, 16#af,
          16#66, 16#d9, 16#e3, 16#ce, 16#1a, 16#2b, 16#79, 16#d4,
          16#ae, 16#f0, 16#0a, 16#00, 16#00, 16#00, 16#00, 16#00>>) -> true;
is_bip30_unspendable(_, _) -> false.

%% Add a tx's created outputs to the accumulator + counters.
add_outputs(#transaction{outputs = Outs}, Txid, Height, IsCoinbase, Acc, DV) ->
    {_, AccF, DVF} =
        lists:foldl(
          fun(#tx_out{value = Value, script_pubkey = SPK}, {Vout, A, D}) ->
              case beamchain_chainstate:is_unspendable_script(SPK) of
                  true ->
                      %% Unspendable (OP_RETURN at 0 OR script > MAX_SIZE):
                      %% NOT inserted into muhash, NOT counted; value goes to
                      %% uns_scripts. (coinstatsindex.cpp:140-143)
                      {Vout + 1, A,
                       D#dbval{uns_scripts = D#dbval.uns_scripts + Value}};
                  false ->
                      Utxo = #utxo{value = Value, script_pubkey = SPK,
                                   is_coinbase = IsCoinbase, height = Height},
                      A1 = beamchain_snapshot:txoutset_muhash_apply(
                             add, {Txid, Vout, Utxo}, A),
                      Bogo = 50 + byte_size(SPK),
                      D1 = D#dbval{
                          txouts       = D#dbval.txouts + 1,
                          bogosize     = D#dbval.bogosize + Bogo,
                          total_amount = D#dbval.total_amount + Value
                      },
                      D2 = case IsCoinbase of
                          true ->
                              D1#dbval{total_coinbase =
                                           D1#dbval.total_coinbase + Value};
                          false ->
                              D1#dbval{total_new_outputs =
                                           D1#dbval.total_new_outputs + Value}
                      end,
                      {Vout + 1, A1, D2}
              end
          end,
          {0, Acc, DV},
          Outs),
    {AccF, DVF}.

%% Remove a non-coinbase tx's spent prevouts (Core CustomAppend:158-174).
%% Spent prevouts are removed unconditionally (no IsUnspendable filter —
%% they were spendable by definition since they appear in undo data).
remove_prevouts(TxSpents, Acc, DV) ->
    lists:foldl(
      fun({Txid, Vout, #utxo{value = Value, script_pubkey = SPK} = Utxo},
          {A, D}) ->
          A1 = beamchain_snapshot:txoutset_muhash_apply(
                 remove, {Txid, Vout, Utxo}, A),
          Bogo = 50 + byte_size(SPK),
          D1 = D#dbval{
              txouts              = D#dbval.txouts - 1,
              bogosize            = D#dbval.bogosize - Bogo,
              total_amount        = D#dbval.total_amount - Value,
              total_prevout_spent = D#dbval.total_prevout_spent + Value
          },
          {A1, D1}
      end,
      {Acc, DV},
      TxSpents).

%% Resolve the list of spent-prevout coins for this block in forward
%% (tx, input) order excluding the coinbase. If the caller supplied them
%% (connect path), use as-is; otherwise read the on-disk undo data and
%% decode it into {Txid, Vout, #utxo{}} tuples (the same shape).
resolve_spent_coins(_Txs, SpentCoins, _BlockHash) when is_list(SpentCoins) ->
    SpentCoins;
resolve_spent_coins(Txs, undefined, BlockHash) ->
    case beamchain_db:get_undo(BlockHash) of
        {ok, UndoBin} ->
            Undo = beamchain_validation:decode_undo_data(UndoBin),
            %% Undo is a flat list of {#outpoint{}, #utxo{}} in forward
            %% (non-coinbase tx, input) order — exactly what we need.
            [{H, I, Coin}
             || {#outpoint{hash = H, index = I}, Coin} <- Undo];
        not_found ->
            %% No undo (e.g. a block with only a coinbase). If there are
            %% non-coinbase inputs we cannot proceed — but the genesis /
            %% coinbase-only case has no prevouts, so [] is correct.
            HasNonCoinbaseInputs =
                lists:any(
                  fun(Tx) ->
                      not beamchain_validation:is_coinbase_tx(Tx)
                  end, Txs),
            case HasNonCoinbaseInputs of
                false -> [];
                true -> throw(missing_undo_data)
            end
    end.

%%% ===================================================================
%%% CustomRemove / RevertBlock — disconnect / reorg rollback
%%% ===================================================================

%% Core CustomRemove (coinstatsindex.cpp:216-234):
%%   1. CopyHeightIndexToHashIndex: preserve the disconnected block's
%%      DBVal under its HASH key so a later query by that (now orphan)
%%      hash still resolves.
%%   2. Delete the height entry + reverse-index entry, roll the tip back
%%      to Height-1. The DBVal at Height-1 is already the correct
%%      rolled-back state (RevertBlock restores counters from the parent's
%%      stored DBVal), so there is nothing to recompute here — the next
%%      connect rebuilds height H from the verified parent.
do_remove_block(Db, BlockHash, Height) ->
    case Height of
        H when is_integer(H), H >= 0 ->
            %% Copy height->DBVal to the hash index (orphan stays queryable).
            case lookup_height_dbval(Db, H) of
                {ok, DBVal} ->
                    ok = put_kv(Db, skey(DBVal#dbval.block_hash),
                                encode_dbval(DBVal));
                not_found ->
                    ok
            end,
            ok = delete_kv(Db, height_key(H)),
            case BlockHash of
                B when byte_size(B) =:= 32 ->
                    ok = delete_kv(Db, rkey(B));
                _ -> ok
            end,
            %% Roll the tip back to H-1 (or empty the index at genesis).
            case H of
                0 -> ok = delete_kv(Db, mkey(?META_TIP_HEIGHT));
                _ -> ok = put_kv(Db, mkey(?META_TIP_HEIGHT),
                                 <<(H - 1):32/little>>)
            end,
            ok;
        _ ->
            %% No height given — best-effort: drop the reverse index entry.
            case BlockHash of
                B when byte_size(B) =:= 32 -> delete_kv(Db, rkey(B));
                _ -> ok
            end,
            ok
    end.

%%% ===================================================================
%%% Query — shape the stored DBVal for the gettxoutsetinfo index path
%%% ===================================================================

%% Build the per-height response map for gettxoutsetinfo. Includes the
%% finalized muhash digest (raw 32B internal order — caller reverses for
%% display hex) and the fields the at-height index path emits. block_info
%% deltas are computed against the parent DBVal.
lookup_height_stats(Db, Height) ->
    case lookup_height_dbval(Db, Height) of
        {ok, DBVal} -> {ok, stats_map(Db, Height, DBVal)};
        not_found -> not_found
    end.

lookup_hash_stats(Db, BlockHash) ->
    case lookup_height_internal(Db, BlockHash) of
        {ok, Height} ->
            case lookup_height_dbval(Db, Height) of
                {ok, DBVal} -> {ok, stats_map(Db, Height, DBVal)};
                not_found -> lookup_hash_index_stats(Db, BlockHash)
            end;
        not_found ->
            lookup_hash_index_stats(Db, BlockHash)
    end.

lookup_hash_index_stats(Db, BlockHash) ->
    case get_kv(Db, skey(BlockHash)) of
        {ok, Bin} ->
            DBVal = decode_dbval(Bin),
            %% For an orphan-by-hash entry there is no reliable height in
            %% the live height index; report stats without block_info
            %% deltas. (Harness only queries by height.)
            {ok, base_stats_map(undefined, DBVal)};
        not_found ->
            not_found
    end.

stats_map(Db, Height, DBVal) ->
    Base = base_stats_map(Height, DBVal),
    %% block_info deltas vs the parent cumulative DBVal (Core:1132-1138).
    Prev = case Height of
        0 -> #dbval{muhash = beamchain_muhash:serialize(
                               beamchain_muhash:new())};
        _ ->
            case lookup_height_dbval(Db, Height - 1) of
                {ok, P} -> P;
                not_found -> #dbval{}
            end
    end,
    TotalUnspendable = DBVal#dbval.uns_genesis + DBVal#dbval.uns_bip30
        + DBVal#dbval.uns_scripts + DBVal#dbval.uns_unclaimed,
    PrevUnspendable = Prev#dbval.uns_genesis + Prev#dbval.uns_bip30
        + Prev#dbval.uns_scripts + Prev#dbval.uns_unclaimed,
    BlockInfo = #{
        prevout_spent => DBVal#dbval.total_prevout_spent
                         - Prev#dbval.total_prevout_spent,
        coinbase => DBVal#dbval.total_coinbase - Prev#dbval.total_coinbase,
        new_outputs_ex_coinbase => DBVal#dbval.total_new_outputs
                                   - Prev#dbval.total_new_outputs,
        unspendable => TotalUnspendable - PrevUnspendable,
        unspendables => #{
            genesis_block => DBVal#dbval.uns_genesis - Prev#dbval.uns_genesis,
            bip30 => DBVal#dbval.uns_bip30 - Prev#dbval.uns_bip30,
            scripts => DBVal#dbval.uns_scripts - Prev#dbval.uns_scripts,
            unclaimed_rewards => DBVal#dbval.uns_unclaimed
                                 - Prev#dbval.uns_unclaimed
        }
    },
    Base#{total_unspendable_amount => TotalUnspendable,
          block_info => BlockInfo}.

base_stats_map(Height, DBVal) ->
    Acc = beamchain_muhash:deserialize(DBVal#dbval.muhash),
    #{
        height       => Height,
        block_hash   => DBVal#dbval.block_hash,
        txouts       => DBVal#dbval.txouts,
        bogosize     => DBVal#dbval.bogosize,
        total_amount => DBVal#dbval.total_amount,
        muhash       => beamchain_muhash:finalize(Acc)
    }.

%%% ===================================================================
%%% Startup reconciliation (BaseIndex::Init -> Rewind)
%%% ===================================================================

reconcile_with_chain(undefined) -> ok;
reconcile_with_chain(Db) ->
    case chain_tip_height() of
        not_found ->
            logger:debug("coinstatsindex: chainstate tip unavailable, "
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
%% active chain, then drop every entry above it. Generic; lifted from the
%% blockfilter index. ChainHashFun :: fun((H) -> {ok,Hash}|not_found).
-spec reconcile_index(rocksdb:db_handle() | undefined,
                      fun((non_neg_integer()) ->
                              {ok, binary()} | not_found),
                      integer()) -> ok.
reconcile_index(undefined, _ChainHashFun, _ChainTipHeight) -> ok;
reconcile_index(Db, ChainHashFun, ChainTipHeight) ->
    IndexTip = read_tip_height(Db),
    case IndexTip < 0 of
        true -> ok;  %% empty index — nothing to reconcile
        false ->
            StartH = min(IndexTip, ChainTipHeight),
            Ancestor = find_common_ancestor(Db, ChainHashFun, StartH),
            case Ancestor < IndexTip of
                true ->
                    rewind_index_to(Db, IndexTip, Ancestor),
                    logger:info("coinstatsindex: reconciled tip ~B -> ~B "
                                "(chain tip ~B, common ancestor ~B)",
                                [IndexTip, Ancestor, ChainTipHeight, Ancestor]),
                    ok;
                false -> ok
            end
    end.

find_common_ancestor(_Db, _ChainHashFun, H) when H < 0 -> -1;
find_common_ancestor(Db, ChainHashFun, H) ->
    case {lookup_height_hash(Db, H), ChainHashFun(H)} of
        {{ok, Hash}, {ok, Hash}} -> H;
        _ -> find_common_ancestor(Db, ChainHashFun, H - 1)
    end.

rewind_index_to(Db, IndexTip, Ancestor) when IndexTip > Ancestor ->
    lists:foreach(
      fun(H) ->
          case lookup_height_dbval(Db, H) of
              {ok, #dbval{block_hash = BH}} ->
                  ok = delete_kv(Db, rkey(BH));
              not_found -> ok
          end,
          ok = delete_kv(Db, height_key(H))
      end,
      lists:seq(Ancestor + 1, IndexTip)),
    set_tip_meta(Db, Ancestor),
    ok;
rewind_index_to(_Db, _IndexTip, _Ancestor) -> ok.

set_tip_meta(Db, H) when H < 0 ->
    ok = delete_kv(Db, mkey(?META_TIP_HEIGHT)),
    ok;
set_tip_meta(Db, H) ->
    ok = put_kv(Db, mkey(?META_TIP_HEIGHT), <<H:32/little>>),
    ok.

%%% ===================================================================
%%% Subsidy
%%% ===================================================================

%% GetBlockSubsidy via the canonical chain-params schedule (50 BTC start,
%% halving every subsidy_halving_interval). Used only for the cumulative
%% total_subsidy / unclaimed-rewards accounting (block_info /
%% total_unspendable_amount) — the muhash / txouts / total_amount fields
%% depend solely on the UTXO set, not subsidy.
block_subsidy(Height) ->
    beamchain_chain_params:block_subsidy(Height, beamchain_config:network()).

%%% ===================================================================
%%% DBVal codec
%%% ===================================================================

%% Self-describing tagged binary. Field order is fixed; integers are
%% signed 64-bit (counters can never legitimately exceed that). The muhash
%% accumulator is a 768-byte blob.
encode_dbval(#dbval{block_hash = BH, muhash = MH,
                    txouts = TO, bogosize = BG, total_amount = TA,
                    total_subsidy = TS, total_prevout_spent = TP,
                    total_new_outputs = TN, total_coinbase = TC,
                    uns_genesis = UG, uns_bip30 = UB,
                    uns_scripts = US, uns_unclaimed = UU}) ->
    <<BH:32/binary,
      MH:768/binary,
      TO:64/big,
      BG:64/big,
      TA:64/big-signed,
      TS:64/big-signed,
      TP:64/big-signed,
      TN:64/big-signed,
      TC:64/big-signed,
      UG:64/big-signed,
      UB:64/big-signed,
      US:64/big-signed,
      UU:64/big-signed>>.

decode_dbval(<<BH:32/binary, MH:768/binary,
               TO:64/big, BG:64/big,
               TA:64/big-signed, TS:64/big-signed, TP:64/big-signed,
               TN:64/big-signed, TC:64/big-signed,
               UG:64/big-signed, UB:64/big-signed,
               US:64/big-signed, UU:64/big-signed>>) ->
    #dbval{block_hash = BH, muhash = MH,
           txouts = TO, bogosize = BG, total_amount = TA,
           total_subsidy = TS, total_prevout_spent = TP,
           total_new_outputs = TN, total_coinbase = TC,
           uns_genesis = UG, uns_bip30 = UB,
           uns_scripts = US, uns_unclaimed = UU}.

%%% ===================================================================
%%% RocksDB key/value helpers
%%% ===================================================================

write_height_dbval(Db, Height, DBVal) ->
    put_kv(Db, height_key(Height), encode_dbval(DBVal)).

lookup_height_dbval(undefined, _) -> not_found;
lookup_height_dbval(Db, Height) when is_integer(Height), Height >= 0 ->
    case get_kv(Db, height_key(Height)) of
        {ok, Bin} -> {ok, decode_dbval(Bin)};
        not_found -> not_found
    end;
lookup_height_dbval(_, _) -> not_found.

lookup_height_hash(Db, Height) ->
    case lookup_height_dbval(Db, Height) of
        {ok, #dbval{block_hash = BH}} -> {ok, BH};
        not_found -> not_found
    end.

lookup_height_internal(undefined, _) -> not_found;
lookup_height_internal(Db, BlockHash) when byte_size(BlockHash) =:= 32 ->
    case get_kv(Db, rkey(BlockHash)) of
        {ok, <<H:32/little>>} -> {ok, H};
        _ -> not_found
    end;
lookup_height_internal(_, _) -> not_found.

height_key(H) when is_integer(H), H >= 0 -> <<?P_HEIGHT, H:32/big>>.
skey(BH) -> <<?P_HASH, BH/binary>>.
rkey(BH) -> <<?P_HASH_TO_HEIGHT, BH/binary>>.
mkey(MK) -> <<?P_META, MK/binary>>.

read_tip_height(undefined) -> -1;
read_tip_height(Db) ->
    case get_kv(Db, mkey(?META_TIP_HEIGHT)) of
        {ok, <<H:32/little>>} -> H;
        _ -> -1
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

%% Take the first N elements off a list, returning {Taken, Rest}.
take_n(N, List) -> lists:split(min(N, length(List)), List).
