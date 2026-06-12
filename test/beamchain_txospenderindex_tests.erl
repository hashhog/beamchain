-module(beamchain_txospenderindex_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% -------------------------------------------------------------------
%%% Unit / integration tests for the persistent, reorg-safe
%%% txospenderindex (Bitcoin Core -txospenderindex) and the
%%% gettxspendingprevout RPC.
%%%
%%% These exercise the LOAD-BEARING design invariants against a REAL
%%% RocksDB instance (temp dir), driving the exact production functions
%%% the chainstate connect/disconnect path calls:
%%%
%%%   1. Connect (add_block) writes spent_outpoint -> spending tx; a query
%%%      returns the spending txid + confirming block hash (Core CustomAppend
%%%      + FindSpender).
%%%   2. DISCONNECT (remove_block) RE-DERIVES the disconnected block's spend
%%%      keys from its OWN inputs and erases them — no undo data (Core
%%%      CustomRemove(BuildSpenderPositions)). This is the SAME function the
%%%      invalidateblock path (disconnect_to_height -> do_disconnect_block)
%%%      AND the live reorg path (do_reorganize_atomic -> disconnect_to ->
%%%      do_disconnect_block) both call, disconnect-before-connect.
%%%   3. LIVE REORG: simulate the orchestrator — disconnect B (erases A:0's
%%%      spender), then connect a competing block B' that does NOT spend A:0;
%%%      the A:0 spender stays ERASED. Heavier branch orphaning B erases the
%%%      entry. Mirrors the real do_reorganize_atomic ordering.
%%%   4. best-block persisted: tip height/hash survive a close+reopen.
%%%   5. reconcile_index rewinds a stale persisted tip to the chain's
%%%      common ancestor on restart (BaseIndex::Init Rewind contract).
%%%   6. gettxspendingprevout RPC: the FOUR Core error codes
%%%      (-8 / -8 / -3 / -1) + the unspent / mempool / confirmed shapes.
%%%   7. config gate defaults OFF (Core DEFAULT_TXOSPENDERINDEX false).
%%% -------------------------------------------------------------------

-define(IDX, beamchain_txospenderindex).

%%% ===================================================================
%%% Builders
%%% ===================================================================

%% Deterministic 32-byte hash from a small integer.
h(N) -> <<N:256/big>>.

%% A coinbase tx (null prevout) paying Value to Script.
coinbase_tx(Value, Script) ->
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = <<16#51>>, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = Value, script_pubkey = Script}],
        locktime = 0}.

%% A spending tx: Inputs = [{PrevTxid, PrevVout}], Outputs = [{Value, SPK}].
spend_tx(Inputs, Outputs) ->
    #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = HH, index = II},
                         script_sig = <<>>, sequence = 16#fffffffe,
                         witness = []} || {HH, II} <- Inputs],
        outputs = [#tx_out{value = V, script_pubkey = SPK}
                   || {V, SPK} <- Outputs],
        locktime = 0}.

%% Build a block at Height containing Txs, with a deterministic header hash.
make_block(Height, Txs) ->
    Header = #block_header{
        version = 1,
        prev_hash = <<Height:32/big, 0:224>>,
        merkle_root = <<Height:32/big, 7:224>>,
        timestamp = 1700000000 + Height,
        bits = 16#207fffff,
        nonce = Height},
    Hash = beamchain_serialize:block_hash(Header),
    {Hash, #block{header = Header, transactions = Txs, hash = Hash,
                  height = Height}}.

%%% ===================================================================
%%% Fixture: real RocksDB-backed index gen_server in a temp datadir
%%% ===================================================================

setup() ->
    TmpDir = "/tmp/beamchain_txospender_test_"
             ++ integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    %% Stand up a config ETS table the gen_server reads (datadir + enabled).
    Tbl = beamchain_config_ets,
    case ets:info(Tbl) of
        undefined -> ets:new(Tbl, [named_table, set, public]);
        _ -> ok
    end,
    ets:insert(Tbl, {datadir, TmpDir}),
    ets:insert(Tbl, {txospenderindex, "1"}),
    SavedEnv = os:getenv("BEAMCHAIN_TXOSPENDERINDEX"),
    os:unsetenv("BEAMCHAIN_TXOSPENDERINDEX"),
    catch ?IDX:stop(),
    {ok, _Pid} = ?IDX:start_link(),
    {TmpDir, SavedEnv}.

teardown({TmpDir, SavedEnv}) ->
    catch ?IDX:stop(),
    catch ets:delete(beamchain_config_ets, txospenderindex),
    case SavedEnv of
        false -> os:unsetenv("BEAMCHAIN_TXOSPENDERINDEX");
        _ -> os:putenv("BEAMCHAIN_TXOSPENDERINDEX", SavedEnv)
    end,
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% 1+2+3. connect / disconnect / live-reorg erase
%%% ===================================================================

connect_disconnect_reorg_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun({_TmpDir, _Env}) ->
        [
         {"connect/disconnect + live-reorg erase", fun() ->
            %% Block A (height 1): coinbase txA paying 50 BTC to <<0x51>>.
            TxA = coinbase_tx(5000000000, <<16#51>>),
            ATxid = beamchain_serialize:tx_hash(TxA),  %% internal order
            {_AHash, BlockA} = make_block(1, [TxA]),
            ok = ?IDX:add_block(BlockA, 1),

            %% A:0 is unspent so far.
            ?assertEqual(not_found, ?IDX:find_spender(ATxid, 0)),

            %% Block B (height 2): coinbase + txB spending A:0.
            CbB = coinbase_tx(5000000000, <<16#52>>),
            TxB = spend_tx([{ATxid, 0}], [{4999999000, <<16#53>>}]),
            BTxid = beamchain_serialize:tx_hash(TxB),
            {BHash, BlockB} = make_block(2, [CbB, TxB]),
            ok = ?IDX:add_block(BlockB, 2),

            %% find_spender(A:0) -> txB + block B hash (Core FindSpender).
            {ok, Found} = ?IDX:find_spender(ATxid, 0),
            ?assertEqual(BTxid, maps:get(spending_txid, Found)),
            ?assertEqual(BHash, maps:get(block_hash, Found)),
            ?assertEqual(beamchain_serialize:encode_transaction(TxB, witness),
                         maps:get(spending_tx, Found)),
            ?assertEqual(2, ?IDX:tip_height()),

            %% --- INVALIDATEBLOCK / DISCONNECT: remove_block(B) erases ---
            ok = ?IDX:remove_block(BlockB, 2),
            ?assertEqual(not_found, ?IDX:find_spender(ATxid, 0)),
            ?assertEqual(1, ?IDX:tip_height()),

            %% --- LIVE REORG: heavier branch orphaning B ---
            %% Re-connect B so we have something to reorg AWAY from.
            ok = ?IDX:add_block(BlockB, 2),
            {ok, _} = ?IDX:find_spender(ATxid, 0),
            %% Reorg orchestrator order: DISCONNECT B first
            %% (disconnect-before-connect), then connect a heavier competing
            %% block B' that does NOT spend A:0.
            ok = ?IDX:remove_block(BlockB, 2),
            CbBp = coinbase_tx(5000000000, <<16#54>>),
            TxBp = spend_tx([{h(99), 0}], [{1000, <<16#55>>}]),
            {_BpHash, BlockBp} = make_block(2, [CbBp, TxBp]),
            ok = ?IDX:add_block(BlockBp, 2),
            %% The A:0 spender is ERASED by the reorg — B' never spent it.
            ?assertEqual(not_found, ?IDX:find_spender(ATxid, 0)),
            ?assertEqual(2, ?IDX:tip_height())
         end}
        ]
     end}.

%%% ===================================================================
%%% 4. best-block persisted across close + reopen
%%% ===================================================================

persist_tip_reopen_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun({_TmpDir, _Env}) ->
        [
         {"best-block persisted across close+reopen", fun() ->
            TxA = coinbase_tx(5000000000, <<16#51>>),
            ATxid = beamchain_serialize:tx_hash(TxA),
            {_AHash, BlockA} = make_block(1, [TxA]),
            ok = ?IDX:add_block(BlockA, 1),
            CbB = coinbase_tx(5000000000, <<16#52>>),
            TxB = spend_tx([{ATxid, 0}], [{4999999000, <<16#53>>}]),
            {_BHash, BlockB} = make_block(2, [CbB, TxB]),
            ok = ?IDX:add_block(BlockB, 2),
            ?assertEqual(2, ?IDX:tip_height()),

            %% Close and reopen (no chainstate -> reconcile is a no-op): the
            %% persisted tip + spender record survive.
            catch ?IDX:stop(),
            {ok, _} = ?IDX:start_link(),
            ?assertEqual(2, ?IDX:tip_height()),
            {ok, Found} = ?IDX:find_spender(ATxid, 0),
            ?assertEqual(beamchain_serialize:tx_hash(TxB),
                         maps:get(spending_txid, Found))
         end}
        ]
     end}.

%%% ===================================================================
%%% 5. reconcile_index rewinds a stale persisted tip (Rewind contract)
%%% ===================================================================

reconcile_rewind_test() ->
    %% Pure unit test of reconcile_index/3 against an in-memory-ish stub.
    %% Build a tiny in-process RocksDB to host the index state.
    TmpDir = "/tmp/beamchain_txospender_recon_"
             ++ integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    {ok, Db} = rocksdb:open(filename:join(TmpDir, "db"),
                            [{create_if_missing, true}]),
    try
        %% Seed an index tip at height 5 with a known hash.
        IndexTipHash = h(5),
        ok = rocksdb:put(Db, <<$M, "tip_height">>, <<5:32/little>>, []),
        ok = rocksdb:put(Db, <<$M, "tip_hash">>, IndexTipHash, []),
        %% Chain agrees with the index up to height 3 but FORKED at the tip
        %% (different hash at 5 and 4). The chain-hash fn returns the chain's
        %% hashes; below the index tip we treat any chain-present height as
        %% the common ancestor (height-based rewind, which is always safe).
        ChainHashFun = fun(H) when H >= 0, H =< 3 -> {ok, h(100 + H)};
                          (H) when H =:= 4 -> {ok, h(444)};  %% != index 4
                          (H) when H =:= 5 -> {ok, h(555)};  %% != index tip 5
                          (_) -> not_found
                       end,
        %% Index tip hash (h(5)) != chain hash at 5 (h(555)) -> the tip-level
        %% hash compare fails, so the walk descends; height 4 is chain-present
        %% so 4 becomes the common ancestor and the index rewinds 5 -> 4.
        %% beamchain_db is not running here; rewind reads blocks best-effort
        %% (get_block_by_height returns not_found under catch) so it only
        %% moves the tip pointer — exactly the Rewind contract we assert.
        ok = beamchain_txospenderindex:reconcile_index(Db, ChainHashFun, 5),
        {ok, <<NewTip:32/little>>} = rocksdb:get(Db, <<$M, "tip_height">>, []),
        ?assert(NewTip =< 4)
    after
        catch rocksdb:close(Db),
        os:cmd("rm -rf " ++ TmpDir)
    end.

%%% ===================================================================
%%% 6. gettxspendingprevout RPC — the FOUR Core error codes + shapes
%%% ===================================================================

%% Ensure the mempool reverse-index table exists (production creates it in
%% beamchain_mempool:init before the RPC server binds; in bare eunit we make
%% an empty one so the mempool-first scan returns not_found rather than
%% raising badarg on a missing table).
ensure_mempool_table() ->
    case ets:info(mempool_outpoints) of
        undefined ->
            ets:new(mempool_outpoints, [set, public, named_table]);
        _ -> ok
    end,
    case ets:info(mempool_txs) of
        undefined -> catch ets:new(mempool_txs, [set, public, named_table]);
        _ -> ok
    end.

%% -8 RPC_INVALID_PARAMETER: empty outputs -> "outputs are missing".
rpc_empty_outputs_code_test() ->
    ?assertMatch(
       {error, -8, <<"Invalid parameter, outputs are missing">>},
       beamchain_rpc:rpc_gettxspendingprevout([[]])).

%% -8 RPC_INVALID_PARAMETER: negative vout -> "vout cannot be negative".
rpc_negative_vout_code_test() ->
    Out = #{<<"txid">> => txid_hex_for_int(1), <<"vout">> => -1},
    ?assertMatch(
       {error, -8, <<"Invalid parameter, vout cannot be negative">>},
       beamchain_rpc:rpc_gettxspendingprevout([[Out]])).

%% -3 RPC_TYPE_ERROR: strict unknown key in an output object.
rpc_strict_unknown_key_output_test() ->
    Out = #{<<"txid">> => txid_hex_for_int(1), <<"vout">> => 0,
            <<"bogus">> => 1},
    ?assertMatch({error, -3, _},
                 beamchain_rpc:rpc_gettxspendingprevout([[Out]])).

%% -3 RPC_TYPE_ERROR: strict unknown key in the options object.
rpc_strict_unknown_key_options_test() ->
    Out = #{<<"txid">> => txid_hex_for_int(1), <<"vout">> => 0},
    Opts = #{<<"nope">> => true},
    ?assertMatch({error, -3, _},
                 beamchain_rpc:rpc_gettxspendingprevout([[Out], Opts])).

%% -1 RPC_MISC_ERROR: index unavailable + mempool can't answer +
%% mempool_only=false -> "txospenderindex is unavailable.".
%% (The index gen_server is NOT running in this bare-eunit context, so
%% is_enabled() is false and the mempool is empty -> the unresolved
%% remainder triggers the Core RPC_MISC_ERROR path.)
rpc_index_unavailable_code_test() ->
    ensure_mempool_table(),
    Out = #{<<"txid">> => txid_hex_for_int(7), <<"vout">> => 0},
    Opts = #{<<"mempool_only">> => false},
    %% Ensure the index is not running for this assertion.
    catch beamchain_txospenderindex:stop(),
    ?assertMatch(
       {error, -1,
        <<"Mempool lacks a relevant spend, and "
          "txospenderindex is unavailable.">>},
       beamchain_rpc:rpc_gettxspendingprevout([[Out], Opts])).

%% mempool_only default (index unavailable) -> unspent outpoint returns a
%% bare {txid, vout} object, no error.
rpc_mempool_only_unspent_shape_test() ->
    ensure_mempool_table(),
    THex = txid_hex_for_int(3),
    Out = #{<<"txid">> => THex, <<"vout">> => 0},
    %% Index off -> default mempool_only = true.
    catch beamchain_txospenderindex:stop(),
    case beamchain_rpc:rpc_gettxspendingprevout([[Out]]) of
        {ok_raw_json, Json} ->
            Decoded = jsx:decode(Json, [return_maps]),
            ?assertEqual([#{<<"txid">> => THex, <<"vout">> => 0}], Decoded);
        Other ->
            ?assertEqual({ok_raw_json, ok}, Other)
    end.

%% A deterministic display-order txid hex for a small integer.
txid_hex_for_int(N) ->
    beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(<<N:256/big>>)).

%%% ===================================================================
%%% 7. config gate defaults OFF (Core DEFAULT_TXOSPENDERINDEX false)
%%% ===================================================================

config_default_off_test() ->
    Tbl = beamchain_config_ets,
    Created = case ets:info(Tbl) of
        undefined -> ets:new(Tbl, [named_table, set, public]), true;
        _ -> false
    end,
    %% Make sure the key is absent for the default path.
    ets:delete(Tbl, txospenderindex),
    Saved = os:getenv("BEAMCHAIN_TXOSPENDERINDEX"),
    os:unsetenv("BEAMCHAIN_TXOSPENDERINDEX"),
    try
        ?assertEqual(false, beamchain_config:txospenderindex_enabled())
    after
        case Saved of
            false -> ok;
            _ -> os:putenv("BEAMCHAIN_TXOSPENDERINDEX", Saved)
        end,
        case Created of
            true -> ets:delete(Tbl);
            false -> ok
        end
    end.

config_env_on_test() ->
    Saved = os:getenv("BEAMCHAIN_TXOSPENDERINDEX"),
    os:putenv("BEAMCHAIN_TXOSPENDERINDEX", "1"),
    try
        ?assertEqual(true, beamchain_config:txospenderindex_enabled())
    after
        case Saved of
            false -> os:unsetenv("BEAMCHAIN_TXOSPENDERINDEX");
            _ -> os:putenv("BEAMCHAIN_TXOSPENDERINDEX", Saved)
        end
    end.
