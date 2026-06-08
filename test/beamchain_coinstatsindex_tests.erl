-module(beamchain_coinstatsindex_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% -------------------------------------------------------------------
%%% Unit tests for the persistent coinstatsindex commitment math.
%%%
%%% These exercise the load-bearing invariants the index relies on WITHOUT
%%% standing up the full chainstate + db + supervisor tree (the end-to-end
%%% at-height-vs-Core differential is covered by the regtest harness
%%% test-suite/coinstats/beamchain_coinstatsindex.sh):
%%%
%%%   1. beamchain_muhash:serialize/1 + deserialize/1 round-trip the
%%%      un-finalized accumulator exactly (required to persist Core's
%%%      DBVal{muhash} per height).
%%%   2. Building the muhash incrementally (Insert per created coin,
%%%      Remove per spent coin) yields the SAME finalize digest as a full
%%%      rescan over only the SURVIVING (unspent) coins — i.e. the per-block
%%%      delta application the index performs on connect is byte-exact.
%%%   3. Reorg reversibility: applying then reversing a block's coins
%%%      (Remove the outputs it Inserted, re-Insert the prevouts it Removed)
%%%      returns to the parent accumulator's exact digest — the self-check
%%%      Core asserts in RevertBlock (coinstatsindex.cpp:386).
%%%   4. The persisted (serialized) running accumulator, when reloaded mid
%%%      chain, continues to produce the same digest as an uninterrupted
%%%      in-memory run (proves persistence does not perturb the commitment).
%%% -------------------------------------------------------------------

%% Build a #utxo{} for a fake coin.
utxo(Value, Script, IsCb, Height) ->
    #utxo{value = Value, script_pubkey = Script,
          is_coinbase = IsCb, height = Height}.

%% A deterministic 32-byte fake txid from a small integer.
txid(N) -> <<N:256/big>>.

%% Apply a list of {Txid,Vout,#utxo{}} as creations (add) to Acc.
add_all(Coins, Acc) ->
    lists:foldl(
      fun(Coin, A) ->
          beamchain_snapshot:txoutset_muhash_apply(add, Coin, A)
      end, Acc, Coins).

%% Apply a list of {Txid,Vout,#utxo{}} as spends (remove) to Acc.
do_remove_all(Coins, Acc) ->
    lists:foldl(
      fun(Coin, A) ->
          beamchain_snapshot:txoutset_muhash_apply(remove, Coin, A)
      end, Acc, Coins).

%%% ===================================================================
%%% 1. serialize/deserialize round-trip
%%% ===================================================================

serialize_roundtrip_empty_test() ->
    Acc = beamchain_muhash:new(),
    Bin = beamchain_muhash:serialize(Acc),
    ?assertEqual(768, byte_size(Bin)),
    Acc2 = beamchain_muhash:deserialize(Bin),
    ?assertEqual(beamchain_muhash:finalize(Acc),
                 beamchain_muhash:finalize(Acc2)).

serialize_roundtrip_populated_test() ->
    Coins = [{txid(1), 0, utxo(5000000000, <<16#76, 16#a9, 1, 2, 3>>,
                               true, 1)},
             {txid(2), 0, utxo(4999999000, <<16#00, 16#14, 9, 9, 9>>,
                               false, 2)},
             {txid(2), 1, utxo(1000, <<16#51>>, false, 2)}],
    Acc = add_all(Coins, beamchain_muhash:new()),
    Bin = beamchain_muhash:serialize(Acc),
    Acc2 = beamchain_muhash:deserialize(Bin),
    %% Both the finalize digest AND a further-mutated digest must match,
    %% proving the un-finalized num/den (not just the collapse) round-trips.
    ?assertEqual(beamchain_muhash:finalize(Acc),
                 beamchain_muhash:finalize(Acc2)),
    Extra = {txid(3), 0, utxo(7, <<16#52>>, false, 3)},
    A3  = beamchain_snapshot:txoutset_muhash_apply(add, Extra, Acc),
    A3b = beamchain_snapshot:txoutset_muhash_apply(add, Extra, Acc2),
    ?assertEqual(beamchain_muhash:finalize(A3),
                 beamchain_muhash:finalize(A3b)).

%%% ===================================================================
%%% 2. incremental delta == full rescan over surviving coins
%%% ===================================================================

delta_equals_rescan_test() ->
    %% Created across (conceptually) several blocks.
    Created = [{txid(10), 0, utxo(5000000000, <<16#76, 16#a9, 0:160/big,
                                                 16#88, 16#ac>>, true, 1)},
               {txid(11), 0, utxo(5000000000, <<16#00, 16#14, 1:160/big>>,
                                  true, 2)},
               {txid(12), 0, utxo(2500000000, <<16#51>>, false, 3)},
               {txid(12), 1, utxo(2500000000, <<16#52>>, false, 3)},
               {txid(13), 0, utxo(123456, <<16#6a, 1, 2>>, false, 4)}],
    %% Spend two of them.
    Spent = [{txid(10), 0, utxo(5000000000, <<16#76, 16#a9, 0:160/big,
                                              16#88, 16#ac>>, true, 1)},
             {txid(12), 1, utxo(2500000000, <<16#52>>, false, 3)}],
    %% Incremental: add all, then remove spent.
    Incremental = do_remove_all(Spent, add_all(Created, beamchain_muhash:new())),
    %% Full rescan over the SURVIVING set only.
    SpentKeys = [{T, V} || {T, V, _} <- Spent],
    Surviving = [C || {T, V, _} = C <- Created,
                      not lists:member({T, V}, SpentKeys)],
    Rescan = add_all(Surviving, beamchain_muhash:new()),
    ?assertEqual(beamchain_muhash:finalize(Rescan),
                 beamchain_muhash:finalize(Incremental)),
    %% Sanity: the spent-inclusive digest differs from the surviving one.
    AllIn = add_all(Created, beamchain_muhash:new()),
    ?assertNotEqual(beamchain_muhash:finalize(AllIn),
                    beamchain_muhash:finalize(Incremental)).

%%% ===================================================================
%%% 3. reorg reversibility: revert restores the parent digest exactly
%%% ===================================================================

revert_restores_parent_test() ->
    %% Parent state: a couple of coins.
    Parent = add_all(
               [{txid(20), 0, utxo(5000000000, <<16#51>>, true, 5)},
                {txid(21), 0, utxo(3000000000, <<16#52>>, false, 6)}],
               beamchain_muhash:new()),
    ParentDigest = beamchain_muhash:finalize(Parent),
    %% A block creates two outputs and spends one prevout.
    BlockOutputs = [{txid(30), 0, utxo(2000000000, <<16#53>>, false, 7)},
                    {txid(30), 1, utxo(999999000,  <<16#54>>, false, 7)}],
    BlockSpends  = [{txid(21), 0, utxo(3000000000, <<16#52>>, false, 6)}],
    %% Connect: add outputs, remove spends.
    Connected = do_remove_all(BlockSpends, add_all(BlockOutputs, Parent)),
    ?assertNotEqual(ParentDigest, beamchain_muhash:finalize(Connected)),
    %% Revert: remove the outputs it added, re-add the prevouts it removed.
    Reverted = add_all(BlockSpends, do_remove_all(BlockOutputs, Connected)),
    ?assertEqual(ParentDigest, beamchain_muhash:finalize(Reverted)).

%%% ===================================================================
%%% 4. persistence mid-chain does not perturb the commitment
%%% ===================================================================

persist_reload_midchain_test() ->
    B1 = [{txid(40), 0, utxo(5000000000, <<16#51>>, true, 1)}],
    B2 = [{txid(41), 0, utxo(5000000000, <<16#52>>, true, 2)},
          {txid(42), 0, utxo(100, <<16#53>>, false, 2)}],
    B3spend = [{txid(40), 0, utxo(5000000000, <<16#51>>, true, 1)}],
    B3add   = [{txid(43), 0, utxo(4999999900, <<16#54>>, false, 3)}],
    %% Uninterrupted in-memory run.
    A1 = add_all(B1, beamchain_muhash:new()),
    A2 = add_all(B2, A1),
    A3 = add_all(B3add, do_remove_all(B3spend, A2)),
    %% Same run, but serialize+deserialize the accumulator after block 2
    %% (simulating an index restart between blocks).
    A2p = beamchain_muhash:deserialize(beamchain_muhash:serialize(A2)),
    A3p = add_all(B3add, do_remove_all(B3spend, A2p)),
    ?assertEqual(beamchain_muhash:finalize(A3),
                 beamchain_muhash:finalize(A3p)).

%%% ===================================================================
%%% 5. config gate defaults off, env var overrides
%%% ===================================================================

config_default_off_test() ->
    %% With no env var and the config key absent, the gate must be false
    %% (Core's DEFAULT_COINSTATSINDEX = false). The config ETS table is
    %% created by beamchain_config:init/1 in production; create an empty
    %% one here so we exercise the genuine get(coinstatsindex,"0")->default
    %% path rather than crashing on a missing table.
    Tbl = beamchain_config_ets,
    Created = case ets:info(Tbl) of
        undefined ->
            ets:new(Tbl, [named_table, set, public]),
            true;
        _ ->
            false
    end,
    Saved = os:getenv("BEAMCHAIN_COINSTATSINDEX"),
    os:unsetenv("BEAMCHAIN_COINSTATSINDEX"),
    try
        ?assertEqual(false, beamchain_config:coinstatsindex_enabled())
    after
        case Saved of
            false -> ok;
            _ -> os:putenv("BEAMCHAIN_COINSTATSINDEX", Saved)
        end,
        case Created of
            true -> ets:delete(Tbl);
            false -> ok
        end
    end.

config_env_on_test() ->
    Saved = os:getenv("BEAMCHAIN_COINSTATSINDEX"),
    os:putenv("BEAMCHAIN_COINSTATSINDEX", "1"),
    try
        ?assertEqual(true, beamchain_config:coinstatsindex_enabled())
    after
        case Saved of
            false -> os:unsetenv("BEAMCHAIN_COINSTATSINDEX");
            _ -> os:putenv("BEAMCHAIN_COINSTATSINDEX", Saved)
        end
    end.
