-module(beamchain_status_bit_tests).

%%% Block-index status is RAISED, never assigned over the have-bits.
%%%
%%% Core (chain.h CBlockIndex::RaiseValidity, validation.cpp ConnectBlock /
%%% ReceivedBlockTransactions / InvalidateBlock): nStatus only ever gains
%%% bits — `nStatus |= BLOCK_HAVE_DATA`, `|= BLOCK_HAVE_UNDO`,
%%% `|= BLOCK_FAILED_VALID`, and the validity level is raised with
%%% RaiseValidity. Nothing downstream of a successful connect lowers it.
%%%
%%% beamchain bug (receipts/beamchain-status-bit-2026-10-04.md): block_sync's
%%% post-connect "step 5" re-read the entry that direct_atomic_connect_writes
%%% had just stored with VALID_SCRIPTS|HAVE_DATA|HAVE_UNDO (29) and wrote it
%%% back with a plain 2. Every block connected over P2P (IBD + at-tip) lost
%%% HAVE_DATA, so find_best_valid_chain — which requires HAVE_DATA — could
%%% not see the chain, and reconsiderblock left the tip stuck below the
%%% reconsidered block. header_sync:mark_orphaned_blocks had the same shape
%%% (ASSIGNED 32).
%%%
%%% These tests REACH the real code: the block goes through
%%% beamchain_block_sync:validate_and_connect/3 (the P2P connect path)
%%% against a real beamchain_db + beamchain_chainstate. Only script/consensus
%%% validation is stubbed (dummy blocks carry no real PoW / merkle root).
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_status_bit_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).
-define(VALID_TREE, 2).
-define(VALID_SCRIPTS, 5).
-define(HAVE_DATA, 8).
-define(HAVE_UNDO, 16).
-define(FAILED_VALID, 32).
-define(CONNECTED, (?VALID_SCRIPTS bor ?HAVE_DATA bor ?HAVE_UNDO)).

p2p_connect_keeps_have_bits_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun p2p_connect_keeps_have_bits/0} end}.

p2p_connect_then_reconsider_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun p2p_connect_then_reconsider/0} end}.

mark_orphaned_keeps_have_bits_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun mark_orphaned_keeps_have_bits/0} end}.

raise_block_status_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_) -> {timeout, 60, fun raise_block_status_never_lowers/0} end}.

raised_status_arith_test() ->
    %% level raised to the max, flags OR-ed, nothing cleared
    ?assertEqual(29, beamchain_db:raised_status(2, 5, ?HAVE_DATA bor ?HAVE_UNDO)),
    ?assertEqual(29, beamchain_db:raised_status(29, 2, 0)),
    ?assertEqual(29 bor ?FAILED_VALID, beamchain_db:raised_status(29, 0, ?FAILED_VALID)),
    ?assertEqual(?FAILED_VALID bor 1, beamchain_db:raised_status(1, 0, ?FAILED_VALID)),
    %% a level smuggled in Flags' low bits is ignored (Level is the only way)
    ?assertEqual(?HAVE_DATA bor 2, beamchain_db:raised_status(2, 0, ?HAVE_DATA bor 7)),
    ?assertEqual(5, beamchain_db:raised_status(5, 3, 0)).

%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_status_bit_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, _Height, _Prev, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_block,
                     fun(_Block, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, disconnect_block,
                     fun(Block, _Height, _Params) ->
                             {ok, beamchain_serialize:block_hash(Block#block.header)}
                     end),
    %% Fresh datadir: chainstate connects genesis itself.
    {ok, Pid} = beamchain_chainstate:start_link(),
    unlink(Pid),
    TmpDir.

teardown(TmpDir) ->
    catch gen_server:stop(beamchain_chainstate),
    catch meck:unload(beamchain_validation),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

delete_chainstate_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta]).

dummy_block(PrevHash, Height) ->
    Header = #block_header{
        version = 4,
        prev_hash = PrevHash,
        merkle_root = <<Height:256>>,
        timestamp = 1296688602 + Height,
        bits = 16#207fffff,
        nonce = Height
    },
    Hash = beamchain_serialize:block_hash(Header),
    Coinbase = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<Height:32/little>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000, script_pubkey = <<16#51>>}],
        locktime = 0
    },
    #block{header = Header, transactions = [Coinbase], hash = Hash}.

%% Connect blocks 1..N through the P2P connect path
%% (beamchain_block_sync:validate_and_connect/3). Returns [{Height, Hash}].
p2p_connect_chain(N) ->
    {ok, {GenesisHash, 0}} = beamchain_chainstate:get_tip(),
    State = beamchain_block_sync:test_state(
              #{params => beamchain_chain_params:params(regtest)}),
    p2p_connect_chain(GenesisHash, 1, N, State, []).

p2p_connect_chain(_Prev, H, N, _State, Acc) when H > N ->
    lists:reverse(Acc);
p2p_connect_chain(Prev, H, N, State, Acc) ->
    Block = dummy_block(Prev, H),
    {ok, active, State2} = beamchain_block_sync:validate_and_connect(H, Block, State),
    p2p_connect_chain(Block#block.hash, H + 1, N, State2,
                      [{H, Block#block.hash} | Acc]).

status_of(Hash) ->
    {ok, #{status := S}} = beamchain_db:get_block_index_by_hash(Hash),
    S.

tip_height() ->
    {ok, {_, H}} = beamchain_chainstate:get_tip(),
    H.

%%% ===================================================================

p2p_connect_keeps_have_bits() ->
    Chain = p2p_connect_chain(3),
    ?assertEqual(3, tip_height()),
    lists:foreach(
      fun({H, Hash}) ->
          {ok, #{status := S, n_tx := NTx, hash := Hash}} =
              beamchain_db:get_block_index(H),
          ?assertNotEqual(0, S band ?HAVE_DATA),
          ?assertNotEqual(0, S band ?HAVE_UNDO),
          ?assertEqual(?VALID_SCRIPTS, S band 7),
          ?assertEqual(?CONNECTED, S),
          ?assertEqual(1, NTx)
      end, Chain).

%% The real consequence: after invalidateblock + reconsiderblock on a chain
%% that arrived over P2P, the tip must return to the best chain (Core
%% ResetBlockFailureFlags + ActivateBestChain). Before the fix the
%% reconsidered blocks carried status 2 (no HAVE_DATA) and were invisible
%% to find_best_valid_chain: tip stuck at X-1.
p2p_connect_then_reconsider() ->
    Chain = p2p_connect_chain(?N),
    X = 4,
    {X, HashX} = lists:keyfind(X, 1, Chain),
    ?assertEqual(?N, tip_height()),
    ok = beamchain_chainstate:invalidate_block(HashX),
    ?assertEqual(X - 1, tip_height()),
    ?assertNotEqual(0, status_of(HashX) band ?FAILED_VALID),
    ok = beamchain_chainstate:reconsider_block(HashX),
    ?assertEqual(?N, tip_height()),
    {?N, TipHash} = lists:keyfind(?N, 1, Chain),
    ?assertMatch({ok, {TipHash, ?N}}, beamchain_chainstate:get_tip()),
    ok = gen_server:stop(beamchain_chainstate).

%% header_sync:mark_orphaned_blocks OR-s FAILED_VALID in; the have-bits and
%% the validity level survive (they used to be wiped by an assignment of 32).
mark_orphaned_keeps_have_bits() ->
    Chain = p2p_connect_chain(3),
    ok = beamchain_header_sync:mark_orphaned_blocks(2, 3),
    {1, H1} = lists:keyfind(1, 1, Chain),
    ?assertEqual(?CONNECTED, status_of(H1)),
    lists:foreach(
      fun(H) ->
          {H, Hash} = lists:keyfind(H, 1, Chain),
          ?assertEqual(?CONNECTED bor ?FAILED_VALID, status_of(Hash))
      end, [2, 3]).

raise_block_status_never_lowers() ->
    [{1, H1}] = p2p_connect_chain(1),
    ?assertEqual(?CONNECTED, status_of(H1)),
    ok = beamchain_db:raise_block_status(H1, ?VALID_TREE, 0),
    ?assertEqual(?CONNECTED, status_of(H1)),
    ok = beamchain_db:raise_block_status(H1, 0, ?FAILED_VALID),
    ?assertEqual(?CONNECTED bor ?FAILED_VALID, status_of(H1)),
    ?assertEqual({error, block_not_found},
                 beamchain_db:raise_block_status(<<7:256>>, 0, ?FAILED_VALID)).
