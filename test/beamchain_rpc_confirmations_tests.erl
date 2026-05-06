%%% ===================================================================
%%% Pattern C1 regression: confirmations() must report 0 for blocks
%%% that exist in the index but are NOT on the active chain
%%% (i.e. were disconnected by a reorg).
%%%
%%% Bug: beamchain_rpc:confirmations/1 (and beamchain_rest:confirmations/1)
%%% computed `tip_height - block_height + 1` with no active-chain check.
%%% After a reorg that disconnects A1 (height 111, tip now 113 on B-chain),
%%% getrawtransaction(A1.coinbase) reported confirmations=3 instead of 0.
%%%
%%% Mirrors haskoin C1 (same shape): see findings doc
%%% CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
%%% and Bitcoin Core's `tip->GetAncestor(blockindex->nHeight) == blockindex`
%%% check in src/rpc/blockchain.cpp.
%%% ===================================================================
-module(beamchain_rpc_confirmations_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(CHAIN_META, beamchain_chain_meta).

confirmations_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun({_TmpDir, _ConfigPid, _DbPid, ActiveHash, OrphanHash}) ->
         [
          %% Sanity: 1-arg variant still does the height-delta calc
          {"confirmations/1 returns tip-height delta (legacy)",
           fun() -> ?assertEqual(3, beamchain_rpc:confirmations(111)) end},

          %% NEW 2-arg variant — Pattern C1 fix
          {"confirmations/2 returns delta when block IS on active chain",
           fun() ->
               %% Active block at h=111, tip at h=113 → confs = 3
               ?assertEqual(3,
                   beamchain_rpc:confirmations(111, ActiveHash))
           end},

          {"confirmations/2 returns 0 when block is NOT on active chain (reorg)",
           fun() ->
               %% Orphan block at stored h=111 — same height, different hash —
               %% must report 0 (Core convention) even though height delta = 3.
               ?assertEqual(0,
                   beamchain_rpc:confirmations(111, OrphanHash))
           end},

          {"confirmations/2 returns 0 for unknown hash",
           fun() ->
               UnknownHash = crypto:strong_rand_bytes(32),
               ?assertEqual(0,
                   beamchain_rpc:confirmations(111, UnknownHash))
           end},

          %% Same Pattern C1 fix lives in beamchain_rest
          {"beamchain_rest:confirmations/2 — active path",
           fun() ->
               ?assertEqual(3,
                   beamchain_rest:confirmations(111, ActiveHash))
           end},
          {"beamchain_rest:confirmations/2 — orphan path",
           fun() ->
               ?assertEqual(0,
                   beamchain_rest:confirmations(111, OrphanHash))
           end}
         ]
     end}.

%%% ===================================================================
%%% Fixture: in-memory regtest db with one active + one orphan block
%%% at the same height, plus a tip 2 blocks ahead.
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_rpc_confs_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),

    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, DbPid}     = beamchain_db:start_link(),

    %% beamchain_rpc:confirmations/1 calls beamchain_chainstate:get_tip/0,
    %% which is a *direct* ETS read on the named table CHAIN_META. Standing
    %% up the full chainstate gen_server is overkill for this unit test —
    %% just create the table and seed the tip.
    case ets:info(?CHAIN_META) of
        undefined ->
            ets:new(?CHAIN_META, [set, public, named_table,
                                   {keypos, 1},
                                   {read_concurrency, true}]);
        _ ->
            ets:delete_all_objects(?CHAIN_META)
    end,

    %% Build an ACTIVE block at height 111 + a sibling/orphan at the same
    %% height (different hash, what would be left over after a reorg).
    {ActiveHash, ActiveHeader} = make_block_header(111, <<111:8>>),
    {OrphanHash, OrphanHeader} = make_block_header(111, <<222:8>>),
    ?assert(ActiveHash =/= OrphanHash),

    Chainwork = <<0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0>>,

    %% Active chain: store ACTIVE at height 111. The height-keyed CF is the
    %% canonical "what's on the active chain at H" pointer (see
    %% beamchain_db handle_call({get_block_index,H},_) — it returns the
    %% entry currently keyed by encode_height(H), i.e. the canonical one).
    ok = beamchain_db:store_block_index(111, ActiveHash, ActiveHeader,
                                         Chainwork, 1),

    %% Orphan: register the by-hash entry but do NOT make it the canonical
    %% height-111 entry. We do this by: (a) writing the orphan first, then
    %% (b) overwriting height 111 with the active block. The hash→height
    %% pointer for the orphan stays put because it's keyed by hash.
    ok = beamchain_db:store_block_index(111, OrphanHash, OrphanHeader,
                                         Chainwork, 1),
    %% Re-write the active block so the height-keyed CF resolves to ACTIVE
    ok = beamchain_db:store_block_index(111, ActiveHash, ActiveHeader,
                                         Chainwork, 1),

    %% Tip at height 113 (2 blocks past 111) — height delta = 3
    {TipHash, _} = make_block_header(113, <<113:8>>),
    true = ets:insert(?CHAIN_META, {tip, TipHash, 113}),

    {TmpDir, ConfigPid, DbPid, ActiveHash, OrphanHash}.

teardown({TmpDir, _ConfigPid, _DbPid, _A, _O}) ->
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    catch ets:delete(?CHAIN_META),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

make_block_header(Height, Salt) ->
    Header = #block_header{
        version     = 1,
        prev_hash   = <<Height:32/big, 0:224>>,
        merkle_root = <<Salt/binary, 0:(32*8 - bit_size(Salt))>>,
        timestamp   = 1700000000 + Height,
        bits        = 16#1d00ffff,
        nonce       = Height
    },
    Hash = beamchain_serialize:block_hash(Header),
    {Hash, Header}.
