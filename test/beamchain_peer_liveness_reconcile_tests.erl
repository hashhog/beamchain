-module(beamchain_peer_liveness_reconcile_tests).

%%% -------------------------------------------------------------------
%%% Regression tests for two cleanup/consistency defects.
%%%
%%% (1) PEER LIVENESS — non-graceful peer removal must notify the sync
%%%     coordinator the same way the graceful path does. Both the monitor
%%%     'DOWN' handler and the {peer_banned,_,_} handler in
%%%     beamchain_peer_manager previously called remove_peer_and_update/2
%%%     directly, skipping beamchain_sync:notify_peer_disconnected/1 and
%%%     beamchain_mempool:erase_orphans_for_peer/1. That leaves zombie
%%%     dead-peer entries in header_sync (peer_heights / sync_peer) and
%%%     block_sync (peers / peer_stats / in_flight) and wedges any blocks
%%%     in flight from the dead peer.
%%%
%%%     Bitcoin Core funnels EVERY disconnect (graceful or forced) through
%%%     PeerManagerImpl::FinalizeNode exactly once
%%%     (net_processing.cpp:1675). The fix introduces a single
%%%     finalize_peer/2 helper that all three paths call.
%%%
%%% (2) BLOCK-FILTER INDEX RECONCILE — the BIP-157 index keeps its own
%%%     RocksDB tip, written synchronously per block, while the chainstate
%%%     flushes in batches. On unclean exit the index tip can be AHEAD of
%%%     (or forked from) the chainstate, and the restart-replay then
%%%     re-chains cfheaders onto the stale/ahead tip, corrupting the
%%%     persisted cfheader chain. The fix reconciles (rewinds) the index
%%%     against the active chain on startup, per Core
%%%     BaseIndex::Init/Sync/Rewind (index/base.cpp:104,201,290).
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").
-include("../include/beamchain.hrl").
-include("../include/beamchain_protocol.hrl").

%%% ===================================================================
%%% Source-path helpers (mirrors W133 / FIX-66 convention)
%%% ===================================================================

beamchain_src_dir() ->
    Beam = code:which(beamchain_peer_manager),
    case Beam of
        non_existing -> "src";
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true -> Src;
                false -> "src"
            end
    end.

peer_manager_src() ->
    filename:join(beamchain_src_dir(), "beamchain_peer_manager.erl").

read_src(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        {error, _} -> <<>>
    end.

%%% ===================================================================
%%% (1a) PEER LIVENESS — wiring assertion (fails pre-fix)
%%%
%%% Pre-fix the two non-graceful handlers called remove_peer_and_update/2
%%% directly and NEVER notify the sync coordinator. Post-fix they both
%%% call finalize_peer/2, which is the single FinalizeNode-equivalent.
%%% This source assertion is the part that demonstrably flips PASS<->FAIL
%%% across the fix.
%%% ===================================================================

peer_manager_nongraceful_paths_finalize_test() ->
    Src = read_src(peer_manager_src()),
    %% The single funnel helper must exist.
    ?assertNotEqual(nomatch, binary:match(Src, <<"finalize_peer(Pid, State)">>)),
    %% finalize_peer must notify the sync coordinator and prune orphans —
    %% the two steps the non-graceful paths used to skip.
    {FinBody, _} = extract_function(Src, <<"finalize_peer(Pid, State) ->">>),
    ?assertNotEqual(nomatch,
                    binary:match(FinBody,
                                 <<"beamchain_sync:notify_peer_disconnected">>)),
    ?assertNotEqual(nomatch,
                    binary:match(FinBody,
                                 <<"beamchain_mempool:erase_orphans_for_peer">>)),

    %% Monitor 'DOWN' handler (non-graceful death) must route through
    %% finalize_peer/2, NOT bare remove_peer_and_update/2.
    {DownBody, _} = extract_function(
        Src, <<"handle_info({'DOWN', _MonRef, process, Pid, Reason}, State) ->">>),
    ?assertNotEqual(nomatch, binary:match(DownBody, <<"finalize_peer(Pid, State)">>)),

    %% Ban handler (forced removal) must route through finalize_peer/2.
    {BanBody, _} = extract_function(
        Src, <<"handle_info({peer_banned, Pid, Address}, State) ->">>),
    ?assertNotEqual(nomatch, binary:match(BanBody, <<"finalize_peer(Pid, State)">>)).

%% Extract the text of a function clause starting at the given header line
%% up to (but not including) the next top-level "handle_info("/"handle_"
%% boundary or the helper that follows. Cheap heuristic: take the header
%% and the following ~1200 bytes, which comfortably covers each clause
%% here without crossing into unrelated code we assert on.
extract_function(Src, Header) ->
    case binary:match(Src, Header) of
        nomatch -> {<<>>, nomatch};
        {Start, _Len} ->
            Tail = binary:part(Src, Start, min(1200, byte_size(Src) - Start)),
            {Tail, Start}
    end.

%%% ===================================================================
%%% (1b) PEER LIVENESS — behavioral end-to-end through the sync stack.
%%%
%%% Proves the cleanup contract finalize_peer/2 invokes: a peer that the
%%% sync coordinator knows about is fully dropped from header_sync's
%%% peer_heights AND block_sync's peer map when
%%% beamchain_sync:notify_peer_disconnected/1 fires (which the fix now
%%% guarantees on non-graceful death). Pre-fix the non-graceful handlers
%%% never made this call; this is the downstream effect that mattered.
%%% ===================================================================

sync_stack_setup() ->
    TmpDir = filename:join(
        ["/tmp", "beamchain_liveness_test_" ++
                 integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir, [{persistent, true}]),
    application:set_env(beamchain, network, regtest, [{persistent, true}]),
    catch gen_server:stop(beamchain_config),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    {ok, _} = beamchain_header_sync:start_link(),
    {ok, _} = beamchain_block_sync:start_link(),
    {ok, _} = beamchain_sync:start_link(),
    TmpDir.

sync_stack_teardown(TmpDir) ->
    catch gen_server:stop(beamchain_sync),
    catch gen_server:stop(beamchain_block_sync),
    catch gen_server:stop(beamchain_header_sync),
    catch gen_server:stop(beamchain_db),
    catch gen_server:stop(beamchain_config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

notify_peer_disconnected_drops_peer_from_sync_modules_test_() ->
    {setup, fun sync_stack_setup/0, fun sync_stack_teardown/1,
     fun(_TmpDir) ->
        {timeout, 30, fun() ->
            %% A dummy peer process (just needs a pid the sync modules can key on).
            Peer = spawn(fun() -> receive stop -> ok end end),

            %% Register the peer with the sync coordinator (the graceful
            %% peer_connected path also does this). Use a high start_height
            %% so header_sync records it in peer_heights.
            beamchain_sync:notify_peer_connected(
                Peer, #{start_height => 1000000,
                        services => 0,
                        user_agent => <<"test">>}),
            %% Let the casts settle.
            _ = sys:get_state(beamchain_header_sync),
            _ = sys:get_state(beamchain_block_sync),

            ?assert(header_sync_knows_peer(Peer)),

            %% Now simulate what finalize_peer/2 does on ANY disconnect
            %% (graceful or non-graceful): notify the coordinator.
            beamchain_sync:notify_peer_disconnected(Peer),
            _ = sys:get_state(beamchain_header_sync),
            _ = sys:get_state(beamchain_block_sync),

            %% Peer must be gone from header_sync's in-memory peer map —
            %% no zombie entry.
            ?assertNot(header_sync_knows_peer(Peer)),

            Peer ! stop,
            ok
        end}
     end}.

%% Read header_sync's state record and check whether Peer is still in
%% peer_heights. We pull the raw gen_server state via sys:get_state/1 and
%% inspect the record by position-independent means: peer_heights is a map
%% in the #state{} record; find the map that contains the peer key.
header_sync_knows_peer(Peer) ->
    St = sys:get_state(beamchain_header_sync),
    %% #state{} is a tuple; scan its map fields for one keyed by Peer.
    Fields = tl(tuple_to_list(St)),
    lists:any(
      fun(F) when is_map(F) -> maps:is_key(Peer, F);
         (_) -> false
      end, Fields).

%%% ===================================================================
%%% (2) BLOCK-FILTER INDEX RECONCILE — rewind against the active chain.
%%%
%%% These drive the injectable core reconcile_index/3 directly against a
%%% real RocksDB so they are deterministic and don't need the full
%%% chainstate. Pre-fix reconcile_index/3 does not exist, so the whole
%%% block fails to compile/run; post-fix it rewinds correctly.
%%% ===================================================================

mk_block(Tag) ->
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<0:256>>,
        timestamp = 1231006505,
        bits = 16#207fffff,
        nonce = Tag
    },
    SPK = <<16#00, 16#14, Tag:160/big>>,
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000, script_pubkey = SPK}],
        locktime = 0
    },
    #block{header = Header,
           transactions = [Tx],
           hash = <<Tag:256/big>>}.

index_setup() ->
    TmpDir = filename:join(
        ["/tmp", "beamchain_reconcile_test_" ++
                 integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir, [{persistent, true}]),
    application:set_env(beamchain, network, regtest, [{persistent, true}]),
    os:putenv("BEAMCHAIN_BLOCKFILTERINDEX", "1"),
    catch gen_server:stop(beamchain_config),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_blockfilter_index:start_link(),
    TmpDir.

index_teardown(TmpDir) ->
    catch beamchain_blockfilter_index:stop(),
    catch gen_server:stop(beamchain_config),
    os:unsetenv("BEAMCHAIN_BLOCKFILTERINDEX"),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%% Build a synthetic active-chain hash function over the blocks we add.
%% Genesis (height 0) is seeded by maybe_index_genesis on a fresh index;
%% we don't include it here since the test blocks start at height 1.
chain_hash_fun(BlocksByHeight) ->
    fun(Height) ->
        case maps:find(Height, BlocksByHeight) of
            {ok, #block{hash = H}} -> {ok, H};
            error -> not_found
        end
    end.

%% Reach into the running index's RocksDB handle so the test can call the
%% injectable core directly. The handle lives in the gen_server #state{}.
index_db_handle() ->
    St = sys:get_state(beamchain_blockfilter_index),
    %% #state{db, enabled, filter_type} — db is the first field.
    element(2, St).

reconcile_index_test_() ->
    {foreach, fun index_setup/0, fun index_teardown/1,
     [
      fun(_) ->
        {"index AHEAD of chain is rewound to the chain tip", fun() ->
            ?assert(beamchain_blockfilter_index:is_enabled()),
            B1 = mk_block(101), B2 = mk_block(102), B3 = mk_block(103),
            {ok, _} = beamchain_blockfilter_index:add_block(B1, 1, []),
            {ok, _} = beamchain_blockfilter_index:add_block(B2, 2, []),
            {ok, _} = beamchain_blockfilter_index:add_block(B3, 3, []),
            ?assertEqual(3, beamchain_blockfilter_index:tip_height()),

            %% Active chain only reached height 2 (the chainstate flushed
            %% behind the synchronously-written index before an unclean exit).
            Chain = #{1 => B1, 2 => B2},
            Db = index_db_handle(),
            ok = beamchain_blockfilter_index:reconcile_index(
                   Db, chain_hash_fun(Chain), 2),

            %% Index tip rewound to 2; the height-3 entry is gone.
            ?assertEqual(2, beamchain_blockfilter_index:tip_height()),
            ?assertEqual(not_found,
                         beamchain_blockfilter_index:get_block_hash_by_height(3)),
            ?assertEqual(not_found,
                         beamchain_blockfilter_index:get_filter(B3#block.hash)),
            ?assertEqual(not_found,
                         beamchain_blockfilter_index:get_header(B3#block.hash)),
            ?assertEqual(not_found,
                         beamchain_blockfilter_index:get_height_by_hash(B3#block.hash)),
            %% Surviving entries intact + tip header equals height-2 header.
            ?assertMatch({ok, _},
                         beamchain_blockfilter_index:get_filter(B2#block.hash)),
            {ok, H2} = beamchain_blockfilter_index:get_header(B2#block.hash),
            ?assertEqual(H2, beamchain_blockfilter_index:tip_header())
        end}
      end,

      fun(_) ->
        {"index FORKED from chain is rewound to the fork point", fun() ->
            B1 = mk_block(201), B2 = mk_block(202), B3 = mk_block(203),
            {ok, _} = beamchain_blockfilter_index:add_block(B1, 1, []),
            {ok, _} = beamchain_blockfilter_index:add_block(B2, 2, []),
            {ok, _} = beamchain_blockfilter_index:add_block(B3, 3, []),
            ?assertEqual(3, beamchain_blockfilter_index:tip_height()),

            %% Active chain agrees up to height 1, then diverges at 2 & 3
            %% (a reorg the index missed because it died mid-flush).
            B2alt = mk_block(252), B3alt = mk_block(253),
            Chain = #{1 => B1, 2 => B2alt, 3 => B3alt},
            Db = index_db_handle(),
            ok = beamchain_blockfilter_index:reconcile_index(
                   Db, chain_hash_fun(Chain), 3),

            %% Rewound to the fork point (height 1). 2 and 3 (the index's
            %% stale fork) are gone.
            ?assertEqual(1, beamchain_blockfilter_index:tip_height()),
            ?assertEqual(not_found,
                         beamchain_blockfilter_index:get_block_hash_by_height(2)),
            ?assertEqual(not_found,
                         beamchain_blockfilter_index:get_block_hash_by_height(3)),
            ?assertEqual(not_found,
                         beamchain_blockfilter_index:get_height_by_hash(B2#block.hash)),
            ?assertMatch({ok, _},
                         beamchain_blockfilter_index:get_filter(B1#block.hash))
        end}
      end,

      fun(_) ->
        {"index consistent-prefix-of / equal-to chain is a no-op", fun() ->
            B1 = mk_block(301), B2 = mk_block(302),
            {ok, _} = beamchain_blockfilter_index:add_block(B1, 1, []),
            {ok, _} = beamchain_blockfilter_index:add_block(B2, 2, []),
            ?assertEqual(2, beamchain_blockfilter_index:tip_height()),
            TipHdrBefore = beamchain_blockfilter_index:tip_header(),

            %% Active chain is at height 5 and agrees with the index on the
            %% heights the index has (1,2). Nothing to rewind — the missing
            %% forward heights get filled by normal block-connect.
            Chain = #{1 => B1, 2 => B2,
                      3 => mk_block(303), 4 => mk_block(304),
                      5 => mk_block(305)},
            Db = index_db_handle(),
            ok = beamchain_blockfilter_index:reconcile_index(
                   Db, chain_hash_fun(Chain), 5),

            ?assertEqual(2, beamchain_blockfilter_index:tip_height()),
            ?assertEqual(TipHdrBefore,
                         beamchain_blockfilter_index:tip_header()),
            ?assertMatch({ok, _},
                         beamchain_blockfilter_index:get_filter(B1#block.hash)),
            ?assertMatch({ok, _},
                         beamchain_blockfilter_index:get_filter(B2#block.hash))
        end}
      end,

      fun(_) ->
        {"no-corruption: add_block after a rewind re-chains onto the "
         "surviving (rewound) tip header, not the stale ahead header", fun() ->
            %% Index goes 1,2,3 then a reorg replaces 3 with 3alt.
            B1 = mk_block(401), B2 = mk_block(402), B3 = mk_block(403),
            B3alt = mk_block(453),
            {ok, _} = beamchain_blockfilter_index:add_block(B1, 1, []),
            {ok, _} = beamchain_blockfilter_index:add_block(B2, 2, []),
            {ok, _} = beamchain_blockfilter_index:add_block(B3, 3, []),
            %% Capture the stale (pre-fix) tip header — the one B3alt would
            %% wrongly chain onto if the rewind did NOT reset the tip.
            StaleAheadHdr = beamchain_blockfilter_index:tip_header(),

            %% Active chain: 1,2,3alt. Reconcile rewinds the index to 2.
            ChainA = #{1 => B1, 2 => B2, 3 => B3alt},
            DbA = index_db_handle(),
            ok = beamchain_blockfilter_index:reconcile_index(
                   DbA, chain_hash_fun(ChainA), 3),
            ?assertEqual(2, beamchain_blockfilter_index:tip_height()),

            %% After rewind the tip header is height-2's header (the common
            %% ancestor), NOT the stale ahead (height-3) header.
            {ok, Hdr2} = beamchain_blockfilter_index:get_header(B2#block.hash),
            SurvivingTipHdr = beamchain_blockfilter_index:tip_header(),
            ?assertEqual(Hdr2, SurvivingTipHdr),
            ?assertNotEqual(StaleAheadHdr, SurvivingTipHdr),

            %% Replay reconnects 3alt; its cfheader must chain onto the
            %% surviving height-2 header. The correct (never-corrupted)
            %% value is compute_header(filter(3alt), height-2 header).
            ExpectedHdr = beamchain_blockfilter:compute_header(
                            beamchain_blockfilter:build_basic_filter(B3alt, []),
                            Hdr2),
            {ok, {_FB, HdrAfterRewind}} =
                beamchain_blockfilter_index:add_block(B3alt, 3, []),
            ?assertEqual(ExpectedHdr, HdrAfterRewind),

            %% And it must NOT equal the value that chaining onto the stale
            %% ahead header would have produced (the pre-fix corruption).
            CorruptHdr = beamchain_blockfilter:compute_header(
                           beamchain_blockfilter:build_basic_filter(B3alt, []),
                           StaleAheadHdr),
            ?assertNotEqual(CorruptHdr, HdrAfterRewind)
        end}
      end
     ]}.
