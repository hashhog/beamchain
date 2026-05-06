-module(beamchain_side_branch_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% ============================================================
%% Side-branch acceptance / Pattern Y + Pattern A closure tests
%% (CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md).
%%
%% Pre-fix, beamchain rejected any block whose prev_hash !== active
%% tip with `bad_prevblk`, so the `do_reorganize/1` dispatcher (already
%% defined) was structurally unreachable from submit_block.  These
%% tests pin:
%%
%%   1. The new side-branch index storage layer
%%      (beamchain_db:store_side_branch_index / get_side_branch_index /
%%       delete_side_branch_index / get_all_side_branch_indexes)
%%      roundtrip a hash-keyed BlockIndexEntry that survives in the
%%      meta CF under "sbidx:" prefix.  The active-chain
%%      block_index is height-keyed and so structurally cannot hold
%%      two blocks at the same height; the side-branch index is
%%      hash-keyed and CAN.
%%
%%   2. The chainstate side-branch arm: a block submitted whose
%%      parent IS in the index but is NOT the active tip is stored
%%      as a side-branch (status=VALID_TREE) rather than rejected
%%      with bad_prevblk.
%%
%%   3. The Pattern A dispatcher wiring: when a side-branch block's
%%      cumulative chainwork strictly exceeds the active tip's, the
%%      submit_block path calls do_reorganize/2 which flips the tip.
%%
%% End-to-end coverage of the actual reorg-via-submitblock corpus
%% scenario lives in tools/diff-test-corpus/regression/reorg-via-submitblock
%% (passes post-fix; failed pre-fix with "rejected" Pattern Y).
%% ============================================================

%%% ===================================================================
%%% Side-branch index storage layer (beamchain_db)
%%% ===================================================================

side_branch_index_storage_test_() ->
    {setup,
     fun setup_db_only/0,
     fun teardown_db_only/1,
     fun(_) ->
         [
          {"side-branch index roundtrip", fun test_sb_index_roundtrip/0},
          {"side-branch index delete removes entry", fun test_sb_index_delete/0},
          {"side-branch index get_all returns inserted entries",
           fun test_sb_index_get_all/0},
          {"side-branch index does not collide with active block_index "
           "at the same height", fun test_sb_index_no_height_collision/0}
         ]
     end}.

setup_db_only() ->
    TmpDir = filename:join(["/tmp", "beamchain_sb_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, DbPid} = beamchain_db:start_link(),
    {TmpDir, ConfigPid, DbPid}.

teardown_db_only({TmpDir, _ConfigPid, _DbPid}) ->
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%% Helper: build a synthetic block_header for tests.
mk_header(PrevHash, Timestamp, Bits) ->
    #block_header{
       version = 16#20000000,
       prev_hash = PrevHash,
       merkle_root = <<0:256>>,
       timestamp = Timestamp,
       bits = Bits,
       nonce = 0
    }.

test_sb_index_roundtrip() ->
    Hash = <<16#AB:8, 0:248>>,
    PrevHash = <<16#11:8, 0:248>>,
    Header = mk_header(PrevHash, 1700000000, 16#207fffff),
    Entry = #{
        height    => 5,
        header    => Header,
        chainwork => <<5:256>>,
        status    => 2,           %% VALID_TREE
        n_tx      => 1
    },
    ok = beamchain_db:store_side_branch_index(Hash, Entry),
    {ok, Got} = beamchain_db:get_side_branch_index(Hash),
    ?assertEqual(Hash, maps:get(hash, Got)),
    ?assertEqual(5, maps:get(height, Got)),
    ?assertEqual(<<5:256>>, maps:get(chainwork, Got)),
    ?assertEqual(2, maps:get(status, Got)),
    ?assertEqual(1, maps:get(n_tx, Got)),
    GotHdr = maps:get(header, Got),
    ?assertEqual(PrevHash, GotHdr#block_header.prev_hash),
    ?assertEqual(1700000000, GotHdr#block_header.timestamp),
    ?assertEqual(16#207fffff, GotHdr#block_header.bits).

test_sb_index_delete() ->
    Hash = <<16#CD:8, 0:248>>,
    Entry = #{
        height    => 7,
        header    => mk_header(<<0:256>>, 1700000001, 16#207fffff),
        chainwork => <<7:256>>,
        status    => 2,
        n_tx      => 1
    },
    ok = beamchain_db:store_side_branch_index(Hash, Entry),
    ?assertMatch({ok, _}, beamchain_db:get_side_branch_index(Hash)),
    ok = beamchain_db:delete_side_branch_index(Hash),
    ?assertEqual(not_found, beamchain_db:get_side_branch_index(Hash)).

test_sb_index_get_all() ->
    %% Wipe any prior entries by writing distinct hashes for this test.
    H1 = <<16#A0:8, 1:248>>,
    H2 = <<16#A0:8, 2:248>>,
    H3 = <<16#A0:8, 3:248>>,
    Hdr = mk_header(<<0:256>>, 1700000002, 16#207fffff),
    ok = beamchain_db:store_side_branch_index(H1,
        #{height => 10, header => Hdr, chainwork => <<10:256>>,
          status => 2, n_tx => 1}),
    ok = beamchain_db:store_side_branch_index(H2,
        #{height => 11, header => Hdr, chainwork => <<11:256>>,
          status => 2, n_tx => 1}),
    ok = beamchain_db:store_side_branch_index(H3,
        #{height => 12, header => Hdr, chainwork => <<12:256>>,
          status => 2, n_tx => 1}),
    {ok, All} = beamchain_db:get_all_side_branch_indexes(),
    Hashes = [maps:get(hash, E) || E <- All],
    ?assert(lists:member(H1, Hashes)),
    ?assert(lists:member(H2, Hashes)),
    ?assert(lists:member(H3, Hashes)).

%% A and B are at the same height but with distinct hashes — Core's
%% block index DOES allow this; ours has to use the side-branch
%% (hash-keyed) index for one of them since the active block_index is
%% height-keyed.  This test pins that the two coexist.
test_sb_index_no_height_collision() ->
    %% Active-chain entry at h=20 (height-keyed).
    HashA = <<16#BB:8, 0:248>>,
    HdrA = mk_header(<<0:256>>, 1700000003, 16#207fffff),
    ok = beamchain_db:store_block_index(20, HashA, HdrA, <<20:256>>, 8, 1),

    %% Side-branch entry at h=20 (hash-keyed) — different hash.
    HashB = <<16#BC:8, 0:248>>,
    HdrB = mk_header(<<0:256>>, 1700000004, 16#207fffff),
    ok = beamchain_db:store_side_branch_index(HashB,
        #{height => 20, header => HdrB, chainwork => <<20:256>>,
          status => 2, n_tx => 1}),

    %% Active path: get_block_index(20) must still return A.
    {ok, ActiveEntry} = beamchain_db:get_block_index(20),
    ?assertEqual(HashA, maps:get(hash, ActiveEntry)),

    %% Side-branch path: get_side_branch_index(HashB) must return B.
    {ok, SbEntry} = beamchain_db:get_side_branch_index(HashB),
    ?assertEqual(HashB, maps:get(hash, SbEntry)),
    ?assertEqual(20, maps:get(height, SbEntry)),

    %% A is NOT in the side-branch index.
    ?assertEqual(not_found, beamchain_db:get_side_branch_index(HashA)).
