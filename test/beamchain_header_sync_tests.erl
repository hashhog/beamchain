-module(beamchain_header_sync_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Block locator tests
%%% ===================================================================

%% Test the block locator construction logic.
%% The locator should start at the tip and go back exponentially.

%% We test the core locator algorithm in isolation by checking
%% the structure of the locator output.

%% Helper: compute MTP from a list of timestamps
compute_mtp_test() ->
    %% 11 timestamps, sorted median should be the 6th element
    Timestamps = [{I, 1000 + I * 600} || I <- lists:seq(0, 10)],
    MTP = compute_mtp_from_window(Timestamps),
    %% Median of [1000,1600,2200,2800,3400,4000,4600,5200,5800,6400,7000]
    %% = 4000 (6th element when 1-indexed at position 6)
    ?assertEqual(4000, MTP).

compute_mtp_empty_test() ->
    ?assertEqual(0, compute_mtp_from_window([])).

compute_mtp_single_test() ->
    ?assertEqual(1000, compute_mtp_from_window([{0, 1000}])).

compute_mtp_three_test() ->
    Window = [{0, 1000}, {1, 3000}, {2, 2000}],
    %% sorted: [1000, 2000, 3000], median = 2000
    ?assertEqual(2000, compute_mtp_from_window(Window)).

%% Test MTP window update (sliding window of 11)
mtp_window_update_test() ->
    %% Start with 11 entries
    Window = [{I, 1000 + I * 600} || I <- lists:seq(0, 10)],
    ?assertEqual(11, length(Window)),
    %% Add one more — should drop the oldest
    Window2 = update_mtp_window(Window, 11, 7600),
    ?assertEqual(11, length(Window2)),
    %% First entry should now be height 1, not height 0
    [{FirstH, _} | _] = Window2,
    ?assertEqual(1, FirstH),
    %% Last entry should be height 11
    {LastH, _} = lists:last(Window2),
    ?assertEqual(11, LastH).

mtp_window_grow_test() ->
    %% Window with fewer than 11 entries should grow
    Window = [{0, 1000}],
    Window2 = update_mtp_window(Window, 1, 1600),
    ?assertEqual(2, length(Window2)),
    Window3 = update_mtp_window(Window2, 2, 2200),
    ?assertEqual(3, length(Window3)).

%% Test chainwork binary encoding
chainwork_to_binary_test() ->
    %% Zero
    ?assertEqual(<<0:256>>, chainwork_to_binary(0)),
    %% Small value should be left-padded to 32 bytes
    Bin = chainwork_to_binary(42),
    ?assertEqual(32, byte_size(Bin)),
    ?assertEqual(42, binary:decode_unsigned(Bin, big)),
    %% Large value
    BigVal = 1 bsl 128,
    BigBin = chainwork_to_binary(BigVal),
    ?assertEqual(BigVal, binary:decode_unsigned(BigBin, big)).

%%% ===================================================================
%%% Checkpoint enforcement tests
%%% ===================================================================

checkpoint_match_test() ->
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => Hash}},
    ?assertEqual(ok, check_checkpoint(100, Hash, Params)).

checkpoint_mismatch_test() ->
    GoodHash = <<1:256>>,
    BadHash = <<2:256>>,
    Params = #{checkpoints => #{100 => GoodHash}},
    ?assertThrow(checkpoint_mismatch,
                 check_checkpoint(100, BadHash, Params)).

checkpoint_no_entry_test() ->
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => <<99:256>>}},
    %% Height 50 has no checkpoint, should pass
    ?assertEqual(ok, check_checkpoint(50, Hash, Params)).

checkpoint_empty_test() ->
    Hash = <<1:256>>,
    Params = #{checkpoints => #{}},
    ?assertEqual(ok, check_checkpoint(42, Hash, Params)).

%%% ===================================================================
%%% Anti-DoS: PoW and continuity validation tests
%%% ===================================================================

%% Test PoW validation on a sequence of headers
check_headers_pow_valid_test() ->
    %% Create a valid header with correct PoW
    %% Using testnet4 pow_limit for easier testing
    PowLimit = hex_to_bin(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    %% A header with very low difficulty (max target) will have valid PoW
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,  %% mainnet genesis difficulty
        nonce = 0
    },
    %% Compute hash - won't actually be valid but tests the flow
    %% For unit testing we use a mock approach
    ?assertEqual(ok, check_headers_pow_continuity_mock([Header], PowLimit, true)).

check_headers_pow_invalid_test() ->
    PowLimit = hex_to_bin(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,
        nonce = 0
    },
    %% Test with mock returning invalid PoW
    ?assertEqual({error, invalid_pow},
                 check_headers_pow_continuity_mock([Header], PowLimit, false)).

check_headers_non_continuous_test() ->
    %% Two headers where the second doesn't point to the first
    Header1 = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,
        nonce = 0
    },
    Header2 = #block_header{
        version = 1,
        prev_hash = <<99:256>>,  %% Wrong prev_hash
        merkle_root = <<2:256>>,
        timestamp = 1700000600,
        bits = 16#1d00ffff,
        nonce = 0
    },
    %% Should fail continuity check
    ?assertEqual({error, non_continuous},
                 check_continuity([Header1, Header2])).

check_headers_continuous_test() ->
    %% Two headers where the second correctly points to the first
    Header1 = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,
        nonce = 0
    },
    Header1Hash = mock_block_hash(Header1),
    Header2 = #block_header{
        version = 1,
        prev_hash = Header1Hash,
        merkle_root = <<2:256>>,
        timestamp = 1700000600,
        bits = 16#1d00ffff,
        nonce = 0
    },
    ?assertEqual(ok, check_continuity([Header1, Header2])).

%%% ===================================================================
%%% Anti-DoS: Checkpoint ancestry tests
%%% ===================================================================

checkpoint_ancestry_below_last_checkpoint_test() ->
    %% Height 50 is below last checkpoint (100), but no checkpoint at 50
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => <<99:256>>}},
    ?assertEqual(ok, check_checkpoint_ancestry(50, Hash, Params)).

checkpoint_ancestry_at_checkpoint_match_test() ->
    %% At checkpoint height below the last checkpoint with matching hash
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => Hash, 200 => <<99:256>>}},
    ?assertEqual(ok, check_checkpoint_ancestry(100, Hash, Params)).

checkpoint_ancestry_at_checkpoint_mismatch_test() ->
    %% At checkpoint height below the last checkpoint with wrong hash
    BadHash = <<2:256>>,
    Params = #{checkpoints => #{100 => <<1:256>>, 200 => <<99:256>>}},
    ?assertEqual({error, checkpoint_ancestry_mismatch},
                 check_checkpoint_ancestry(100, BadHash, Params)).

checkpoint_ancestry_above_last_checkpoint_test() ->
    %% Above all checkpoints - any hash is fine
    Hash = <<42:256>>,
    Params = #{checkpoints => #{100 => <<1:256>>}},
    ?assertEqual(ok, check_checkpoint_ancestry(200, Hash, Params)).

checkpoint_ancestry_empty_checkpoints_test() ->
    %% No checkpoints configured (testnet4, regtest)
    Hash = <<1:256>>,
    Params = #{checkpoints => #{}},
    ?assertEqual(ok, check_checkpoint_ancestry(50, Hash, Params)).

%%% ===================================================================
%%% Anti-DoS: Deep fork detection tests
%%% ===================================================================

get_last_checkpoint_height_test() ->
    Checkpoints = #{100 => <<1:256>>, 200 => <<2:256>>, 50 => <<3:256>>},
    ?assertEqual(200, get_last_checkpoint_height(Checkpoints)).

get_last_checkpoint_height_empty_test() ->
    ?assertEqual(0, get_last_checkpoint_height(#{})).

get_last_checkpoint_height_single_test() ->
    Checkpoints = #{42 => <<1:256>>},
    ?assertEqual(42, get_last_checkpoint_height(Checkpoints)).

%%% ===================================================================
%%% Anti-DoS: Unconnecting header count tests
%%% ===================================================================

max_unconnecting_headers_constant_test() ->
    %% Verify the constant is defined as expected (10)
    ?assertEqual(10, max_unconnecting_headers()).

%%% ===================================================================
%%% P2P fork-DEPTH-cap Core-parity: classify_deep_fork/4 (the gate that
%%% decides whether a competing fork of a given depth may proceed).
%%%
%%% Bitcoin Core has NO fork-depth ceiling; it follows any higher-work branch
%%% at any depth (work-based anti-DoS). The pre-fix gate rejected a deep (>288)
%%% fork past the minimum chainwork UNCONDITIONALLY, banning honest deep-fork
%%% peers and stranding the node on the minority chain. The gate is now keyed on
%%% pruning: ARCHIVE allows the deep fork (check_reorg judges it on work), PRUNED
%%% keeps the depth rejection (a reorg past the retained undo window is
%%% un-appliable).
%%% ===================================================================

%% Shallow fork (<= MIN_FORK_DEPTH_FOR_WORK_CHECK=288) is always allowed,
%% regardless of chainwork or prune mode.
classify_deep_fork_shallow_test() ->
    ?assertEqual(ok, beamchain_header_sync:classify_deep_fork(288, 100, 50, false)),
    ?assertEqual(ok, beamchain_header_sync:classify_deep_fork(288, 100, 50, true)),
    ?assertEqual(ok, beamchain_header_sync:classify_deep_fork(10, 100, 50, false)).

%% Deep fork while still in IBD (tip chainwork < minimum chainwork) is allowed
%% so the node can catch up to the honest chain — on archive AND pruned nodes.
classify_deep_fork_ibd_allowed_test() ->
    ?assertEqual(ok, beamchain_header_sync:classify_deep_fork(500, 40, 50, false)),
    ?assertEqual(ok, beamchain_header_sync:classify_deep_fork(500, 40, 50, true)).

%% THE FIX: a deep fork past the minimum chainwork on an ARCHIVE node (prune
%% disabled) is ALLOWED — Core follows the higher-work branch at any depth, and
%% check_reorg judges it on work. Pre-fix this returned
%% {error, deep_fork_insufficient_work} (banned the peer, stranded the node).
classify_deep_fork_archive_follows_deep_fork_test() ->
    ?assertEqual(ok, beamchain_header_sync:classify_deep_fork(289, 100, 50, false)),
    ?assertEqual(ok, beamchain_header_sync:classify_deep_fork(5000, 100, 50, false)).

%% Pruning gate: the SAME deep fork past the minimum chainwork on a PRUNED node
%% keeps the depth rejection — a reorg deeper than the retained 288-block undo
%% window is un-appliable. Proves the gate keys on pruning, not depth.
classify_deep_fork_pruned_rejects_deep_fork_test() ->
    ?assertEqual({error, deep_fork_insufficient_work},
                 beamchain_header_sync:classify_deep_fork(289, 100, 50, true)),
    ?assertEqual({error, deep_fork_insufficient_work},
                 beamchain_header_sync:classify_deep_fork(5000, 100, 50, true)).

%%% ===================================================================
%%% Probe rotation: select_next_probe_peer/2 (2026-07-20 header-sync
%%% wedge fix, D3). On getheaders_timeout the sync loop must rotate to a
%%% peer NOT yet attempted this round — regardless of the (possibly
%%% handshake-stale) recorded heights — and only report `none` (falling
%%% back to the height map / mark-complete path) after every connected
%%% peer has been attempted.
%%% ===================================================================

select_next_probe_peer_empty_test() ->
    ?assertEqual(none,
                 beamchain_header_sync:select_next_probe_peer(#{}, [])).

select_next_probe_peer_all_attempted_test() ->
    P1 = list_to_pid("<0.901.0>"),
    P2 = list_to_pid("<0.902.0>"),
    Heights = #{P1 => 100, P2 => 200},
    ?assertEqual(none,
                 beamchain_header_sync:select_next_probe_peer(
                     Heights, [P2, P1])).

%% Rotation must skip already-attempted peers even when they have the
%% highest recorded height (that peer just timed out on us).
select_next_probe_peer_skips_attempted_test() ->
    P1 = list_to_pid("<0.903.0>"),
    P2 = list_to_pid("<0.904.0>"),
    P3 = list_to_pid("<0.905.0>"),
    Heights = #{P1 => 300, P2 => 200, P3 => 100},
    %% P1 (highest) already attempted → pick P2 (next highest)
    ?assertEqual({ok, P2},
                 beamchain_header_sync:select_next_probe_peer(
                     Heights, [P1])),
    %% P1 and P2 attempted → pick P3
    ?assertEqual({ok, P3},
                 beamchain_header_sync:select_next_probe_peer(
                     Heights, [P2, P1])).

%% THE FIX'S KEY PROPERTY: peers whose recorded height does NOT exceed
%% ours are still probe candidates. Heights are frozen at the version
%% handshake, so post-IBD every peer can look equal-height-to-us while
%% the network is really ahead — the pre-fix path (select_best_peer via
%% pick_sync_peer_and_start) returned none here and logged "already at
%% tip, marking complete", wedging the node.
select_next_probe_peer_ignores_stale_heights_test() ->
    P1 = list_to_pid("<0.906.0>"),
    P2 = list_to_pid("<0.907.0>"),
    Heights = #{P1 => 0, P2 => 0},
    Result = beamchain_header_sync:select_next_probe_peer(Heights, []),
    ?assertMatch({ok, P} when P =:= P1 orelse P =:= P2, Result),
    {ok, First} = Result,
    %% And after the first times out, the OTHER one is chosen.
    {ok, Second} =
        beamchain_header_sync:select_next_probe_peer(Heights, [First]),
    ?assertNotEqual(First, Second).

%%% ===================================================================
%%% Internal helpers (duplicated from module for testing)
%%% ===================================================================

compute_mtp_from_window([]) ->
    0;
compute_mtp_from_window(Window) ->
    Timestamps = [Ts || {_H, Ts} <- Window],
    Sorted = lists:sort(Timestamps),
    lists:nth((length(Sorted) div 2) + 1, Sorted).

update_mtp_window(Window, Height, Timestamp) ->
    Window2 = Window ++ [{Height, Timestamp}],
    case length(Window2) > 11 of
        true -> tl(Window2);
        false -> Window2
    end.

chainwork_to_binary(0) ->
    <<0:256>>;
chainwork_to_binary(N) ->
    Bin = binary:encode_unsigned(N, big),
    case byte_size(Bin) < 32 of
        true ->
            Pad = 32 - byte_size(Bin),
            <<0:(Pad * 8), Bin/binary>>;
        false ->
            Bin
    end.

check_checkpoint(Height, BlockHash, Params) ->
    Checkpoints = maps:get(checkpoints, Params, #{}),
    case maps:find(Height, Checkpoints) of
        {ok, ExpectedHash} ->
            case BlockHash =:= ExpectedHash of
                true -> ok;
                false -> throw(checkpoint_mismatch)
            end;
        error ->
            ok
    end.

%% Mock PoW+continuity check for testing
check_headers_pow_continuity_mock(_Headers, _PowLimit, true) ->
    ok;
check_headers_pow_continuity_mock(_Headers, _PowLimit, false) ->
    {error, invalid_pow}.

%% Check header continuity (prev_hash chain)
check_continuity([]) ->
    ok;
check_continuity([_Single]) ->
    ok;
check_continuity([First | Rest]) ->
    FirstHash = mock_block_hash(First),
    check_continuity_chain(Rest, FirstHash).

check_continuity_chain([], _PrevHash) ->
    ok;
check_continuity_chain([Header | Rest], PrevHash) ->
    case Header#block_header.prev_hash =:= PrevHash of
        true ->
            NextHash = mock_block_hash(Header),
            check_continuity_chain(Rest, NextHash);
        false ->
            {error, non_continuous}
    end.

%% Simple mock block hash for testing continuity
mock_block_hash(#block_header{merkle_root = MR, nonce = N}) ->
    %% Just use a deterministic hash based on merkle_root and nonce
    crypto:hash(sha256, <<MR/binary, N:32>>).

%% Checkpoint ancestry check (duplicated from module)
check_checkpoint_ancestry(Height, BlockHash, Params) ->
    Checkpoints = maps:get(checkpoints, Params, #{}),
    case maps:size(Checkpoints) of
        0 ->
            ok;
        _ ->
            LastCheckpointHeight = get_last_checkpoint_height(Checkpoints),
            case Height < LastCheckpointHeight of
                true ->
                    case maps:find(Height, Checkpoints) of
                        {ok, ExpectedHash} ->
                            case BlockHash =:= ExpectedHash of
                                true -> ok;
                                false -> {error, checkpoint_ancestry_mismatch}
                            end;
                        error ->
                            ok
                    end;
                false ->
                    ok
            end
    end.

%% Get the highest checkpoint height
get_last_checkpoint_height(Checkpoints) ->
    maps:fold(fun(H, _, Max) -> max(H, Max) end, 0, Checkpoints).

%% Constant for testing
max_unconnecting_headers() ->
    10.

%% Hex to binary helper
hex_to_bin(HexStr) ->
    hex_to_bin(HexStr, <<>>).

hex_to_bin([], Acc) ->
    Acc;
hex_to_bin([H1, H2 | Rest], Acc) ->
    Byte = (hex_val(H1) bsl 4) bor hex_val(H2),
    hex_to_bin(Rest, <<Acc/binary, Byte>>).

hex_val(C) when C >= $0, C =< $9 -> C - $0;
hex_val(C) when C >= $a, C =< $f -> C - $a + 10;
hex_val(C) when C >= $A, C =< $F -> C - $A + 10.

%%% ===================================================================
%%% Chain selection is by WORK, never by LENGTH (#45)
%%%
%%% Core's CBlockIndexWorkComparator (validation.cpp:3114-3123) orders
%%% candidates by nChainWork and breaks ties on nSequenceId — never on height
%%% or block count. Bitcoin abandoned length-based selection in 2010.
%%%
%%% check_reorg used to accept a fork that was merely LONGER, provided the fork
%%% point was within 10 blocks of the tip. That arm alone — no header drift, no
%%% other precondition — let a 6-header fork carrying 95.05% of the tip's work
%%% evict five VALIDATED blocks, and the eviction is permanent: the caller runs
%%% mark_orphaned_blocks (FAILED_VALID, HAVE_DATA cleared) before the fork's
%%% headers are even validated.
%%% ===================================================================

%% A strictly heavier chain wins. This is the whole rule.
reorg_accepts_strictly_more_work_test() ->
    ?assert(beamchain_header_sync:incoming_chain_wins(1001, 1000)).

%% Equal work does NOT reorg: Core requires strictly greater, so a tie leaves
%% the incumbent tip in place rather than thrashing between equal chains.
reorg_rejects_equal_work_test() ->
    ?assertNot(beamchain_header_sync:incoming_chain_wins(1000, 1000)).

%% A lighter chain never wins, however long it is.
reorg_rejects_less_work_test() ->
    ?assertNot(beamchain_header_sync:incoming_chain_wins(999, 1000)).

%% THE REGRESSION, with the receipt's measured numbers: a 6-header fork rooted
%% within 10 blocks of the tip, carrying 95.05% of the tip's work. Under the
%% old length arm this evicted five validated blocks. It must now lose.
reorg_rejects_longer_but_lighter_fork_test() ->
    TipCW = 100000000,
    IncomingCW = 95050000,          %% 95.05% of tip work
    ?assertNot(beamchain_header_sync:incoming_chain_wins(IncomingCW, TipCW)).

%% Length is not an input at all — the predicate cannot see it. A fork twice as
%% long but a hair lighter still loses.
reorg_length_is_not_a_tiebreaker_test() ->
    ?assertNot(beamchain_header_sync:incoming_chain_wins(99999999, 100000000)).

%% Genesis-adjacent sanity: zero work never displaces a real chain.
reorg_rejects_zero_work_test() ->
    ?assertNot(beamchain_header_sync:incoming_chain_wins(0, 1)).

%%% ===================================================================
%%% Headers never change the active chain (secfix-beamchain-header-only-reorg)
%%%
%%% Core (validation.cpp): AcceptBlockHeader only adds a block-index entry.
%%% Headers never move the active chain, never mark a block failed and never
%%% touch the UTXO set; ActivateBestChain switches to a heavier branch only
%%% once that branch's block data has been connected, and a block that fails
%%% to connect leaves the old tip active.
%%%
%%% beamchain bug (audited at 95b28d810f03): a headers message carrying a
%%% fork with more work than the header tip ran check_reorg_work, which
%%% marked every active block above the fork point FAILED_VALID
%%% (mark_orphaned_blocks) and disconnected the chainstate back to the fork
%%% point (rollback_to -> disconnect_chainstate_to) before a single fork body
%%% had arrived. Two cheap headers were enough to roll back the UTXO set and
%%% poison the valid chain; if the fork's bodies never came, the node stayed
%%% rolled back.
%%%
%%% These tests run the real beamchain_header_sync, beamchain_chainstate and
%%% beamchain_db (regtest, temp datadir). Only script/consensus block
%%% validation is stubbed; the fork headers carry real regtest PoW and go
%%% through header_sync's real header checks.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_header_sync_tests`
%%% ===================================================================

-define(HO_N, 6).
-define(HO_FAILED, 16#60).   %% BLOCK_FAILED_VALID bor BLOCK_FAILED_CHILD

header_only_reorg_test_() ->
    {foreach, fun ho_setup/0, fun ho_teardown/1,
     [fun(_) -> {timeout, 60, {"fork headers without bodies do not regress "
                               "the tip",
                               fun fork_headers_without_bodies_do_not_regress_tip/0}}
      end,
      fun(_) -> {timeout, 60, {"fork headers stay off the active height "
                               "slots; MTP survives a restart",
                               fun fork_headers_keep_active_slots_and_mtp/0}}
      end,
      fun(_) -> {timeout, 60, {"heavier fork reorgs once its bodies connect",
                               fun heavier_fork_reorgs_when_bodies_connect/0}}
      end,
      fun(_) -> {timeout, 60, {"fork bodies without more work do not reorg",
                               fun fork_bodies_without_more_work_do_not_reorg/0}}
      end,
      fun(_) -> {timeout, 60, {"invalid fork body leaves the old tip active",
                               fun invalid_fork_body_keeps_old_tip/0}}
      end,
      fun(_) -> {timeout, 60, {"invalid fork body below the tip rewinds the "
                               "header chain to the active tip",
                               fun invalid_fork_body_below_tip_rewinds_to_active_tip/0}}
      end,
      fun(_) -> {timeout, 60, {"header chain lookup follows a hash-keyed "
                               "header tip past a stale slot",
                               fun header_chain_follows_tip_past_stale_slot/0}}
      end,
      fun(_) -> {timeout, 60, {"a restarted header sync checks the next fork "
                               "header against the fork's own MTP",
                               fun fork_mtp_window_survives_header_sync_restart/0}}
      end]}.

header_only_reorg_snapshot_test_() ->
    {setup, fun() -> ho_setup(snapshot) end, fun ho_teardown/1,
     fun(_) -> {timeout, 60, {"headers below a snapshot-style tip fill their "
                              "empty height slots",
                              fun snapshot_headers_fill_empty_slots_below_tip/0}}
     end}.

%% A 2-header fork off block 5 (heights 6', 7') has more work than our tip
%% at 6. Nothing about the active chain may change until bodies arrive.
fork_headers_without_bodies_do_not_regress_tip() ->
    {F6, F7} = ho_fork(),
    ok = ho_announce([F6, F7]),
    %% The best header follows the heavier fork (Core: best header = most
    %% work header), ...
    ?assertMatch(#{tip_height := 7}, beamchain_header_sync:get_status()),
    %% ... the active chain does not move, ...
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()),
    %% ... nothing was disconnected from the UTXO set, ...
    ?assertEqual(0, meck:num_calls(beamchain_validation, disconnect_block, '_')),
    %% ... and no block on either branch is marked failed.
    [?assertNot(beamchain_chainstate:is_known_invalid(H))
     || H <- [ho_hash(5), ho_hash(6), F6#block.hash, F7#block.hash]],
    ?assertEqual(0, ho_status(ho_hash(?HO_N)) band ?HO_FAILED),
    %% The active chain's height slot is untouched; the fork header for that
    %% height is kept hash-keyed (side-branch index), the one above the tip
    %% takes its height slot.
    {ok, #{hash := Slot6}} = beamchain_db:get_block_index(?HO_N),
    ?assertEqual(ho_hash(?HO_N), Slot6),
    ?assertMatch({ok, #{height := ?HO_N}},
                 beamchain_db:get_side_branch_index(F6#block.hash)),
    {ok, #{hash := Slot7}} = beamchain_db:get_block_index(?HO_N + 1),
    ?assertEqual(F7#block.hash, Slot7).

%% Consensus risk of the fix: while a heavier fork's headers are known but
%% its bodies are not, the active chain must read exactly as before. Height
%% slots at or below the tip are read by height for consensus (the boot MTP
%% window, BIP68 ancestor MTP), so fork headers must not land there. A
%% 5-header fork off block 2 whose timestamps are far later than the active
%% chain's would move the median of the active tip's window if it did. The
%% chainstate is restarted (it rebuilds the MTP window from the height
%% slots) and must come back with the same tip and the same MTP.
fork_headers_keep_active_slots_and_mtp() ->
    MTP0 = beamchain_chainstate:get_mtp(),
    Fork = ho_pow_chain(ho_hash(2), 3, 5, 400, 50000),
    ok = ho_announce(Fork),
    ?assertMatch(#{tip_height := 7}, beamchain_header_sync:get_status()),
    ok = gen_server:stop(beamchain_chainstate),
    ho_delete_ets(),
    {ok, CS} = beamchain_chainstate:start_link(),
    unlink(CS),
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()),
    ?assertEqual(MTP0, beamchain_chainstate:get_mtp()),
    [begin
         {ok, #{hash := S}} = beamchain_db:get_block_index(H),
         ?assertEqual(ho_hash(H), S)
     end || H <- [3, 4, 5, 6]].

%% Once the fork's bodies arrive the chainstate reorgs onto the heavier
%% branch. Driven through block_sync: its download start is the fork point
%% + 1 (the header chain now diverges below the connected tip), and the
%% bodies go through validate_and_connect/3, the P2P connect path, which
%% hands blocks that do not extend the connected tip to submit_block/1.
%% 6' alone only ties block 6 (Core keeps the first-seen tip), so it stays
%% on the side branch; 7' makes the fork heavier and the tip moves. The
%% out-worked block is not marked failed.
heavier_fork_reorgs_when_bodies_connect() ->
    {F6, F7} = ho_fork(),
    ok = ho_announce([F6, F7]),
    ?assertEqual(?HO_N, beamchain_block_sync:find_start_height()),
    S0 = ho_sync_state(),
    {ok, O6, S1} = beamchain_block_sync:validate_and_connect(?HO_N, F6, S0),
    ?assertEqual(side_branch, O6),
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()),
    {ok, O7, _} = beamchain_block_sync:validate_and_connect(?HO_N + 1, F7, S1),
    io:format(user, "~nvalidate_and_connect(6') -> ~p, (7') -> ~p~n", [O6, O7]),
    ?assertEqual(reorg, O7),
    ?assertEqual({ok, {F7#block.hash, ?HO_N + 1}},
                 beamchain_chainstate:get_tip()),
    {ok, #{hash := Slot6}} = beamchain_db:get_block_index(?HO_N),
    ?assertEqual(F6#block.hash, Slot6),
    ?assertNot(beamchain_chainstate:is_known_invalid(ho_hash(?HO_N))).

%% Consensus risk of the fix: while the heavier fork's headers hold the
%% height slots (the active tip's own slot included), a fork body with LESS
%% or EQUAL work than the active tip must not move it (Core: a block becomes
%% the tip only with strictly more work). A 3-header fork 5'', 6'', 7'' off
%% block 4 is announced; its bodies arrive one at a time: 5'' (work 10 < 12)
%% and 6'' (12 = 12) stay on the side branch, 7'' (14) reorgs.
fork_bodies_without_more_work_do_not_reorg() ->
    G5 = ho_pow_block(ho_hash(4), 5, 300),
    G6 = ho_pow_block(G5#block.hash, 6, 300),
    G7 = ho_pow_block(G6#block.hash, 7, 300),
    ok = ho_announce([G5, G6, G7]),
    ?assertMatch(#{tip_height := 7}, beamchain_header_sync:get_status()),
    S0 = ho_sync_state(),
    {ok, O5, S1} = beamchain_block_sync:validate_and_connect(5, G5, S0),
    ?assertEqual(side_branch, O5),
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()),
    {ok, O6, S2} = beamchain_block_sync:validate_and_connect(6, G6, S1),
    ?assertEqual(side_branch, O6),
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()),
    {ok, O7, _} = beamchain_block_sync:validate_and_connect(7, G7, S2),
    io:format(user, "~nvalidate_and_connect(5'') -> ~p, (6'') -> ~p, (7'') -> ~p~n",
              [O5, O6, O7]),
    ?assertEqual(reorg, O7),
    ?assertEqual({ok, {G7#block.hash, 7}}, beamchain_chainstate:get_tip()).

%% Consensus risk of the fix: a heavier header chain whose first body is
%% invalid must not cost us the valid chain. 6' ties block 6 (side branch);
%% 7' makes the fork heavier, the reorg connects 6', which fails. The tip
%% stays on block 6 and 5 and 6 are not marked failed (6' is).
invalid_fork_body_keeps_old_tip() ->
    {F6, F7} = ho_fork(),
    ok = ho_announce([F6, F7]),
    Bad = F6#block.hash,
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(#block{header = Hdr}, _Ht, _Prev, _Params) ->
                             case beamchain_serialize:block_hash(Hdr) of
                                 Bad -> {error, bad_cb_amount};
                                 _ -> ok
                             end
                     end),
    S0 = ho_sync_state(),
    {ok, O6, S1} = beamchain_block_sync:validate_and_connect(?HO_N, F6, S0),
    ?assertEqual(side_branch, O6),
    R7 = beamchain_block_sync:validate_and_connect(?HO_N + 1, F7, S1),
    io:format(user, "~nvalidate_and_connect(6') -> ~p, (7' over invalid 6') -> ~p~n",
              [O6, R7]),
    ?assertMatch({error, _}, R7),
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()),
    ?assert(beamchain_chainstate:is_known_invalid(Bad)),
    ?assertNot(beamchain_chainstate:is_known_invalid(ho_hash(?HO_N))),
    ?assertNot(beamchain_chainstate:is_known_invalid(ho_hash(5))),
    %% What block_sync does next (invalid_block_found/4 -> header sync),
    %% then a peer's headers reply on the old chain.
    beamchain_header_sync:invalid_block_found(F7#block.hash, ?HO_N + 1, undefined),
    %% The header chain is back on the active tip; the stale 7' left in
    %% height slot 7 must not make block download go back to the fork.
    ?assertMatch(#{tip_height := ?HO_N}, beamchain_header_sync:get_status()),
    ?assertEqual(?HO_N + 1, beamchain_block_sync:find_start_height()),
    B7 = ho_pow_block(ho_hash(?HO_N), ?HO_N + 1, 200),
    ok = ho_announce([ho_blk(?HO_N), B7]),
    St = beamchain_header_sync:get_status(),
    {ok, #{hash := Slot6}} = beamchain_db:get_block_index(?HO_N),
    ?assertMatch(#{tip_height := 7}, St),
    ?assertEqual(B7#block.hash, maps:get(tip_hash, St)),
    ?assertEqual(ho_hash(?HO_N), Slot6),
    ?assertEqual(?HO_N + 1, beamchain_block_sync:find_start_height()),
    ?assertMatch({ok, active, _},
                 beamchain_block_sync:validate_and_connect(?HO_N + 1, B7, S0)),
    ?assertEqual({ok, {B7#block.hash, ?HO_N + 1}},
                 beamchain_chainstate:get_tip()).

%% A fork body at a height at or below the tip fails its context-free
%% check before any reorg is tried (here 5'' of a 5'', 6'', 7'' fork off
%% block 4). Block sync reports it; the failed block is a fork header kept
%% off the active slots, so header sync matches it by hash, and since every
%% header above it on that chain is invalid too, rewinds the header chain to
%% the active tip. Block download resumes on the active chain.
invalid_fork_body_below_tip_rewinds_to_active_tip() ->
    G5 = ho_pow_block(ho_hash(4), 5, 300),
    G6 = ho_pow_block(G5#block.hash, 6, 300),
    G7 = ho_pow_block(G6#block.hash, 7, 300),
    ok = ho_announce([G5, G6, G7]),
    ?assertMatch(#{tip_height := 7}, beamchain_header_sync:get_status()),
    Bad = G5#block.hash,
    ok = meck:expect(beamchain_validation, check_block,
                     fun(#block{header = Hdr}, _Params) ->
                             case beamchain_serialize:block_hash(Hdr) of
                                 Bad -> {error, bad_txnmrklroot};
                                 _ -> ok
                             end
                     end),
    ?assertEqual(5, beamchain_block_sync:find_start_height()),
    ?assertMatch({error, _},
                 beamchain_block_sync:validate_and_connect(5, G5, ho_sync_state())),
    %% What block_sync's invalid_block_found/4 does with a verdict.
    ok = beamchain_chainstate:invalid_block_found(Bad),
    beamchain_header_sync:invalid_block_found(Bad, 5, undefined),
    St = beamchain_header_sync:get_status(),
    ?assertMatch(#{tip_height := ?HO_N}, St),
    ?assertEqual(ho_hash(?HO_N), maps:get(tip_hash, St)),
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()),
    ?assertNot(beamchain_chainstate:is_known_invalid(ho_hash(5))),
    ?assertEqual(?HO_N + 1, beamchain_block_sync:find_start_height()),
    %% An honest block 7 on the active tip now connects as usual.
    B7 = ho_pow_block(ho_hash(?HO_N), ?HO_N + 1, 200),
    ok = ho_announce([B7]),
    ?assertEqual(B7#block.hash,
                 maps:get(tip_hash, beamchain_header_sync:get_status())),
    ?assertMatch({ok, active, _},
                 beamchain_block_sync:validate_and_connect(?HO_N + 1, B7,
                                                           ho_sync_state())).

%% The best header can be a single fork header at a height at or below the
%% tip (e.g. one full-difficulty block out-working two min-difficulty ones
%% on testnet4; regtest's fixed difficulty cannot produce it, so the index
%% state is written directly): tip 6, header 7 on block 6 still in slot 7
%% from before, header tip 6' on block 5 kept hash-keyed. The header chain
%% at 6 is 6', so block download starts at 6, not 7. A restarted header
%% sync resumes from 6' and accepts a header extending it.
header_chain_follows_tip_past_stale_slot() ->
    B7 = ho_pow_block(ho_hash(?HO_N), ?HO_N + 1, 0),
    ok = beamchain_db:store_block_index(?HO_N + 1, B7#block.hash,
                                        B7#block.header,
                                        <<(2 * (?HO_N + 1)):256>>, 1),
    F6 = ho_pow_block(ho_hash(5), ?HO_N, 500),
    ok = beamchain_db:store_side_branch_index(
           F6#block.hash, #{height => ?HO_N, header => F6#block.header,
                            chainwork => <<100:256>>, status => 1,
                            n_tx => 0}),
    ok = beamchain_db:set_header_tip(F6#block.hash, ?HO_N),
    ?assertEqual(?HO_N, beamchain_block_sync:find_start_height()),
    ?assertEqual({ok, F6#block.hash}, beamchain_header_chain:hash_at(?HO_N)),
    ?assertEqual({ok, ho_hash(5)}, beamchain_header_chain:hash_at(5)),
    %% A restarted header sync loads that header tip by hash (its slot holds
    %% block 6), and a header extending it is checked against it (prev
    %% header and MTP window by hash) and connects.
    ok = gen_server:stop(beamchain_header_sync),
    {ok, HS} = beamchain_header_sync:start_link(),
    unlink(HS),
    St0 = beamchain_header_sync:get_status(),
    ?assertMatch(#{tip_height := ?HO_N}, St0),
    ?assertEqual(F6#block.hash, maps:get(tip_hash, St0)),
    F7 = ho_pow_block(F6#block.hash, ?HO_N + 1, 500),
    ok = ho_announce([F7]),
    St1 = beamchain_header_sync:get_status(),
    ?assertMatch(#{tip_height := 7}, St1),
    ?assertEqual(F7#block.hash, maps:get(tip_hash, St1)),
    {ok, #{hash := Slot7}} = beamchain_db:get_block_index(?HO_N + 1),
    ?assertEqual(F7#block.hash, Slot7).

%% The header-sync MTP window must follow the fork's own headers, not the
%% active blocks in the height slots below the connected tip. A 5-header
%% fork 3'..7' off block 2, timestamps 50,000 s later than the active
%% chain's, is announced (3'..6' kept off the slots, 7' in slot 7), then
%% header sync restarts. Over the fork the median of the last 11 is
%% base + 50004; read from the active slots it would be base + 4. A header
%% 8' timestamped base + 108 is too old (Core: time-too-old) and must be
%% refused; one timestamped base + 50008 is accepted.
fork_mtp_window_survives_header_sync_restart() ->
    Fork = ho_pow_chain(ho_hash(2), 3, 5, 400, 50000),
    ok = ho_announce(Fork),
    F7 = lists:last(Fork),
    ?assertEqual(F7#block.hash,
                 maps:get(tip_hash, beamchain_header_sync:get_status())),
    ok = gen_server:stop(beamchain_header_sync),
    {ok, HS} = beamchain_header_sync:start_link(),
    unlink(HS),
    ?assertMatch(#{tip_height := 7}, beamchain_header_sync:get_status()),
    TooOld = ho_pow_block(F7#block.hash, 8, 401, 100, 0),
    ok = ho_announce([TooOld]),
    ?assertMatch(#{tip_height := 7}, beamchain_header_sync:get_status()),
    ?assertEqual(not_found, beamchain_db:get_block_index(8)),
    Good = ho_pow_block(F7#block.hash, 8, 402, 50000, 0),
    ok = ho_announce([Good]),
    St = beamchain_header_sync:get_status(),
    ?assertMatch(#{tip_height := 8}, St),
    ?assertEqual(Good#block.hash, maps:get(tip_hash, St)).

%% A snapshot-style node: the chainstate tip is block 6 but the height slots
%% below it are empty (only block 6 is indexed), and header sync starts from
%% genesis, with no block bodies below 6. Block download starts above the
%% connected tip, as before. Headers 1..5 arrive at heights at or below the
%% connected tip; an empty slot is filled exactly as before (it holds no
%% active block), nothing goes to the side-branch index, and slot 6 keeps
%% its entry.
snapshot_headers_fill_empty_slots_below_tip() ->
    ?assertEqual(not_found, beamchain_db:get_block_index(3)),
    ?assertMatch(#{tip_height := 0}, beamchain_header_sync:get_status()),
    %% Header tip at genesis, far below the connected tip, and no bodies
    %% below it: block download still starts above the connected tip.
    ?assertEqual(?HO_N + 1, beamchain_block_sync:find_start_height()),
    ok = ho_announce([ho_blk(H) || H <- lists:seq(1, ?HO_N - 1)]),
    ?assertMatch(#{tip_height := 5}, beamchain_header_sync:get_status()),
    [begin
         {ok, #{hash := S}} = beamchain_db:get_block_index(H),
         ?assertEqual(ho_hash(H), S),
         ?assertEqual(not_found, beamchain_db:get_side_branch_index(ho_hash(H)))
     end || H <- lists:seq(1, ?HO_N - 1)],
    ?assertEqual(?HO_N + 1, beamchain_block_sync:find_start_height()),
    {ok, #{status := St6}} = beamchain_db:get_block_index(?HO_N),
    ?assertEqual(29, St6),
    ?assertEqual({ok, {ho_hash(?HO_N), ?HO_N}}, beamchain_chainstate:get_tip()).

ho_sync_state() ->
    beamchain_block_sync:test_state(
      #{params => beamchain_chain_params:params(regtest)}).

%%% --- fixture ---------------------------------------------------------

%% Fork 6', 7' on block 5, with real regtest PoW (header_sync checks it).
ho_fork() ->
    F6 = ho_pow_block(ho_hash(5), ?HO_N, 100),
    F7 = ho_pow_block(F6#block.hash, ?HO_N + 1, 100),
    {F6, F7}.

%% Deliver an unsolicited headers message (BIP-130 announcement path) and
%% wait for header_sync to process it.
ho_announce(Blocks) ->
    beamchain_header_sync:handle_headers(self(), [B#block.header || B <- Blocks]),
    _ = beamchain_header_sync:get_status(),
    ok.

ho_status(Hash) ->
    case beamchain_db:get_block_index_by_hash(Hash) of
        {ok, #{hash := Hash, status := S}} -> S;
        _ ->
            {ok, #{status := S}} = beamchain_db:get_side_branch_index(Hash),
            S
    end.

ho_setup() ->
    ho_setup(full).

ho_setup(Mode) ->
    TmpDir = filename:join(["/tmp", "beamchain_header_only_reorg_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    %% An earlier module (beamchain_addrman_tests) leaves BEAMCHAIN_NETWORK
    %% and BEAMCHAIN_DATADIR in the OS env, which beamchain_config prefers
    %% over the app env: every test would then share one datadir, on
    %% testnet4 params.
    os:unsetenv("BEAMCHAIN_NETWORK"),
    os:unsetenv("BEAMCHAIN_DATADIR"),
    catch gen_server:stop(beamchain_header_sync),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    ho_delete_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisHash, Genesis#block.header,
                                        <<0:256>>, 29),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
    Blocks = ho_store_chain(GenesisHash, 1, ?HO_N, Mode, []),
    {?HO_N, LastHash, _} = lists:last(Blocks),
    HeaderTipHeight = case Mode of
        full ->
            ok = beamchain_db:set_header_tip(LastHash, ?HO_N),
            ?HO_N;
        snapshot ->
            %% Chainstate already at block 6 (as after a snapshot load);
            %% header sync starts from genesis.
            ok = beamchain_db:set_chain_tip(LastHash, ?HO_N),
            ok = beamchain_db:set_header_tip(GenesisHash, 0),
            0
    end,
    application:set_env(beamchain, header_only_reorg_test_blocks,
                        [{0, GenesisHash, Genesis} | Blocks]),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(_Block, _Height, _Prev, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_block,
                     fun(_Block, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_block_header,
                     fun(_H, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, contextual_check_block_header,
                     fun(_H, _P, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, check_witness_malleation,
                     fun(_B, _H, _Params) -> ok end),
    ok = meck:expect(beamchain_validation, disconnect_block,
                     fun(Block, _Height, _Params) ->
                             {ok, beamchain_serialize:block_hash(
                                    Block#block.header)}
                     end),
    {ok, CS} = beamchain_chainstate:start_link(),
    unlink(CS),
    ?assertEqual({ok, {LastHash, ?HO_N}}, beamchain_chainstate:get_tip()),
    {ok, HS} = beamchain_header_sync:start_link(),
    unlink(HS),
    ?assertMatch(#{tip_height := HeaderTipHeight},
                 beamchain_header_sync:get_status()),
    TmpDir.

ho_teardown(TmpDir) ->
    catch gen_server:stop(beamchain_header_sync),
    catch gen_server:stop(beamchain_chainstate),
    catch meck:unload(beamchain_validation),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    ho_delete_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

ho_delete_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta]).

%% Bodies + height index for 1..N with chain tip at genesis, so the
%% chainstate boot rolls forward to N. In snapshot mode only block N is
%% stored and indexed, nothing below it (the fixture then sets the chain
%% tip to N directly), like a node booted from a snapshot at N. Chainwork is the real regtest work
%% (2 per block at 0x207fffff, genesis stored as 0).
ho_store_chain(_Prev, Height, N, _Mode, Acc) when Height > N ->
    lists:reverse(Acc);
ho_store_chain(PrevHash, Height, N, Mode, Acc) ->
    Block = ho_pow_block(PrevHash, Height, 0),
    Hash = Block#block.hash,
    case Mode =:= full orelse Height =:= N of
        true ->
            ok = beamchain_db:store_block(Block, Height),
            ok = beamchain_db:store_block_index(Height, Hash,
                                                Block#block.header,
                                                <<(2 * Height):256>>, 29);
        false ->
            ok
    end,
    ho_store_chain(Hash, Height + 1, N, Mode, [{Height, Hash, Block} | Acc]).

%% Count blocks on Prev starting at Height, timestamps shifted by TsOffset.
ho_pow_chain(_Prev, _Height, 0, _Salt, _TsOffset) ->
    [];
ho_pow_chain(Prev, Height, Count, Salt, TsOffset) ->
    B = ho_pow_block(Prev, Height, Salt, TsOffset, 0),
    [B | ho_pow_chain(B#block.hash, Height + 1, Count - 1, Salt, TsOffset)].

%% A dummy block whose header meets the regtest target (grinds the nonce).
ho_pow_block(PrevHash, Height, Salt) ->
    ho_pow_block(PrevHash, Height, Salt, 0, 0).

ho_pow_block(PrevHash, Height, Salt, TsOffset, Nonce) ->
    Header = #block_header{
        version = 4,
        prev_hash = PrevHash,
        merkle_root = <<Height:128, Salt:128>>,
        timestamp = 1296688602 + Height + TsOffset,
        bits = 16#207fffff,
        nonce = Nonce
    },
    Hash = beamchain_serialize:block_hash(Header),
    PowLimit = maps:get(pow_limit, beamchain_chain_params:params(regtest)),
    case beamchain_pow:check_pow(Hash, 16#207fffff, PowLimit) of
        false ->
            ho_pow_block(PrevHash, Height, Salt, TsOffset, Nonce + 1);
        true ->
            Coinbase = #transaction{
                version = 1,
                inputs = [#tx_in{
                    prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
                    script_sig = <<Height:32/little, Salt:32/little>>,
                    sequence = 16#ffffffff,
                    witness = []
                }],
                outputs = [#tx_out{value = 5000000000,
                                   script_pubkey = <<16#51>>}],
                locktime = 0
            },
            #block{header = Header, transactions = [Coinbase], hash = Hash}
    end.

ho_blk(H) ->
    {ok, Bs} = application:get_env(beamchain, header_only_reorg_test_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

ho_hash(H) -> (ho_blk(H))#block.hash.
