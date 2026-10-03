-module(beamchain_invalid_block_p2p_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% A peer delivers a block that fails CONSENSUS validation over P2P.
%%%
%%% Core (validation.cpp Chainstate::InvalidBlockFound / InvalidChainFound,
%%% net_processing.cpp BlockChecked -> MaybePunishNodeForBlock): the block
%%% is marked BLOCK_FAILED_VALID (+ descendants), never requested again,
%%% the peer that DELIVERED it is punished, and the node moves on to the
%%% valid competitor. BLOCK_MUTATED and local errors are NOT verdicts.
%%%
%%% Observed before the fix (tools/p2p-invalid-block-feed.py, badcb,
%%% 2026-10-03): the height was requested ~232k times from the HONEST peer
%%% (notfound re-queued it to the front and the same peer was asked again),
%%% the delivered invalid block was retried 3x and block download halted
%%% for good, and the attacker's ban killed the peer manager (inbound peers
%%% were start_link'ed to it), dropping the honest peer too.
%%%
%%% These drive the gen_server callbacks directly on a scripted state with
%%% meck on every collaborator (same harness shape as
%%% beamchain_block_sync_tests' frontier tests).
%%% ===================================================================

-define(BS_MOCKED, [beamchain_db, beamchain_peer, beamchain_peer_manager,
                    beamchain_chainstate, beamchain_validation,
                    beamchain_serialize, beamchain_sync,
                    beamchain_header_sync]).

%%% ===================================================================
%%% Pure: verdict vs non-verdict classification
%%% ===================================================================

verdict_classification_test_() ->
    V = fun beamchain_block_sync:is_consensus_verdict/1,
    Verdicts = [bad_cb_amount, bad_txns_nonfinal, sequence_lock_not_met,
                missing_inputs, bad_blk_sigops, {script_verify_failed, 3},
                {check_block_failed, bad_blk_length}],
    NonVerdicts = [%% BLOCK_MUTATED: another copy of the header may be valid
                   bad_merkle_root, mutated_merkle, dup_txid,
                   bad_witness_commitment, bad_witness_nonce_size,
                   unexpected_witness, missing_witness_commitment,
                   {check_block_failed, mutated_merkle},
                   %% missing parent / ordering
                   bad_prevblk, missing_prev_index,
                   %% BLOCK_TIME_FUTURE
                   time_too_new,
                   %% local failures
                   {exit_during_connect, {timeout, x}},
                   {internal_error, badarg},
                   {post_validation_failure, timeout},
                   {script_verify_failed, killed},
                   script_check_worker_crash, missing_undo_data,
                   some_future_token, "string"],
    [?_assert(V(R)) || R <- Verdicts] ++
        [?_assertNot(V(R)) || R <- NonVerdicts].

%%% ===================================================================
%%% block_sync: the P2P failure path
%%% ===================================================================

bs_setup() ->
    Tab = ets:new(ibp2p_tip, [set, public]),
    ets:insert(Tab, {tip, {height_hash(99), 99}}),
    ets:insert(Tab, {connect_result, ok}),
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, ?BS_MOCKED),
    ok = meck:expect(beamchain_db, get_block_index,
        fun(H) ->
            {ok, #{hash => height_hash(H), header => mk_header(H),
                   chainwork => H, n_tx => 1}}
        end),
    ok = meck:expect(beamchain_db, store_block_index,
        fun(_, _, _, _, _) -> ok end),
    ok = meck:expect(beamchain_db, store_block_index,
        fun(_, _, _, _, _, _) -> ok end),
    ok = meck:expect(beamchain_peer, send_message, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, disconnect, fun(_) -> ok end),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer_manager, get_peers, fun() -> [] end),
    ok = meck:expect(beamchain_peer_manager, misbehaving,
                     fun(_, _, _) -> ok end),
    ok = meck:expect(beamchain_chainstate, get_tip,
        fun() -> [{tip, T}] = ets:lookup(Tab, tip), {ok, T} end),
    ok = meck:expect(beamchain_chainstate, connect_block,
        fun(#block{header = #block_header{merkle_root = <<H:256>>}}) ->
            case ets:lookup(Tab, connect_result) of
                [{connect_result, ok}] ->
                    ets:insert(Tab, {tip, {height_hash(H), H}}),
                    ok;
                [{connect_result, Err}] ->
                    Err
            end
        end),
    ok = meck:expect(beamchain_chainstate, invalid_block_found,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_validation, check_block,
        fun(_, _) ->
            case ets:lookup(Tab, check_result) of
                [{check_result, Err}] -> Err;
                [] -> ok
            end
        end),
    ok = meck:expect(beamchain_serialize, block_hash,
        fun(#block_header{merkle_root = MR}) -> MR end),
    ok = meck:expect(beamchain_sync, notify_blocks_complete,
        fun(_) -> ok end),
    ok = meck:expect(beamchain_header_sync, invalid_block_found,
        fun(_, _, _) -> ok end),
    put(getdata_seen, 0),
    Tab.

bs_teardown(Tab) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?BS_MOCKED),
    ets:delete(Tab),
    flush_all().

block_sync_test_() ->
    {foreach, fun bs_setup/0, fun bs_teardown/1,
     [fun(T) -> {"consensus-invalid block: marked failed, DELIVERING peer "
                 "punished (not the honest one), never re-requested",
                 fun() -> invalid_block_marked_and_not_rerequested(T) end}
      end,
      fun(T) -> {"notfound: the peer is not asked again (no hot loop); "
                 "the height waits for a peer that has it",
                 fun() -> notfound_peer_not_reasked(T) end}
      end,
      fun(T) -> {"NON-verdict (local exit during connect): not marked, "
                 "nobody punished, retried",
                 fun() -> non_verdict_retried(T, {error, {exit_during_connect,
                                                         timeout}}, connect)
                 end}
      end,
      fun(T) -> {"NON-verdict (BLOCK_MUTATED bad_merkle_root): not marked, "
                 "nobody punished, retried",
                 fun() -> non_verdict_retried(T, {error, bad_merkle_root},
                                              check)
                 end}
      end]}.

%% The instrument's `before` shape: honest H (connected first) does not
%% have the block at 100; attacker X does and it is invalid.
invalid_block_marked_and_not_rerequested(Tab) ->
    ets:insert(Tab, {connect_result, {error, bad_cb_amount}}),
    H = spawn(fun() -> receive stop -> ok end end),
    X = spawn(fun() -> receive stop -> ok end end),
    S0 = two_peer_state(H, X),
    B = height_hash(100),

    {noreply, S1} = beamchain_block_sync:handle_info(continue_validation, S0),
    ?assertEqual([{H, B}], new_requests()),

    %% H answers notfound -> X is asked, H is not asked again.
    {noreply, S2} = beamchain_block_sync:handle_cast(
                      {notfound, H, [{?MSG_WITNESS_BLOCK, B}]}, S1),
    ?assertEqual([{X, B}], new_requests()),

    %% X delivers the block; it fails consensus validation.
    {noreply, S3} = beamchain_block_sync:handle_cast({block, X, mk_block(100)},
                                                     S2),
    ?assert(meck:called(beamchain_chainstate, invalid_block_found, [B])),
    ?assertEqual(1, meck:num_calls(beamchain_peer_manager, misbehaving,
                                   [X, '_', '_'])),
    ?assertEqual(0, meck:num_calls(beamchain_peer_manager, misbehaving,
                                   [H, '_', '_'])),
    ?assert(meck:called(beamchain_header_sync, invalid_block_found,
                        [B, 100, X])),
    ?assertEqual(0, meck:num_calls(beamchain_peer, disconnect, [H])),

    %% Nothing on that branch is requested again: not by the validation
    %% loop, the watchdog, nor a peer (re)connecting.
    {noreply, S4} = beamchain_block_sync:handle_info(continue_validation, S3),
    {noreply, S5} = beamchain_block_sync:handle_info(stall_check, S4),
    {noreply, S6} = beamchain_block_sync:handle_info(stall_check, S5),
    {noreply, _S7} = beamchain_block_sync:handle_cast(
                       {peer_connected, X, #{}}, S6),
    ?assertEqual([], [R || {_, Hash} = R <- new_requests(), Hash =:= B]),
    ?assertEqual(1, request_count(X, B)),
    ?assertEqual(1, request_count(H, B)),
    H ! stop, X ! stop.

notfound_peer_not_reasked(_Tab) ->
    H = spawn(fun() -> receive stop -> ok end end),
    B = height_hash(100),
    Now = erlang:monotonic_time(millisecond),
    S0 = beamchain_block_sync:test_state(#{
        status => syncing, next_to_validate => 100, target_height => 100,
        download_queue => [100], in_flight => #{}, hash_to_height => #{},
        downloaded => #{}, peers => #{H => #{}}, peer_stats => #{H => 0}}),
    {noreply, S1} = beamchain_block_sync:handle_info(continue_validation, S0),
    ?assertEqual([{H, B}], new_requests()),
    {noreply, S2} = beamchain_block_sync:handle_cast(
                      {notfound, H, [{?MSG_WITNESS_BLOCK, B}]}, S1),
    {noreply, S3} = beamchain_block_sync:handle_info(continue_validation, S2),
    ?assertEqual([], new_requests()),
    ?assert(lists:member(100, beamchain_block_sync:test_get(download_queue,
                                                            S3))),
    %% A peer that has it connects -> it is asked.
    X = spawn(fun() -> receive stop -> ok end end),
    {noreply, _S4} = beamchain_block_sync:handle_cast(
                       {peer_connected, X, #{}}, S3),
    ?assertEqual([{X, B}], new_requests()),
    _ = Now,
    H ! stop, X ! stop.

non_verdict_retried(Tab, Err, Where) ->
    case Where of
        connect -> ets:insert(Tab, {connect_result, Err});
        check -> ets:insert(Tab, {check_result, Err})
    end,
    X = spawn(fun() -> receive stop -> ok end end),
    B = height_hash(100),
    S0 = beamchain_block_sync:test_state(#{
        status => syncing, next_to_validate => 100, target_height => 100,
        download_queue => [100], in_flight => #{}, hash_to_height => #{},
        downloaded => #{}, peers => #{X => #{}}, peer_stats => #{X => 0}}),
    {noreply, S1} = beamchain_block_sync:handle_info(continue_validation, S0),
    ?assertEqual([{X, B}], new_requests()),
    {noreply, S2} = beamchain_block_sync:handle_cast({block, X, mk_block(100)},
                                                     S1),
    ?assertNot(meck:called(beamchain_chainstate, invalid_block_found, '_')),
    ?assertNot(meck:called(beamchain_header_sync, invalid_block_found, '_')),
    ?assertNot(meck:called(beamchain_peer_manager, misbehaving, '_')),
    ?assertNot(meck:called(beamchain_peer, add_misbehavior, '_')),
    ?assertEqual(syncing, beamchain_block_sync:test_get(status, S2)),
    ?assertEqual(#{100 => 1},
                 beamchain_block_sync:test_get(validation_failures, S2)),
    %% retried: requested again
    ?assertEqual([{X, B}], new_requests()),
    X ! stop.

two_peer_state(H, X) ->
    beamchain_block_sync:test_state(#{
        status => syncing, next_to_validate => 100, target_height => 100,
        download_queue => [100], in_flight => #{}, hash_to_height => #{},
        downloaded => #{}, peers => #{H => #{}, X => #{}},
        peer_stats => #{H => 0, X => 0}}).

%%% ===================================================================
%%% beamchain_peer: an inbound peer's exit must not take the manager down
%%% ===================================================================

inbound_peer_exit_does_not_kill_manager_test() ->
    ok = meck:new(beamchain_config, [no_link, passthrough]),
    ok = meck:expect(beamchain_config, magic, fun() -> <<16#fabfb5da:32>> end),
    try
        {ok, L} = gen_tcp:listen(0, [binary, {active, false},
                                     {ip, {127, 0, 0, 1}}]),
        {ok, Port} = inet:port(L),
        {ok, C} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary,
                                                         {active, false}]),
        {ok, A} = gen_tcp:accept(L),
        Self = self(),
        %% A stand-in manager that, like beamchain_peer_manager, does NOT
        %% trap exits.
        Mgr = spawn(fun() ->
            {ok, P} = beamchain_peer:accept(A, {{127, 0, 0, 2}, 1}, self()),
            Self ! {peer, P},
            receive stop -> ok end
        end),
        ok = gen_tcp:controlling_process(A, Mgr),
        Peer = receive {peer, P} -> P after 5000 -> error(no_peer) end,
        MRef = erlang:monitor(process, Peer),
        exit(Peer, {shutdown, banned}),
        receive {'DOWN', MRef, process, Peer, _} -> ok
        after 5000 -> error(peer_not_down) end,
        timer:sleep(50),
        ?assert(is_process_alive(Mgr)),
        Mgr ! stop,
        gen_tcp:close(C),
        gen_tcp:close(L)
    after
        meck:unload(beamchain_config)
    end.

%%% ===================================================================
%%% header_sync: cached-invalid headers, equal-work forks, rewind
%%% ===================================================================

-define(HS_MOCKED, [beamchain_db, beamchain_chainstate, beamchain_peer,
                    beamchain_peer_manager, beamchain_sync,
                    beamchain_serialize, beamchain_pow, beamchain_config]).

%% Hash of the block at height H on the main chain is <<H:256>>; the
%% attacker's block at 21 is ?B1 (child of <<20:256>>).
-define(B1, <<16#b1:256>>).

hs_setup() ->
    Tab = ets:new(ibp2p_hs, [set, public]),
    ets:insert(Tab, {invalid, []}),
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, ?HS_MOCKED),
    %% Main chain known up to 22 in the height index.
    ok = meck:expect(beamchain_db, get_block_index,
        fun(H) when H =< 22 ->
                case ets:lookup(Tab, {slot, H}) of
                    [{_, Hash}] ->
                        {ok, #{hash => Hash, header => mk_header(H),
                               chainwork => <<H:256>>, height => H}};
                    [] ->
                        {ok, #{hash => height_hash(H), header => mk_header(H),
                               chainwork => <<H:256>>, height => H}}
                end;
           (_) -> not_found
        end),
    ok = meck:expect(beamchain_db, get_block_index_by_hash,
        fun(<<H:256>>) when H =< 22 ->
                {ok, #{hash => height_hash(H), header => mk_header(H),
                       chainwork => <<H:256>>, height => H}};
           (_) -> not_found
        end),
    ok = meck:expect(beamchain_db, store_block_index,
                     fun(_, _, _, _, _) -> ok end),
    ok = meck:expect(beamchain_db, set_header_tip, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_chainstate, is_known_invalid,
        fun(Hash) -> [{invalid, L}] = ets:lookup(Tab, invalid),
                     lists:member(Hash, L) end),
    ok = meck:expect(beamchain_chainstate, get_tip,
                     fun() -> {ok, {height_hash(20), 20}} end),
    ok = meck:expect(beamchain_peer, send_message, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer_manager, mark_headers_received,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_peer_manager, mark_getheaders_sent,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_peer_manager, update_peer_height,
                     fun(_, _) -> ok end),
    ok = meck:expect(beamchain_sync, notify_headers_complete,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_serialize, block_hash,
        fun(#block_header{merkle_root = MR}) -> MR end),
    ok = meck:expect(beamchain_config, prune_enabled, fun() -> false end),
    ok = meck:expect(beamchain_config, network, fun() -> regtest end),
    ok = meck:expect(beamchain_pow, check_pow, fun(_, _, _) -> true end),
    ok = meck:expect(beamchain_pow, compute_work, fun(_) -> 1 end),
    ok = meck:expect(beamchain_pow, permitted_difficulty_transition,
                     fun(_, _, _, _) -> true end),
    ok = meck:expect(beamchain_pow, get_next_work_required,
        fun(_, #block_header{bits = Bits}, _) -> Bits end),
    Tab.

hs_teardown(Tab) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?HS_MOCKED),
    ets:delete(Tab),
    flush_all().

hs_state(TipH, Peers) ->
    beamchain_header_sync:test_state(#{
        status => complete, tip_height => TipH, tip_hash => height_hash(TipH),
        tip_chainwork => <<TipH:256>>,
        mtp_window => [{H, 1296688602 + H} || H <- lists:seq(TipH - 10, TipH)],
        params => #{pow_limit => <<16#7fffff:24, 0:232>>, checkpoints => #{}},
        peer_heights => Peers}).

header_sync_test_() ->
    {foreach, fun hs_setup/0, fun hs_teardown/1,
     [fun(T) -> {"a header we found invalid is refused (never re-requested) "
                 "and the announcing peer is not punished",
                 fun() -> cached_invalid_header_refused(T) end} end,
      fun(T) -> {"an equal-work fork off a known block is not 'unconnecting' "
                 "(no getheaders loop, no ban)",
                 fun() -> equal_work_fork_not_unconnecting(T) end} end,
      fun(T) -> {"invalid_block_found rewinds the header chain to the "
                 "parent and asks a peer other than the culprit",
                 fun() -> rewind_on_invalid_block(T) end} end]}.

cached_invalid_header_refused(Tab) ->
    ets:insert(Tab, {invalid, [?B1]}),
    X = spawn(fun() -> receive stop -> ok end end),
    S0 = hs_state(20, #{X => 21}),
    Hdr = (mk_header(21))#block_header{merkle_root = ?B1},
    {noreply, S1} = beamchain_header_sync:handle_cast({headers, X, [Hdr]}, S0),
    ?assertNot(meck:called(beamchain_db, store_block_index, '_')),
    ?assertNot(meck:called(beamchain_peer, add_misbehavior, '_')),
    ?assertEqual(20, beamchain_header_sync:test_get(tip_height, S1)),
    ?assertNot(maps:is_key(X, beamchain_header_sync:test_get(peer_heights,
                                                             S1))),
    X ! stop.

equal_work_fork_not_unconnecting(_Tab) ->
    X = spawn(fun() -> receive stop -> ok end end),
    S0 = hs_state(21, #{X => 21}),
    Hdr = (mk_header(21))#block_header{merkle_root = ?B1},
    SN = lists:foldl(fun(_, S) ->
        {noreply, S2} = beamchain_header_sync:handle_cast({headers, X, [Hdr]},
                                                          S),
        S2
    end, S0, lists:seq(1, 12)),
    ?assertNot(meck:called(beamchain_peer, add_misbehavior, '_')),
    ?assertNot(meck:called(beamchain_peer, send_message,
                           [X, {getheaders, '_'}])),
    ?assertNot(meck:called(beamchain_db, store_block_index, '_')),
    ?assertEqual(21, beamchain_header_sync:test_get(tip_height, SN)),
    X ! stop.

rewind_on_invalid_block(Tab) ->
    ets:insert(Tab, {{slot, 21}, ?B1}),
    H = spawn(fun() -> receive stop -> ok end end),
    X = spawn(fun() -> receive stop -> ok end end),
    S0 = hs_state(22, #{H => 20, X => 22}),
    {noreply, S1} = beamchain_header_sync:handle_cast(
                      {invalid_block_found, ?B1, 21, X}, S0),
    ?assertEqual(20, beamchain_header_sync:test_get(tip_height, S1)),
    ?assertEqual(height_hash(20), beamchain_header_sync:test_get(tip_hash, S1)),
    ?assert(meck:called(beamchain_db, set_header_tip, [height_hash(20), 20])),
    ?assert(meck:called(beamchain_peer, send_message, [H, {getheaders, '_'}])),
    ?assertNot(meck:called(beamchain_peer, send_message,
                           [X, {getheaders, '_'}])),
    %% A stale notice (our header chain is not on that block) is a no-op.
    {noreply, S2} = beamchain_header_sync:handle_cast(
                      {invalid_block_found, <<16#dead:256>>, 21, X}, S1),
    ?assertEqual(20, beamchain_header_sync:test_get(tip_height, S2)),
    H ! stop, X ! stop.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

height_hash(H) -> <<H:256>>.

mk_header(H) ->
    #block_header{
        version     = 1,
        prev_hash   = height_hash(H - 1),
        merkle_root = height_hash(H),
        timestamp   = 1296688602 + H,
        bits        = 16#207fffff,
        nonce       = 0
    }.

mk_block(H) ->
    #block{header = mk_header(H), transactions = []}.

all_requests() ->
    lists:append(
      [[{Peer, Hash} || #{hash := Hash} <- Items]
       || {_Pid, {beamchain_peer, send_message,
                  [Peer, {getdata, #{items := Items}}]}, _Ret}
              <- meck:history(beamchain_peer)]).

new_requests() ->
    All = all_requests(),
    Seen = case get(getdata_seen) of undefined -> 0; N -> N end,
    put(getdata_seen, length(All)),
    lists:nthtail(min(Seen, length(All)), All).

request_count(Peer, Hash) ->
    length([1 || {P, Hs} <- all_requests(), P =:= Peer, Hs =:= Hash]).

flush_all() ->
    receive _ -> flush_all() after 0 -> ok end.
