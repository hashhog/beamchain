-module(beamchain_download_pipeline_tests).

%%% ===================================================================
%%% perf-fix-beamchain-download-pipeline
%%%
%%% Block download used to keep 32 blocks in flight in total, buffer at
%%% most 32 blocks / 64 MB of DECODED terms, and validate inside the
%%% download process: while a block connected, no block arrival was
%%% handled and no getdata went out, so download and connect took turns.
%%% Now: 128 in flight in total (16 per peer, Core's
%%% MAX_BLOCKS_IN_TRANSIT_PER_PEER), a byte-capped buffer of RAW wire
%%% payloads, and each block connected by a worker process while the
%%% download process carries on. Blocks still connect strictly in height
%%% order, one at a time.
%%%
%%% Most tests run the real beamchain_block_sync gen_server (started with
%%% start_link/0, driven through its public API: start_sync/1,
%%% handle_block/2, get_status/0, stall_check) with its collaborators
%%% mocked. The chainstate mock checks prev_hash against its tip, so a
%%% block connected out of order fails loudly.
%%% ===================================================================

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(MOCKS, [beamchain_config, beamchain_db, beamchain_header_chain,
                beamchain_chainstate, beamchain_validation, beamchain_peer,
                beamchain_peer_manager, beamchain_sync,
                beamchain_header_sync]).
-define(T, beamchain_dl_pipeline_tab).

%%% ===================================================================
%%% Fixture
%%% ===================================================================

setup() ->
    catch ets:delete(?T),
    ets:new(?T, [named_table, public, set]),
    ets:insert(?T, {seq, 0}),
    lists:foreach(fun(M) -> ok = meck:new(M, [no_link]) end, ?MOCKS),
    ok = meck:expect(beamchain_config, network, fun() -> regtest end),
    ok = meck:expect(beamchain_db, get_block_index_by_hash,
                     fun(_) -> not_found end),
    ok = meck:expect(beamchain_db, has_block, fun(_) -> false end),
    ok = meck:expect(beamchain_db, get_header_tip,
        fun() ->
            [{header_tip, H}] = ets:lookup(?T, header_tip),
            {ok, #{height => H, hash => hash_at_height(H)}}
        end),
    ok = meck:expect(beamchain_db, get_block,
        fun(Hash) ->
            case ets:lookup(?T, {body, Hash}) of
                [{_, B}] -> {ok, B};
                [] -> not_found
            end
        end),
    ok = meck:expect(beamchain_header_chain, hash_at,
        fun(H) ->
            case ets:lookup(?T, {hdr, H}) of
                [{_, Hash}] -> {ok, Hash};
                [] -> not_found
            end
        end),
    ok = meck:expect(beamchain_chainstate, is_chain_paused,
                     fun() -> ets:lookup(?T, paused) =/= [] end),
    ok = meck:expect(beamchain_chainstate, is_known_invalid, fun(_) -> false end),
    ok = meck:expect(beamchain_chainstate, get_tip,
        fun() -> [{tip, T}] = ets:lookup(?T, tip), {ok, T} end),
    ok = meck:expect(beamchain_chainstate, get_tip_height,
        fun() -> [{tip, {_, H}}] = ets:lookup(?T, tip), {ok, H} end),
    ok = meck:expect(beamchain_chainstate, connect_block, fun mock_connect/1),
    ok = meck:expect(beamchain_chainstate, submit_block, fun mock_submit/1),
    ok = meck:expect(beamchain_chainstate, invalid_block_found,
                     fun(_) -> ok end),
    ok = meck:expect(beamchain_validation, check_block, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, send_message,
        fun(P, {getdata, #{items := Items}}) ->
                ets:insert(?T, {{getdata, next_seq()}, P,
                                [H || #{hash := H} <- Items]}),
                ok;
           (_, _) -> ok
        end),
    ok = meck:expect(beamchain_peer, add_misbehavior, fun(_, _) -> ok end),
    ok = meck:expect(beamchain_peer, disconnect, fun(_) -> ok end),
    ok = meck:expect(beamchain_peer_manager, get_peers,
        fun() ->
            [{peers, Ps}] = ets:lookup(?T, peers),
            [#{pid => P, connected => true, info => #{}} || P <- Ps]
        end),
    ok = meck:expect(beamchain_peer_manager, misbehaving,
                     fun(_, _, _) -> ok end),
    ok = meck:expect(beamchain_sync, notify_blocks_complete, fun(_) -> ok end),
    ok = meck:expect(beamchain_header_sync, invalid_block_found,
                     fun(_, _, _) -> ok end),
    ok = meck:expect(beamchain_header_sync, probe_peer, fun(_) -> ok end),
    ok = meck:expect(beamchain_header_sync, handle_headers,
                     fun(_, _) -> ok end),
    ok.

teardown(_) ->
    case whereis(beamchain_block_sync) of
        undefined -> ok;
        Pid -> unlink(Pid), exit(Pid, kill), wait_dead(Pid)
    end,
    [P ! stop || {peers, Ps} <- ets:tab2list(?T), P <- Ps],
    application:unset_env(beamchain, block_download_buffer_mb),
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKS),
    catch ets:delete(?T),
    ok.

wait_dead(Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive {'DOWN', Ref, process, Pid, _} -> ok after 5000 -> ok end.

next_seq() -> ets:update_counter(?T, seq, 1).

%%% ===================================================================
%%% Chain fixture
%%% ===================================================================

%% Blocks 1..N on top of a connected tip at height 0. Pad adds an output
%% of that many bytes, to give blocks a wire size.
make_chain(N, Pad) ->
    Base = <<16#aa:256>>,
    ets:insert(?T, {{hdr, 0}, Base}),
    ets:insert(?T, {{height_of, Base}, 0}),
    ets:insert(?T, {tip, {Base, 0}}),
    build(1, N, Base, Pad, chain_a).

%% Blocks From..To on Prev, tagged so two branches differ. Each block's
%% header is registered as the header chain's block at its height.
build(From, To, _Prev, _Pad, _Tag) when From > To ->
    ok;
build(H, To, Prev, Pad, Tag) ->
    B = mk_block(H, Prev, Pad, Tag),
    Hash = beamchain_serialize:block_hash(B#block.header),
    ets:insert(?T, {{hdr, H}, Hash}),
    ets:insert(?T, {{block, H}, B}),
    ets:insert(?T, {{height_of, Hash}, H}),
    ets:insert(?T, {{body, Hash}, B}),
    build(H + 1, To, Hash, Pad, Tag).

mk_block(H, Prev, Pad, Tag) ->
    TagN = case Tag of chain_a -> 1; chain_b -> 2 end,
    Coinbase = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = <<3, H:24/little, TagN>>,
                         sequence = 16#ffffffff,
                         witness = undefined}],
        outputs = [#tx_out{value = 50 * 100000000,
                           script_pubkey = <<16#51>>}] ++
                  [#tx_out{value = 0, script_pubkey = binary:copy(<<0>>, Pad)}
                   || Pad > 0],
        locktime = 0},
    Root = beamchain_serialize:compute_merkle_root(
             [beamchain_serialize:tx_hash(Coinbase)]),
    Header = #block_header{version = 4, prev_hash = Prev, merkle_root = Root,
                           timestamp = 1296688602 + H, bits = 16#207fffff,
                           nonce = TagN},
    #block{header = Header, transactions = [Coinbase]}.

block(H) -> [{_, B}] = ets:lookup(?T, {block, H}), B.
raw(H) -> beamchain_p2p_msg:encode_payload(block, block(H)).
hash_at_height(H) ->
    case ets:lookup(?T, {hdr, H}) of [{_, Hash}] -> Hash; [] -> <<0:256>> end.
height_of(Hash) -> [{_, H}] = ets:lookup(?T, {height_of, Hash}), H.

%%% ===================================================================
%%% Chainstate mock: in-order connect, optional gate per height
%%% ===================================================================

%% connect_block extends the tip only: a block whose prev_hash is not the
%% tip is refused (bad_prevblk), so an out-of-order connect cannot pass.
mock_connect(#block{header = #block_header{prev_hash = Prev} = Hdr}) ->
    Hash = beamchain_serialize:block_hash(Hdr),
    H = height_of(Hash),
    gate(H),
    note_off_header_chain(H, Hash),
    [{tip, {TipHash, _}}] = ets:lookup(?T, tip),
    case ets:lookup(?T, {verdict, H}) of
        [{_, V}] ->
            {error, V};
        [] when Prev =:= TipHash ->
            ets:insert(?T, {tip, {Hash, H}}),
            ets:insert(?T, {{connected, next_seq()}, connect, H, Hash}),
            ok;
        [] ->
            ets:insert(?T, {{connected, next_seq()}, out_of_order, H, Hash}),
            {error, bad_prevblk}
    end.

%% submit_block for the reorg test: store a side-branch block; once the
%% branch is longer than the connected chain, flip the tip to it.
mock_submit(#block{header = Hdr}) ->
    Hash = beamchain_serialize:block_hash(Hdr),
    H = height_of(Hash),
    gate(H),
    note_off_header_chain(H, Hash),
    [{tip, {_, TipH}}] = ets:lookup(?T, tip),
    ets:insert(?T, {{connected, next_seq()}, submit, H, Hash}),
    case H > TipH of
        true -> ets:insert(?T, {tip, {Hash, H}}), {ok, reorg};
        false -> {ok, side_branch}
    end.

%% Record a block handed to the chainstate that is not, at that moment, the
%% header chain's block at its height: block download must never do that.
note_off_header_chain(H, Hash) ->
    case ets:lookup(?T, {hdr, H}) of
        [{_, Hash}] -> ok;
        _ -> ets:insert(?T, {{off_header_chain, next_seq()}, H, Hash})
    end.

off_header_chain() ->
    [{H, Hash} || {{off_header_chain, _}, H, Hash} <- ets:tab2list(?T)].

%% A gated height blocks the connecting process until released, as a
%% slow chainstate connect holds its caller.
gate(H) ->
    case ets:lookup(?T, {gate, H}) of
        [{_, closed}] ->
            ets:insert(?T, {{in_connect, H}, self()}),
            receive {release, H} -> ok after 20000 -> ok end;
        _ ->
            ok
    end.

close_gate(H) -> ets:insert(?T, {{gate, H}, closed}).

release_gate(H) ->
    ets:insert(?T, {{gate, H}, open}),
    case wait_until(fun() -> ets:lookup(?T, {in_connect, H}) =/= [] end,
                    2000) of
        true -> [{_, Pid}] = ets:lookup(?T, {in_connect, H}),
                Pid ! {release, H};
        false -> ok
    end.

in_connect(H) -> ets:lookup(?T, {in_connect, H}) =/= [].

connect_log() ->
    [{Seq, Kind, H} || {{connected, Seq}, Kind, H, _} <- ets:tab2list(?T)].

connected_heights() ->
    [H || {_, Kind, H} <- lists:sort(connect_log()), Kind =/= out_of_order].

%%% ===================================================================
%%% Server + peer helpers
%%% ===================================================================

start(NPeers, Target) ->
    Peers = [spawn(fun() -> receive stop -> ok end end)
             || _ <- lists:seq(1, NPeers)],
    ets:insert(?T, {peers, Peers}),
    ets:insert(?T, {header_tip, Target}),
    {ok, Pid} = beamchain_block_sync:start_link(),
    unlink(Pid),
    ok = beamchain_block_sync:start_sync(#{target_height => Target}),
    _ = status(5000),
    Peers.

status(Timeout) ->
    try gen_server:call(beamchain_block_sync, get_status, Timeout)
    catch exit:{timeout, _} -> timeout
    end.

state() -> sys:get_state(beamchain_block_sync, 5000).

%% {Peer, Hash} for every getdata item sent so far, in send order.
requests() ->
    lists:append(
      [[{P, Hash} || Hash <- Hashes]
       || {_, P, Hashes} <- lists:sort([{S, P, Hs} ||
                                        {{getdata, S}, P, Hs}
                                            <- ets:tab2list(?T)])]).

requested_hashes() -> [H || {_, H} <- requests()].

%% Serve every getdata item sent so far exactly once (a re-request of
%% the same block is a new item and is served again), using
%% Deliver(Height) for the payload and Order to arrange each round, until
%% nothing new is asked for and validation is idle. Returns the number of
%% rounds.
serve_all(Deliver, Order) ->
    serve_all(Deliver, Order, 0, 0).

serve_all(Deliver, Order, Served, Rounds) when Rounds < 5000 ->
    All = requests(),
    case lists:nthtail(Served, All) of
        [] ->
            settle(),
            case length(requests()) > Served of
                true -> serve_all(Deliver, Order, Served, Rounds + 1);
                false -> Rounds
            end;
        Pending ->
            lists:foreach(
              fun({P, Hash}) ->
                      beamchain_block_sync:handle_block(P, Deliver(height_of(Hash)))
              end, Order(Pending)),
            settle(),
            serve_all(Deliver, Order, length(All), Rounds + 1)
    end.

%% Wait until block_sync has handled everything sent so far and no block
%% is connecting. (A build without validation workers has no `connecting`
%% field; test_get then raises and there is nothing to wait for.)
settle() ->
    wait_until(fun() ->
                   S = state(),
                   not_connecting(S) andalso no_runnable_worker()
               end, 5000),
    _ = state(),
    ok.

not_connecting(S) ->
    case catch beamchain_block_sync:test_get(connecting, S) of
        undefined -> true;
        {'EXIT', {function_clause, _}} -> true;
        _ -> false
    end.

no_runnable_worker() ->
    {message_queue_len, N} =
        process_info(whereis(beamchain_block_sync), message_queue_len),
    N =:= 0.

wait_until(F, Ms) when Ms =< 0 -> F();
wait_until(F, Ms) ->
    case F() of
        true -> true;
        false -> timer:sleep(10), wait_until(F, Ms - 10)
    end.

decoded(H) -> block(H).

in_order(L) -> L.
reversed(L) -> lists:reverse(L).

%%% ===================================================================
%%% Tests
%%% ===================================================================

pipeline_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{"getdata keeps going out while a block connects",
       fun getdata_flows_during_connect/0},
      {"blocks connect in height order when they arrive out of order "
       "(decoded blocks; reference behaviour)",
       fun out_of_order_decoded/0},
      {"blocks connect in height order when raw payloads arrive out of "
       "order",
       fun out_of_order_raw/0},
      {"the buffer holds raw payloads and never exceeds its byte cap",
       fun raw_buffer_byte_cap/0},
      {"128 blocks in flight across 8 peers, 16 per peer",
       fun window_128_in_flight/0},
      {"a stalled peer's blocks are re-requested (inline validation; "
       "reference behaviour)",
       fun() -> stalled_peer_rerequested(false) end},
      {"a stalled peer's blocks are re-requested (async validation)",
       fun() -> stalled_peer_rerequested(true) end},
      {"watchdog ticks during a long connect do not drop the peer",
       fun long_connect_is_not_a_stall/0},
      {"a reorg during IBD connects the heavier branch in order "
       "(decoded blocks; reference behaviour)",
       fun reorg_during_ibd_decoded/0},
      {"a reorg during IBD connects the heavier branch in order "
       "(raw payloads)",
       fun reorg_during_ibd_raw/0},
      {"a verdict for a block connecting when chain_invalidated arrives "
       "is still applied (reference behaviour)",
       fun verdict_survives_concurrent_invalidate/0},
      {"a check_block verdict on the block after a connecting one marks "
       "it invalid (reference behaviour)",
       fun prepared_check_verdict/0},
      {"a mutated body on the block after a connecting one is "
       "re-requested, not marked (reference behaviour)",
       fun prepared_check_mutation/0},
      {"a re-plan while connecting is paused never connects the block "
       "that was prepared for the old plan (reference behaviour)",
       fun replan_during_pause/0},
      {"an undecodable payload under a requested header is scored and "
       "re-requested, not marked invalid",
       fun undecodable_solicited_payload/0},
      {"an undecodable unsolicited payload is scored 20",
       fun undecodable_unsolicited_payload/0}]}.

%% A connect is held at height 1. With validation inside the download
%% process (base) nothing else happens until it returns: get_status times
%% out and blocks 2..16, already delivered, free no request slots. With a
%% validation worker the server answers and requests 17..32 meanwhile.
getdata_flows_during_connect() ->
    make_chain(64, 0),
    close_gate(1),
    [P] = start(1, 64),
    First = requested_hashes(),
    ?assertEqual([hash_at_height(H) || H <- lists:seq(1, 16)], First),
    [beamchain_block_sync:handle_block(P, decoded(H)) || H <- lists:seq(1, 16)],
    ?assert(wait_until(fun() -> in_connect(1) end, 2000)),
    %% Still connecting height 1: the server answers and has asked for
    %% the next 16 blocks.
    ?assertMatch(#{next_to_validate := 1}, status(1000)),
    ?assert(wait_until(
              fun() -> lists:member(hash_at_height(32), requested_hashes())
              end, 2000)),
    ?assert(in_connect(1)),
    ?assertEqual([], connected_heights()),
    release_gate(1),
    serve_all(fun decoded/1, fun in_order/1),
    ?assertEqual(lists:seq(1, 64), connected_heights()),
    ?assertMatch(#{status := complete, next_to_validate := 65}, status(5000)).

out_of_order_decoded() ->
    out_of_order(fun decoded/1).

out_of_order_raw() ->
    out_of_order(fun raw/1).

%% Two peers; every round is delivered in reverse request order, so each
%% block arrives after the ones above it.
out_of_order(Deliver) ->
    make_chain(300, 0),
    _ = start(2, 300),
    serve_all(Deliver, fun reversed/1),
    ?assertEqual(lists:seq(1, 300), connected_heights()),
    ?assertEqual([], [X || {_, out_of_order, _} = X <- connect_log()]),
    ?assertMatch(#{status := complete, next_to_validate := 301}, status(5000)).

%% 8 MiB cap (app env), ~100 KB blocks. Block 1 is withheld, so nothing
%% connects and the buffer only grows. After every delivery the buffered
%% bytes stay within the cap and every buffered value is the raw payload;
%% the cap, not the count, is what stops requests. Then block 1 arrives
%% and everything connects in order.
raw_buffer_byte_cap() ->
    application:set_env(beamchain, block_download_buffer_mb, 8),
    Cap = 8 * 1024 * 1024,
    ?assertEqual(Cap, beamchain_block_sync:max_downloaded_bytes()),
    make_chain(200, 100000),
    Size = byte_size(raw(2)),
    Peers = start(4, 200),
    Hash1 = hash_at_height(1),
    MaxSeen = fill_without(Hash1, Peers, sets:new(), 0, Cap),
    S = state(),
    D = beamchain_block_sync:test_get(downloaded, S),
    Bytes = beamchain_block_sync:test_get(downloaded_bytes, S),
    ?assert(MaxSeen =< Cap),
    ?assert(Bytes =< Cap),
    ?assertEqual(Bytes, lists:sum([byte_size(V) || V <- maps:values(D)])),
    ?assert(lists:all(fun is_binary/1, maps:values(D))),
    %% The byte cap is the binding limit: the buffer is within one block
    %% of the estimated budget, well short of the count cap.
    ?assert(Bytes + 20 * Size >= Cap),
    ?assert(maps:size(D) < beamchain_block_sync:max_downloaded_ahead()),
    ?assertEqual(1, beamchain_block_sync:test_get(next_to_validate, S)),
    [P1 | _] = Peers,
    beamchain_block_sync:handle_block(P1, raw(1)),
    settle(),
    S2 = state(),
    ?assert(beamchain_block_sync:test_get(downloaded_bytes, S2) =< Cap),
    serve_all(fun raw/1, fun in_order/1),
    ?assertEqual(lists:seq(1, 200), connected_heights()).

%% Serve everything requested except Hash1, checking the cap after every
%% delivered block, until no new request appears.
fill_without(Hash1, Peers, Served, MaxSeen, Cap) ->
    Pending = [{P, Hash} || {P, Hash} <- requests(), Hash =/= Hash1,
                            not sets:is_element({P, Hash}, Served)],
    case Pending of
        [] ->
            MaxSeen;
        _ ->
            Max2 = lists:foldl(
                     fun({P, Hash}, M) ->
                         beamchain_block_sync:handle_block(
                           P, raw(height_of(Hash))),
                         B = beamchain_block_sync:test_get(downloaded_bytes,
                                                           state()),
                         ?assert(B =< Cap),
                         max(M, B)
                     end, MaxSeen, Pending),
            fill_without(Hash1, Peers,
                         lists:foldl(fun sets:add_element/2, Served, Pending),
                         Max2, Cap)
    end.

%% Eight peers and a long queue: the first fill puts 128 blocks in flight,
%% 16 at each peer (base: 32 in total).
window_128_in_flight() ->
    make_chain(1000, 0),
    Peers = start(8, 1000),
    ?assertMatch(#{in_flight_count := 128}, status(5000)),
    PerPeer = [length([1 || {Q, _} <- requests(), Q =:= P]) || P <- Peers],
    ?assertEqual(lists:duplicate(8, 16), PerPeer).

%% Peer A was asked for 100..115 ten minutes ago and never answered. A
%% stall_check re-queues them (A is dropped after its third stall) and
%% asks again; once A's disconnect is handled, B is asked for them. Run on
%% a scripted state through the callbacks, in both validation modes.
stalled_peer_rerequested(Async) ->
    make_chain(140, 0),
    A = spawn(fun() -> receive stop -> ok end end),
    B = spawn(fun() -> receive stop -> ok end end),
    ets:insert(?T, {peers, [A, B]}),
    Old = erlang:monotonic_time(millisecond) - 600000,
    Stalled = lists:seq(100, 115),
    Base = #{status           => syncing,
             next_to_validate => 100,
             target_height    => 140,
             download_queue   => lists:seq(116, 140),
             in_flight        => maps:from_list(
                                   [{H, {A, Old, hash_at_height(H)}}
                                    || H <- Stalled]),
             hash_to_height   => maps:from_list(
                                   [{hash_at_height(H), H} || H <- Stalled]),
             downloaded       => #{},
             peers            => #{A => #{}, B => #{}},
             peer_stats       => #{A => 16, B => 0}},
    S0 = beamchain_block_sync:test_state(
           case Async of
               true -> Base#{async_validate => true};
               false -> Base
           end),
    {noreply, S1} = beamchain_block_sync:handle_info(stall_check, S0),
    ?assert(meck:called(beamchain_peer, disconnect, [A])),
    Again = requested_hashes(),
    ?assert(lists:member(hash_at_height(100), Again)),
    %% Every stalled height is back in the frontier with a fresh request
    %% or queued; none is still attributed to the old request.
    IF1 = beamchain_block_sync:test_get(in_flight, S1),
    Q1 = beamchain_block_sync:test_get(download_queue, S1),
    lists:foreach(
      fun(H) ->
          case maps:find(H, IF1) of
              {ok, {_, At, _}} -> ?assert(At > Old);
              error -> ?assert(lists:member(H, Q1))
          end
      end, Stalled),
    {noreply, S2} = beamchain_block_sync:handle_cast(
                      {peer_disconnected, A}, S1),
    FromB = [Hash || {P, Hash} <- requests(), P =:= B],
    ?assert(lists:member(hash_at_height(100), FromB)),
    IF2 = beamchain_block_sync:test_get(in_flight, S2),
    ?assertEqual([], [H || {H, {P, _, _}} <- maps:to_list(IF2), P =:= A]),
    A ! stop, B ! stop.

%% Height 1 takes "minutes" to connect. Watchdog ticks during it must not
%% treat the held block as a download stall and drop the peer. (Master
%% handles the ticks only after the connect returns, back to back, with
%% 17 just requested: two at one height escalate to force_unstick and the
%% only peer is killed.)
long_connect_is_not_a_stall() ->
    make_chain(40, 0),
    close_gate(1),
    [P] = start(1, 40),
    [beamchain_block_sync:handle_block(P, decoded(H)) || H <- lists:seq(1, 16)],
    ?assert(wait_until(fun() -> in_connect(1) end, 2000)),
    [beamchain_block_sync ! stall_check || _ <- lists:seq(1, 3)],
    _ = status(1000),
    ?assertEqual(0, meck:num_calls(beamchain_peer, disconnect, '_')),
    release_gate(1),
    serve_all(fun decoded/1, fun in_order/1),
    ?assertEqual(lists:seq(1, 40), connected_heights()),
    ?assertEqual(0, meck:num_calls(beamchain_peer, disconnect, '_')).

reorg_during_ibd_decoded() ->
    reorg_during_ibd(fun decoded/1).

reorg_during_ibd_raw() ->
    reorg_during_ibd(fun raw/1).

%% Connected chain A 0..5; the header chain is A 0..3 then branch B 4..9.
%% Download must start at the fork (4), submit B4..B6 through the reorg
%% path (B6 overtakes A5), then connect B7..B9 on the new tip, in order.
reorg_during_ibd(Deliver) ->
    make_chain(5, 0),
    [{_, A3}] = ets:lookup(?T, {hdr, 3}),
    [{_, A5}] = ets:lookup(?T, {hdr, 5}),
    ets:insert(?T, {tip, {A5, 5}}),
    build(4, 9, A3, 0, chain_b),
    _ = start(1, 9),
    ?assertEqual([hash_at_height(H) || H <- lists:seq(4, 9)],
                 requested_hashes()),
    serve_all(Deliver, fun reversed/1),
    Log = [{K, H} || {_, K, H} <- lists:sort(connect_log())],
    ?assertEqual([{submit, 4}, {submit, 5}, {submit, 6},
                  {connect, 7}, {connect, 8}, {connect, 9}], Log),
    ?assertEqual([{tip, {hash_at_height(9), 9}}], ets:lookup(?T, tip)),
    ?assertMatch(#{status := complete, next_to_validate := 10}, status(5000)).

%% Block 1's connect returns a consensus verdict while a chain_invalidated
%% cast is waiting. The verdict must still be applied (block marked
%% failed, header sync told) -- the deferred cast runs after it.
verdict_survives_concurrent_invalidate() ->
    make_chain(20, 0),
    ets:insert(?T, {{verdict, 1}, bad_cb_amount}),
    close_gate(1),
    [P] = start(1, 20),
    beamchain_block_sync:handle_block(P, decoded(1)),
    ?assert(wait_until(fun() -> in_connect(1) end, 2000)),
    gen_server:cast(beamchain_block_sync, chain_invalidated),
    release_gate(1),
    ?assert(wait_until(
              fun() ->
                  meck:called(beamchain_chainstate, invalid_block_found,
                              [hash_at_height(1)])
              end, 5000)),
    ?assert(meck:called(beamchain_header_sync, invalid_block_found,
                        [hash_at_height(1), 1, P])),
    ?assertMatch(#{status := idle}, status(5000)).

%% check_block fails for height Bad with Reason (only on the first Times
%% calls for that height), ok otherwise.
fail_check(Bad, Reason, Times) ->
    ets:insert(?T, {{check_fail, Bad}, Times}),
    ok = meck:expect(beamchain_validation, check_block,
        fun(#block{header = Hdr}, _) ->
            H = height_of(beamchain_serialize:block_hash(Hdr)),
            case ets:lookup(?T, {check_fail, H}) of
                [{_, N}] when N > 0 ->
                    ets:insert(?T, {{check_fail, H}, N - 1}),
                    {error, Reason};
                _ ->
                    ok
            end
        end).

%% Block 2 is buffered while block 1 connects, so with validation workers
%% its context-free check runs ahead, in the prepared worker. A consensus
%% verdict from that check must still be applied when block 2's turn comes:
%% block 2 marked invalid, its sender punished, download stopped.
prepared_check_verdict() ->
    make_chain(20, 0),
    fail_check(2, first_tx_not_coinbase, 1000),
    close_gate(1),
    [P] = start(1, 20),
    [beamchain_block_sync:handle_block(P, decoded(H)) || H <- [1, 2, 3]],
    ?assert(wait_until(fun() -> in_connect(1) end, 2000)),
    release_gate(1),
    ?assert(wait_until(
              fun() ->
                  meck:called(beamchain_chainstate, invalid_block_found,
                              [hash_at_height(2)])
              end, 5000)),
    ?assert(meck:called(beamchain_peer_manager, misbehaving, [P, 100, '_'])),
    ?assertEqual([1], connected_heights()),
    ?assertMatch(#{status := idle}, status(5000)).

%% Same, but the check says BLOCK_MUTATED (bad_merkle_root): not a verdict.
%% Block 2 is dropped and asked for again, nothing is marked, and the good
%% copy then connects.
prepared_check_mutation() ->
    make_chain(20, 0),
    fail_check(2, bad_merkle_root, 1),
    close_gate(1),
    [P] = start(1, 20),
    [beamchain_block_sync:handle_block(P, decoded(H)) || H <- [1, 2, 3]],
    ?assert(wait_until(fun() -> in_connect(1) end, 2000)),
    release_gate(1),
    %% Keep serving: block 2 is asked for again (once a request slot is
    %% free) and its good copy connects.
    serve_all(fun decoded/1, fun in_order/1),
    ?assert(length([1 || H <- requested_hashes(),
                         H =:= hash_at_height(2)]) >= 2),
    ?assertNot(meck:called(beamchain_chainstate, invalid_block_found, '_')),
    ?assertEqual(lists:seq(1, 20), connected_heights()).

%% Block 1 connects while block 2 (branch A) is buffered, so with
%% validation workers A2 is decoded and checked ahead in a prepared worker.
%% Right then a chain pause starts (dumptxoutset rollback), and while paused
%% the plan changes: the header chain now has branch B from height 2 and
%% download is re-planned (chain_invalidated + start_sync). After the pause
%% B2 arrives. Every block handed to the chainstate must be the header
%% chain's block at its height at that moment -- A2 must not be connected
%% by a worker left over from the old plan.
replan_during_pause() ->
    make_chain(30, 0),
    close_gate(1),
    [P] = start(1, 30),
    [beamchain_block_sync:handle_block(P, decoded(H)) || H <- [1, 2, 3]],
    ?assert(wait_until(fun() -> in_connect(1) end, 2000)),
    ets:insert(?T, {paused}),
    release_gate(1),
    ?assert(wait_until(fun() -> lists:member(1, connected_heights()) end,
                       5000)),
    settle(),
    A1 = hash_at_height(1),
    build(2, 30, A1, 0, chain_b),
    gen_server:cast(beamchain_block_sync, chain_invalidated),
    ok = beamchain_block_sync:start_sync(#{target_height => 30}),
    _ = status(5000),
    ets:delete(?T, paused),
    serve_all(fun decoded/1, fun in_order/1),
    ?assertEqual([], off_header_chain()),
    ?assertEqual([{tip, {hash_at_height(30), 30}}], ets:lookup(?T, tip)),
    ?assertMatch(#{status := complete, next_to_validate := 31}, status(5000)).

%% The requested header followed by garbage: it does not decode. Not a
%% verdict about the header -- the sender is scored 20 (as beamchain_sync
%% scored an undecodable block), nothing is marked, the height is asked
%% for again, and the real block then connects.
undecodable_solicited_payload() ->
    make_chain(10, 0),
    [P] = start(1, 10),
    <<Hdr:80/binary, _/binary>> = raw(1),
    Bad = <<Hdr/binary, 1, 16#ff, 16#ff>>,
    ?assertMatch({error, _}, beamchain_p2p_msg:decode_payload(block, Bad)),
    beamchain_block_sync:handle_block(P, Bad),
    ?assert(wait_until(
              fun() -> meck:called(beamchain_peer, add_misbehavior, [P, 20])
              end, 5000)),
    ?assertNot(meck:called(beamchain_chainstate, invalid_block_found, '_')),
    ?assert(wait_until(
              fun() ->
                  length([1 || H <- requested_hashes(),
                               H =:= hash_at_height(1)]) >= 2
              end, 5000)),
    serve_all(fun raw/1, fun in_order/1),
    ?assertEqual(lists:seq(1, 10), connected_heights()).

%% Shorter than a header, during sync and after it: scored 20, no crash.
undecodable_unsolicited_payload() ->
    make_chain(3, 0),
    [P] = start(1, 3),
    beamchain_block_sync:handle_block(P, <<1>>),
    beamchain_block_sync:handle_block(P, <<0:80/unit:8>>),
    ?assert(wait_until(
              fun() ->
                  meck:num_calls(beamchain_peer, add_misbehavior, [P, 20]) =:= 2
              end, 5000)),
    Pid = whereis(beamchain_block_sync),
    ?assert(is_pid(Pid)),
    serve_all(fun raw/1, fun in_order/1),
    ?assertMatch(#{status := complete}, status(5000)),
    beamchain_block_sync:handle_block(P, <<0:80/unit:8>>),
    ?assert(wait_until(
              fun() ->
                  meck:num_calls(beamchain_peer, add_misbehavior, [P, 20]) =:= 3
              end, 5000)),
    ?assertEqual(Pid, whereis(beamchain_block_sync)).
