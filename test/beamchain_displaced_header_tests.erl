-module(beamchain_displaced_header_tests).

%%% A header-only block-index entry displaced from its height slot must stay
%%% in the index (item refill-20261106-beamchain-consensus).
%%%
%%% Core keeps every block-index entry (BlockManager::m_block_index is never
%%% pruned of headers): after headers 7 and 8 above the tip and a competing
%%% header 7' for height 7, 7 is still LookupBlockIndex-able, 8 is still a
%%% headers-only getchaintips leaf (branchlen 2), and resubmitting 7 is a
%%% no-op (AcceptBlockHeader returns the existing entry).
%%%
%%% beamchain bug (master caba24c): beamchain_db:displaced_entry_ops/5 copied
%%% a displaced entry to the hash-keyed side-branch index only when its body
%%% was stored, so header 7 vanished: getchaintips lost 8 (Core regtest rows
%%% warden_invalidated_submit/p2p-header/tips:$keys and tips:<hash>),
%%% getblockheader 7 answered "not found", and resubmitting 7 stored it back
%%% into slot 7, displacing (and so dropping) 7'.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_displaced_header_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).

displaced_header_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"displaced header stays in the index",
                               fun displaced_header_stays_indexed/0}} end,
      fun(_) -> {timeout, 60, {"resubmitting a displaced header is a no-op",
                               fun resubmit_displaced_header_is_noop/0}} end,
      fun(_) -> {timeout, 60, {"body for a displaced header is not a duplicate",
                               fun body_for_displaced_header_not_duplicate/0}} end,
      fun(_) -> {timeout, 60, {"child of a displaced header is still "
                               "context-checked (real check)",
                               fun child_of_displaced_header_context_checked/0}} end,
      fun(_) -> {timeout, 60, {"body on a header-only displaced parent is "
                               "never connected",
                               fun body_on_header_only_parent_not_connected/0}} end,
      fun(_) -> {timeout, 60, {"invalidateblock marks displaced descendants",
                               fun invalidate_marks_displaced_descendants/0}} end,
      fun(_) -> {timeout, 60, {"fork header below the tip leaves the active "
                               "slot alone",
                               fun fork_header_below_tip_keeps_active_slot/0}} end,
      fun(_) -> {timeout, 60, {"child of a displaced header below the tip "
                               "leaves the active slot alone",
                               fun child_of_displaced_below_tip_keeps_slot/0}} end,
      fun(_) -> {timeout, 60, {"headers above the tip alone: two-tip control",
                               fun no_displacement_control/0}} end]}.

%%% ===================================================================

%% Headers 7, 8 on the tip, then 7' on the tip takes height slot 7.
displace() ->
    H7 = dummy_block(hash_at(?N), ?N + 1, 0),
    H8 = dummy_block(H7#block.hash, ?N + 2, 0),
    H7b = dummy_block(hash_at(?N), ?N + 1, 5),
    [?assertEqual({ok, accepted},
                  beamchain_chainstate:submit_header(B#block.header))
     || B <- [H7, H8, H7b]],
    {H7, H8, H7b}.

displaced_header_stays_indexed() ->
    {ok, _} = start_chainstate(),
    {H7, _H8, H7b} = displace(),
    ?assertMatch({ok, #{hash := _}}, beamchain_db:get_block_index(?N + 1)),
    {ok, #{hash := Slot}} = beamchain_db:get_block_index(?N + 1),
    ?assertEqual(H7b#block.hash, Slot),
    ?assertMatch({ok, #{height := 7}},
                 beamchain_db:get_side_branch_index(H7#block.hash)),
    ?assertEqual(?N + 1, maps:get(<<"height">>, getblockheader(H7#block.hash))).

resubmit_displaced_header_is_noop() ->
    {ok, _} = start_chainstate(),
    {H7, H8, H7b} = displace(),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(H7#block.header)),
    {ok, #{hash := Slot}} = beamchain_db:get_block_index(?N + 1),
    ?assertEqual(H7b#block.hash, Slot),
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(?N + 2, H8#block.hash, 2, <<"headers-only">>),
                   tip(?N + 1, H7b#block.hash, 1, <<"headers-only">>)]),
       getchaintips()).

%% Header 8' on 7 takes slot 8 from header 8.  Then the bodies of 7 and 8'
%% and a block 9 on 8' are connected, so header 8 (still header-only, kept
%% in the side-branch index) has less work than the tip.  Its body is then
%% submitted: a side block that leaves the tip alone.  Core AcceptBlock:
%% fAlreadyHave = nStatus & BLOCK_HAVE_DATA, false for a header-only entry,
%% so submitblock answers "inconclusive" (beamchain side_branch), never
%% "duplicate".
body_for_displaced_header_not_duplicate() ->
    {ok, _} = start_chainstate(),
    H7 = dummy_block(hash_at(?N), ?N + 1, 0),
    H8 = dummy_block(H7#block.hash, ?N + 2, 0),
    H8b = dummy_block(H7#block.hash, ?N + 2, 5),
    [?assertEqual({ok, accepted},
                  beamchain_chainstate:submit_header(B#block.header))
     || B <- [H7, H8, H8b]],
    B9 = dummy_block(H8b#block.hash, ?N + 3, 5),
    [?assertEqual({ok, active}, beamchain_chainstate:submit_block(B, true))
     || B <- [H7, H8b, B9]],
    ?assertEqual({ok, {B9#block.hash, ?N + 3}}, beamchain_chainstate:get_tip()),
    ?assertMatch({ok, _}, beamchain_db:get_side_branch_index(H8#block.hash)),
    Result = beamchain_chainstate:submit_block(H8, true),
    io:format(user, "~nsubmit_block(body of displaced header 8) -> ~p~n", [Result]),
    ?assertEqual({ok, side_branch}, Result),
    ?assertEqual({ok, {B9#block.hash, ?N + 3}}, beamchain_chainstate:get_tip()).

%% Risk: a header whose parent is a displaced header-only entry used to be
%% refused (unknown prev) and is now checked against that parent.  It must
%% go through the same ContextualCheckBlockHeader as any header: the real
%% check runs here (not the fixture's mock), so a timestamp at or below the
%% parent's median time past and a wrong nBits are both refused, and only
%% the well-formed child is accepted.
child_of_displaced_header_context_checked() ->
    ok = meck:expect(beamchain_validation, contextual_check_block_header,
                     fun(H, P, Params) -> meck:passthrough([H, P, Params]) end),
    {ok, _} = start_chainstate(),
    {H7, _H8, _H7b} = displace(),
    ?assertMatch({ok, _}, beamchain_db:get_side_branch_index(H7#block.hash)),
    Base = (dummy_block(H7#block.hash, ?N + 2, 9))#block.header,
    TooOld = Base#block_header{timestamp = 1296688602},
    BadBits = Base#block_header{bits = 16#1d00ffff},
    ?assertEqual({error, time_too_old},
                 beamchain_chainstate:submit_header(TooOld)),
    ?assertEqual({error, bad_diffbits},
                 beamchain_chainstate:submit_header(BadBits)),
    ?assertEqual({ok, accepted}, beamchain_chainstate:submit_header(Base)).

%% Risk: a header-only side entry must never be connected.  Header 7 is
%% displaced by 7'; the body of 8 (more work than the tip) is submitted on
%% top of header-only 7.  Nothing can connect without 7's body, so the tip
%% stays put, and neither 7 nor 8 is marked invalid (Core AcceptBlock
%% stores 8; ActivateBestChain cannot reach it: no data for 7).
body_on_header_only_parent_not_connected() ->
    {ok, _} = start_chainstate(),
    {H7, H8, _H7b} = displace(),
    Result = beamchain_chainstate:submit_block(H8, true),
    io:format(user, "~nsubmit_block(8 on header-only 7) -> ~p~n", [Result]),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()),
    ?assertNot(beamchain_chainstate:is_known_invalid(H7#block.hash)),
    ?assertNot(beamchain_chainstate:is_known_invalid(H8#block.hash)).

%% Risk: invalidateblock must reach every descendant (Core InvalidateBlock
%% marks every block-index entry descending from the failed block),
%% including a displaced header-only entry and the height slot above it
%% whose parent it is.  reconsiderblock clears them all again.
invalidate_marks_displaced_descendants() ->
    {ok, _} = start_chainstate(),
    {H7, H8, H7b} = displace(),
    ok = beamchain_chainstate:invalidate_block(hash_at(5)),
    [?assert(beamchain_chainstate:is_known_invalid(B#block.hash))
     || B <- [H7, H8, H7b]],
    ?assertEqual(
       lists:sort([tip(4, hash_at(4), 0, <<"active">>),
                   tip(?N + 2, H8#block.hash, 4, <<"invalid">>),
                   tip(?N + 1, H7b#block.hash, 3, <<"invalid">>)]),
       getchaintips()),
    ok = beamchain_chainstate:reconsider_block(hash_at(5)),
    [?assertNot(beamchain_chainstate:is_known_invalid(B#block.hash))
     || B <- [H7, H8, H7b]].

%% Core AcceptBlockHeader only adds a hash-keyed entry.  A fork header for
%% a height at or below the tip must not take the active chain's height
%% slot (master wrote it there: slot 3 then named the fork header, and
%% getblockhash 3 with it).  It is kept hash-keyed and reported as a
%% headers-only fork.
fork_header_below_tip_keeps_active_slot() ->
    {ok, _} = start_chainstate(),
    Side = dummy_block(hash_at(2), 3, 7),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(Side#block.header)),
    {ok, #{hash := Slot3}} = beamchain_db:get_block_index(3),
    ?assertEqual(hash_at(3), Slot3),
    ?assertMatch({ok, #{height := 3}},
                 beamchain_db:get_side_branch_index(Side#block.hash)),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()),
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(3, Side#block.hash, 1, <<"headers-only">>)]),
       getchaintips()).

%% Header 7 is displaced by 7', then 7' and blocks 8', 9' on it are
%% connected, so 7 sits below the tip as a side entry.  A new header 8* on
%% 7 resolves its parent now that 7 is kept; it must be stored hash-keyed,
%% leaving the connected block in slot 8 in place.
child_of_displaced_below_tip_keeps_slot() ->
    {ok, _} = start_chainstate(),
    {H7, _H8, H7b} = displace(),
    B8 = dummy_block(H7b#block.hash, ?N + 2, 5),
    B9 = dummy_block(B8#block.hash, ?N + 3, 5),
    [?assertEqual({ok, active}, beamchain_chainstate:submit_block(B, true))
     || B <- [H7b, B8, B9]],
    ?assertEqual({ok, {B9#block.hash, ?N + 3}}, beamchain_chainstate:get_tip()),
    Star = dummy_block(H7#block.hash, ?N + 2, 11),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(Star#block.header)),
    {ok, #{hash := Slot8}} = beamchain_db:get_block_index(?N + 2),
    ?assertEqual(B8#block.hash, Slot8),
    ?assertMatch({ok, #{height := 8}},
                 beamchain_db:get_side_branch_index(Star#block.hash)),
    ?assertEqual({ok, {B9#block.hash, ?N + 3}}, beamchain_chainstate:get_tip()).

%% Control: no displacement, so the old and new code agree.
no_displacement_control() ->
    {ok, _} = start_chainstate(),
    H7 = dummy_block(hash_at(?N), ?N + 1, 0),
    ?assertEqual({ok, accepted},
                 beamchain_chainstate:submit_header(H7#block.header)),
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(?N + 1, H7#block.hash, 1, <<"headers-only">>)]),
       getchaintips()).

%%% ===================================================================

getblockheader(Hash) ->
    Hex = beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Hash)),
    Reply = beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>,
                                     <<"id">> => <<"gbh">>,
                                     <<"method">> => <<"getblockheader">>,
                                     <<"params">> => [Hex, true]}, undefined),
    Envelope = case Reply of
        {raw_json, Bin} -> jsx:decode(Bin, [return_maps]);
        M when is_map(M) -> M
    end,
    #{<<"error">> := null, <<"result">> := Result} = Envelope,
    case Result of
        R when is_map(R) -> R;
        L when is_list(L) -> maps:from_list(L)
    end.

getchaintips() ->
    #{<<"error">> := null, <<"result">> := Result} =
        beamchain_rpc:dispatch(#{<<"jsonrpc">> => <<"1.0">>,
                                 <<"id">> => <<"gct">>,
                                 <<"method">> => <<"getchaintips">>,
                                 <<"params">> => []}, undefined),
    lists:sort([maps:from_list(T) || T <- Result]).

tip(Height, Hash, BranchLen, Status) ->
    #{<<"height">> => Height,
      <<"hash">> => beamchain_serialize:hex_encode(
                      beamchain_serialize:reverse_bytes(Hash)),
      <<"branchlen">> => BranchLen,
      <<"status">> => Status}.

setup() ->
    TmpDir = filename:join(["/tmp",
                            "beamchain_displaced_header_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    catch gen_server:stop(beamchain_header_sync),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    Genesis = beamchain_chain_params:genesis_block(regtest),
    GenesisHash = Genesis#block.hash,
    ok = beamchain_db:store_block(Genesis, 0),
    ok = beamchain_db:store_block_index(0, GenesisHash,
                                        Genesis#block.header, <<0:256>>, 29),
    ok = beamchain_db:set_chain_tip(GenesisHash, 0),
    Blocks = store_dummy_chain(GenesisHash, 1, ?N, []),
    {?N, LastHash, _} = lists:last(Blocks),
    ok = beamchain_db:set_header_tip(LastHash, ?N),
    application:set_env(beamchain, displaced_header_test_blocks,
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
                             {ok, beamchain_serialize:block_hash(Block#block.header)}
                     end),
    TmpDir.

teardown(TmpDir) ->
    catch gen_server:stop(beamchain_header_sync),
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

%% [{Height, Hash, Block}] for 1..N; bodies + height index stored, chain tip
%% at genesis, so the chainstate boot rolls forward to N.
store_dummy_chain(_Prev, Height, N, Acc) when Height > N ->
    lists:reverse(Acc);
store_dummy_chain(PrevHash, Height, N, Acc) ->
    Block = dummy_block(PrevHash, Height, 0),
    Hash = Block#block.hash,
    ok = beamchain_db:store_block(Block, Height),
    ok = beamchain_db:store_block_index(Height, Hash, Block#block.header,
                                        <<Height:256>>, 29),
    store_dummy_chain(Hash, Height + 1, N, [{Height, Hash, Block} | Acc]).

dummy_block(PrevHash, Height, Salt) ->
    Header = #block_header{
        version = 4,
        prev_hash = PrevHash,
        merkle_root = <<Height:128, Salt:128>>,
        timestamp = 1296688602 + Height,
        bits = 16#207fffff,
        nonce = Height + Salt
    },
    Hash = beamchain_serialize:block_hash(Header),
    Coinbase = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<Height:32/little, Salt:32/little>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000, script_pubkey = <<16#51>>}],
        locktime = 0
    },
    #block{header = Header, transactions = [Coinbase], hash = Hash}.

start_chainstate() ->
    {ok, Pid} = beamchain_chainstate:start_link(),
    unlink(Pid),
    {ok, Pid}.

blk(H) ->
    {ok, Bs} = application:get_env(beamchain, displaced_header_test_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

hash_at(H) -> (blk(H))#block.hash.

genesis_hash() -> hash_at(0).
