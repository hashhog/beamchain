-module(beamchain_submit_invalid_indexed_tests).

%%% A submitblock that extends the active tip and then fails consensus
%%% validation must leave a FAILED block-index entry behind, as Core's does
%%% (fleet item batch5-beamchain-consensus).
%%%
%%% Core (validation.cpp):
%%%   AcceptBlock (:4298) -- AcceptBlockHeader adds the header to the block
%%%     index (:4233) before CheckBlock/ContextualCheckBlock (:4349) and before
%%%     the body is written (:4373); a failure there runs InvalidBlockFound.
%%%   ConnectTip (:3036-3043) -- ConnectBlock fails with state.IsInvalid() ->
%%%     InvalidBlockFound (:1988) sets BLOCK_FAILED_VALID unless the result
%%%     is BLOCK_MUTATED.
%%%   AcceptBlockHeader (:4186-4224) -- a header that fails CheckBlockHeader /
%%%     ContextualCheckBlockHeader is rejected BEFORE AddToBlockIndex, so it
%%%     leaves no entry.
%%% So getchaintips lists the rejected block as an `invalid` tip (branchlen
%%% 1), and submitting it again answers "duplicate-invalid".
%%%
%%% beamchain bug (master 268903d): the submitblock tip-extension path
%%% returned the connect error and wrote nothing -- no index entry, no
%%% hash-keyed verdict.  getchaintips missed the block (36 Core regtest rows:
%%% chain/tips/final, seed_invalidated_submit/*/tips,
%%% warden_invalidated_submit/*/tips) and a resubmit was validated again.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_submit_invalid_indexed_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(N, 6).
-define(FAILED_VALID, 32).

submit_invalid_indexed_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 60, {"submitblock bad-cb-amount on the tip is an "
                               "invalid tip, branchlen 1",
                               fun connect_verdict_is_invalid_tip/0}} end,
      fun(_) -> {timeout, 60, {"resubmitting the rejected block answers "
                               "duplicate-invalid",
                               fun resubmit_is_duplicate_invalid/0}} end,
      fun(_) -> {timeout, 60, {"the invalid tip survives a restart",
                               fun invalid_tip_survives_restart/0}} end,
      fun(_) -> {timeout, 60, {"a valid sibling still connects; the failed "
                               "block stays an invalid tip",
                               fun valid_sibling_still_connects/0}} end,
      fun(_) -> {timeout, 60, {"header-level verdict leaves no entry",
                               fun header_verdict_leaves_no_entry/0}} end,
      fun(_) -> {timeout, 60, {"mutated or local failures leave no entry",
                               fun non_verdict_leaves_no_entry/0}} end]}.

%%% ===================================================================

connect_verdict_is_invalid_tip() ->
    {ok, _} = start_chainstate(),
    Bad = dummy_block(hash_at(?N), ?N + 1, 1),
    reject_with(Bad, bad_cb_amount),
    ?assertEqual({error, bad_cb_amount},
                 beamchain_chainstate:submit_block(Bad, true)),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()),
    ?assert(beamchain_chainstate:is_known_invalid(Bad#block.hash)),
    {ok, #{status := S}} = beamchain_db:get_side_branch_index(Bad#block.hash),
    ?assertNotEqual(0, S band ?FAILED_VALID),
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(?N + 1, Bad#block.hash, 1, <<"invalid">>)]),
       getchaintips()).

resubmit_is_duplicate_invalid() ->
    {ok, _} = start_chainstate(),
    Bad = dummy_block(hash_at(?N), ?N + 1, 1),
    reject_with(Bad, premature_spend_of_coinbase),
    ?assertEqual({error, premature_spend_of_coinbase},
                 beamchain_chainstate:submit_block(Bad, true)),
    ?assertEqual({error, duplicate_invalid},
                 beamchain_chainstate:submit_block(Bad, true)),
    %% A child of the failed block: Core BLOCK_INVALID_PREV "bad-prevblk".
    Child = dummy_block(Bad#block.hash, ?N + 2, 1),
    ?assertEqual({error, invalid_prevblk},
                 beamchain_chainstate:submit_block(Child, true)),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()).

invalid_tip_survives_restart() ->
    {ok, _} = start_chainstate(),
    Bad = dummy_block(hash_at(?N), ?N + 1, 1),
    reject_with(Bad, {script_verify_failed, 0}),
    ?assertEqual({error, {script_verify_failed, 0}},
                 beamchain_chainstate:submit_block(Bad, true)),
    ok = gen_server:stop(beamchain_chainstate),
    {ok, _} = start_chainstate(),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()),
    ?assertEqual(
       lists:sort([tip(?N, hash_at(?N), 0, <<"active">>),
                   tip(?N + 1, Bad#block.hash, 1, <<"invalid">>)]),
       getchaintips()).

%% A valid block must not be made invalid: the failed sibling at the same
%% height does not block a good block from connecting on the same parent,
%% and the good block takes the height slot without the verdict leaking.
valid_sibling_still_connects() ->
    {ok, _} = start_chainstate(),
    Bad = dummy_block(hash_at(?N), ?N + 1, 1),
    Good = dummy_block(hash_at(?N), ?N + 1, 2),
    reject_with(Bad, bad_cb_amount),
    ?assertEqual({error, bad_cb_amount},
                 beamchain_chainstate:submit_block(Bad, true)),
    ?assertEqual({ok, active}, beamchain_chainstate:submit_block(Good, true)),
    ?assertEqual({ok, {Good#block.hash, ?N + 1}},
                 beamchain_chainstate:get_tip()),
    ?assertNot(beamchain_chainstate:is_known_invalid(Good#block.hash)),
    ?assertEqual(
       lists:sort([tip(?N + 1, Good#block.hash, 0, <<"active">>),
                   tip(?N + 1, Bad#block.hash, 1, <<"invalid">>)]),
       getchaintips()).

%% Core rejects a bad header in AcceptBlockHeader before AddToBlockIndex.
header_verdict_leaves_no_entry() ->
    {ok, _} = start_chainstate(),
    lists:foreach(
      fun({Salt, Reason}) ->
          B = dummy_block(hash_at(?N), ?N + 1, Salt),
          reject_with(B, Reason),
          ?assertEqual({error, Reason},
                       beamchain_chainstate:submit_block(B, true)),
          assert_no_entry(B)
      end,
      [{11, time_too_old}, {12, bad_diffbits}, {13, time_timewarp_attack},
       {14, {check_block_failed, high_hash}}]),
    ?assertEqual([tip(?N, hash_at(?N), 0, <<"active">>)], getchaintips()).

%% Not verdicts about the block: BLOCK_MUTATED (Core InvalidBlockFound skips
%% it -- another copy of the header may be valid), time-too-new, and local
%% failures.  None may mark the block or index it.
non_verdict_leaves_no_entry() ->
    {ok, _} = start_chainstate(),
    lists:foreach(
      fun({Salt, Reason}) ->
          B = dummy_block(hash_at(?N), ?N + 1, Salt),
          reject_with(B, Reason),
          ?assertEqual({error, Reason},
                       beamchain_chainstate:submit_block(B, true)),
          assert_no_entry(B)
      end,
      [{21, bad_witness_commitment}, {22, bad_merkle_root},
       {23, time_too_new}, {24, {internal_error, boom}},
       {25, {script_verify_failed, worker_crashed}}]),
    ?assertEqual([tip(?N, hash_at(?N), 0, <<"active">>)], getchaintips()).

%%% ===================================================================

assert_no_entry(#block{hash = H}) ->
    ?assertNot(beamchain_chainstate:is_known_invalid(H)),
    ?assertEqual(not_found, beamchain_db:get_side_branch_index(H)),
    ?assertEqual({ok, {hash_at(?N), ?N}}, beamchain_chainstate:get_tip()).

%% connect_block answers Reason for this block only.
reject_with(#block{hash = H}, Reason) ->
    {ok, M} = application:get_env(beamchain, submit_invalid_indexed_rejects),
    application:set_env(beamchain, submit_invalid_indexed_rejects,
                        M#{H => Reason}).

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
                            "beamchain_submit_invalid_indexed_test_" ++
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
    application:set_env(beamchain, submit_invalid_indexed_blocks,
                        [{0, GenesisHash, Genesis} | Blocks]),
    application:set_env(beamchain, submit_invalid_indexed_rejects, #{}),
    {module, beamchain_validation} = code:ensure_loaded(beamchain_validation),
    ok = meck:new(beamchain_validation, [no_link, passthrough]),
    ok = meck:expect(beamchain_validation, connect_block,
                     fun(Block, _Height, _Prev, _Params) ->
                             H = beamchain_serialize:block_hash(
                                   Block#block.header),
                             {ok, M} = application:get_env(
                                         beamchain,
                                         submit_invalid_indexed_rejects),
                             case maps:find(H, M) of
                                 {ok, Reason} -> {error, Reason};
                                 error -> ok
                             end
                     end),
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
    {ok, Bs} = application:get_env(beamchain, submit_invalid_indexed_blocks),
    {H, _, B} = lists:keyfind(H, 1, Bs),
    B.

hash_at(H) -> (blk(H))#block.hash.
