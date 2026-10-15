%%% Output-shape parity with Bitcoin Core v31: these tests pin the SHAPE of
%%% RPC output (strings, field order, rounding, chunk fields).  None of them
%%% changes what the mempool or the miner accepts.
-module(beamchain_output_shape_tests).
-include_lib("eunit/include/eunit.hrl").

-define(A, <<1:256>>).
-define(B, <<2:256>>).
-define(C, <<3:256>>).
-define(D, <<4:256>>).

%%% -- chunkweight / fees.chunk (KB-169) --------------------------------

chunk_singleton_test() ->
    ?assertEqual({437, 2000},
                 beamchain_mempool_chunks:chunk_of(?A, #{?A => {2000, 437, []}})).

%% Low-fee parent + high-fee child: the child pays for the parent, one chunk.
chunk_cpfp_merges_test() ->
    Nodes = #{?A => {100, 340, []}, ?B => {50000, 340, [?A]}},
    ?assertEqual({680, 50100}, beamchain_mempool_chunks:chunk_of(?A, Nodes)),
    ?assertEqual({680, 50100}, beamchain_mempool_chunks:chunk_of(?B, Nodes)).

%% High-fee parent + low-fee child: they stay separate chunks.
chunk_parent_pays_for_itself_test() ->
    Nodes = #{?A => {50000, 340, []}, ?B => {100, 340, [?A]}},
    ?assertEqual({340, 50000}, beamchain_mempool_chunks:chunk_of(?A, Nodes)),
    ?assertEqual({340, 100}, beamchain_mempool_chunks:chunk_of(?B, Nodes)).

%% A rich grandchild lifts a poor chain: ancestor set {A,B,C} beats every
%% smaller prefix, so all three are one chunk.
chunk_grandchild_lifts_chain_test() ->
    Nodes = #{?A => {10, 100, []}, ?B => {10, 100, [?A]},
              ?C => {10000, 100, [?B]}},
    ?assertEqual({300, 10020}, beamchain_mempool_chunks:chunk_of(?A, Nodes)).

%% Two children of one parent: the rich child pulls the parent in, the poor
%% sibling stays alone.
chunk_siblings_test() ->
    Nodes = #{?A => {100, 100, []}, ?B => {9000, 100, [?A]},
              ?C => {200, 100, [?A]}},
    ?assertEqual({200, 9100}, beamchain_mempool_chunks:chunk_of(?B, Nodes)),
    ?assertEqual({100, 200}, beamchain_mempool_chunks:chunk_of(?C, Nodes)).

%%% -- submitpackage package_msg / error strings (KB-173) ---------------

package_msg_tx_failure_test() ->
    Reason = {tx_failed, <<7:256>>, {script_verify_failed, 0}},
    ?assertEqual(<<"transaction failed">>, beamchain_rpc:package_msg(Reason)),
    ?assertEqual(<<"transaction failed">>,
                 beamchain_rpc:package_msg(missing_inputs)).

package_msg_structural_test() ->
    ?assertEqual(<<"package-not-child-with-parents">>,
                 beamchain_rpc:package_msg(package_not_child_with_parents)),
    ?assertEqual(<<"package-too-many-transactions">>,
                 beamchain_rpc:package_msg(package_too_many_transactions)),
    ?assertEqual(<<"conflict-in-package">>,
                 beamchain_rpc:package_msg(conflict_in_package)).

package_msg_is_never_an_erlang_term_test() ->
    Reasons = [{tx_failed, <<7:256>>, dust}, missing_inputs, orphan,
               package_not_sorted, {some, odd, tuple}, an_atom],
    lists:foreach(fun(R) ->
        Msg = beamchain_rpc:package_msg(R),
        ?assertEqual(nomatch, binary:match(Msg, [<<"{">>, <<"<<">>, <<"_">>]))
    end, Reasons).

package_tx_error_test() ->
    ?assertEqual(<<"bad-txns-inputs-missingorspent">>,
                 beamchain_rpc:package_tx_error(missing_inputs)),
    ?assertEqual(<<"bad-txns-inputs-missingorspent">>,
                 beamchain_rpc:package_tx_error(
                   {tx_failed, <<7:256>>, orphan})),
    E = beamchain_rpc:package_tx_error(
          {tx_failed, <<7:256>>, {script_verify_failed, 0}}),
    ?assertEqual(nomatch, binary:match(E, [<<"{">>, <<"<<">>])).

%%% -- effective-feerate rounding ---------------------------------------

%% Core CFeeRate(fee, size).GetFeePerK(): integer sat/kvB, truncated, shown
%% with 8 decimals.  1_000_000 sat over 110 vB is 9_090_909 sat/kvB; 1000 sat
%% over 110 vB is 9_090 sat/kvB; 100 sat over 85 vB is 1_176 sat/kvB.
feerate_truncates_to_sat_per_kvb_test() ->
    ?assertEqual(<<"0.00009090">>, fmt(beamchain_rpc:feerate_btc_per_kvb(1000, 110))),
    ?assertEqual(<<"0.09090909">>,
                 fmt(beamchain_rpc:feerate_btc_per_kvb(1000000, 110))),
    ?assertEqual(<<"0.00001176">>, fmt(beamchain_rpc:feerate_btc_per_kvb(100, 85))).

feerate_has_no_sub_satoshi_digits_test() ->
    F = beamchain_rpc:feerate_btc_per_kvb(1000000, 110),
    ?assertEqual(F, round(F * 100000000) / 100000000.0).

fmt(F) -> iolist_to_binary(io_lib:format("~.8f", [F])).

%%% -- getblocktemplate rules order (KB-170) ----------------------------

gbt_rules_follow_deployment_order_test() ->
    {Rules, _} = beamchain_miner:build_gbt_rules_and_vbavailable(regtest, 0),
    ?assertEqual([<<"csv">>, <<"!segwit">>, <<"taproot">>], Rules).
