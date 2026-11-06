%%% @doc spentby order of a verbose mempool entry (policy-cause-06).
%%%
%%% Core (rpc/mempool.cpp entryToJSON) lists spentby from
%%% CTxMemPool::GetChildren(e), which sorts with CompareIteratorByHash:
%%% Txid `<`, i.e. a memcmp of the INTERNAL (little-endian) 32 bytes, not of
%%% the displayed hex.  beamchain sorted the display hex, so the same set came
%%% out in a different order.  depends is different: Core builds it from a
%%% std::set<std::string> of display hex, so it stays in display-hex order.
-module(beamchain_policy_cause_06_spentby_order_tests).
-include_lib("eunit/include/eunit.hrl").

%% internal bytes <<A, 0...>> and <<B, 0...>> -> display hex ends in A / B
tx(Last, First) ->
    <<First, 0:(30*8), Last>>.

spentby_follows_internal_byte_order_not_display_hex_test() ->
    %% internal order: T1 (first byte 1) < T2 (first byte 2).
    %% display hex reverses the bytes, so T2 (last internal byte 0xff would
    %% not matter here) -- choose last bytes so display order is the opposite.
    T1 = tx(16#ff, 1),
    T2 = tx(16#00, 2),
    ?assertEqual([T1, T2], beamchain_rpc:sort_txids_core_order([T2, T1])),
    ?assertEqual([T1, T2], beamchain_rpc:sort_txids_core_order([T1, T2])),
    %% what the old display-hex sort produced
    ?assertEqual([T2, T1],
                 [T || {_, T} <- lists:sort(
                        [{beamchain_rpc:hash_to_hex(X), X} || X <- [T1, T2]])]).

%% depends is NOT in Txid order: Core builds it from a std::set<std::string>
%% of prevout.hash.ToString() (rpc/mempool.cpp entryToJSON).
depends_stays_in_display_hex_order_test() ->
    T1 = tx(16#ff, 1),
    T2 = tx(16#00, 2),
    ?assertEqual([T2, T1], beamchain_rpc:hex_sorted([T1, T2])).
