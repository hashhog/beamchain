-module(beamchain_getchaintxstats_tests).
-include_lib("eunit/include/eunit.hrl").

%% SERIALIZED-ORDER regression tests for the getchaintxstats RPC.
%%
%% Bug (fixed): the handler built the result as a plain Erlang map; jsx
%% serialises map keys in term order (alphabetical for these binary keys), so
%% the wire output was time, txcount, window_block_count,
%% window_final_block_hash, window_final_block_height, window_interval,
%% window_tx_count, txrate -- NOT Core's pushKV order. Fix builds an ORDERED
%% proplist (mirror of the getnodeaddresses fix, commit a67f827).
%%
%% Core order (bitcoin-core/src/rpc/blockchain.cpp getchaintxstats, the
%% ret.pushKV call sequence):
%%   time, [txcount], window_final_block_hash, window_final_block_height,
%%   window_block_count, [window_interval], [window_tx_count], [txrate]
%%
%% These tests assert the ACTUAL EMITTED BYTE ORDER in the jsx-encoded wire
%% bytes (binary:match start positions strictly increasing), NOT an
%% order-insensitive maps:keys/lists:sort set check. They drive the production
%% order-builder beamchain_rpc:chaintxstats_proplist/7 and encode it through the
%% exact same result_obj-shape + jsx:encode path production uses, so a
%% regression to a map (or any reordering) fails here.

%%% ===================================================================
%%% Helpers — reproduce the production wire-encoding path
%%% ===================================================================

%% Production path: dispatch/2 wraps {ok, Result} via result_obj(Id, Result)
%% (#{<<"result">> => Result, <<"error">> => null, <<"id">> => Id}) then
%% reply_json -> jsx:encode. We rebuild the same wrapper here so the encoded
%% bytes are byte-identical to what goes on the wire (the inner proplist order
%% is what we assert; the outer map keys are jsx-alphabetised, which is fine and
%% does not touch the result object's internal key order).
encode_wire(Result) ->
    Body = #{<<"result">> => Result, <<"error">> => null, <<"id">> => 1},
    jsx:encode(Body).

%% Position of a JSON object key (as it appears quoted with a trailing colon)
%% within the encoded wire bytes. Fails the test if the key is absent.
key_pos(Json, Key) ->
    Needle = <<"\"", Key/binary, "\":">>,
    case binary:match(Json, Needle) of
        {Start, _Len} -> Start;
        nomatch -> erlang:error({key_absent, Key, Json})
    end,
    {Start2, _} = binary:match(Json, Needle),
    Start2.

key_present(Json, Key) ->
    Needle = <<"\"", Key/binary, "\":">>,
    binary:match(Json, Needle) =/= nomatch.

%% Assert the given keys appear in the encoded JSON in exactly this order
%% (strictly increasing byte positions). All listed keys MUST be present.
assert_order(Json, Keys) ->
    Positions = [key_pos(Json, K) || K <- Keys],
    assert_strictly_increasing(Keys, Positions).

assert_strictly_increasing(_Keys, []) -> ok;
assert_strictly_increasing(_Keys, [_]) -> ok;
assert_strictly_increasing([K1, K2 | KT], [P1, P2 | PT]) ->
    ?assert(P1 < P2,
            lists:flatten(io_lib:format(
                "~s (pos ~p) must precede ~s (pos ~p) on the wire",
                [K1, P1, K2, P2]))),
    assert_strictly_increasing([K2 | KT], [P2 | PT]).

build(TS, TxCount, BlockHashHex, Height, NBlocks, TimeDiff, StartTxCount) ->
    beamchain_rpc:chaintxstats_proplist(TS, TxCount, BlockHashHex, Height,
                                        NBlocks, TimeDiff, StartTxCount).

%% The full Core key order (all conditional keys present).
all_keys() ->
    [<<"time">>, <<"txcount">>, <<"window_final_block_hash">>,
     <<"window_final_block_height">>, <<"window_block_count">>,
     <<"window_interval">>, <<"window_tx_count">>, <<"txrate">>].

hashhex() ->
    <<"00000000000000000000000000000000000000000000000000000000deadbeef">>.

%%% ===================================================================
%%% Case 1: NBlocks = 0 -> no window_interval / window_tx_count / txrate
%%% ===================================================================

nblocks_zero_test() ->
    %% NBlocks=0: only the 5 always-present-with-txcount keys; none of the
    %% window keys. txcount present (TxCount =/= undefined).
    Result = build(1700000000, 5000, hashhex(), 100, 0, 0, 4000),
    Json = encode_wire(Result),

    %% Present keys, in Core order.
    assert_order(Json, [<<"time">>, <<"txcount">>,
                        <<"window_final_block_hash">>,
                        <<"window_final_block_height">>,
                        <<"window_block_count">>]),

    %% Window keys MUST be absent when NBlocks = 0.
    ?assertNot(key_present(Json, <<"window_interval">>)),
    ?assertNot(key_present(Json, <<"window_tx_count">>)),
    ?assertNot(key_present(Json, <<"txrate">>)),

    %% And the proplist is exactly these 5 keys.
    ?assertEqual([<<"time">>, <<"txcount">>, <<"window_final_block_hash">>,
                  <<"window_final_block_height">>, <<"window_block_count">>],
                 [K || {K, _} <- Result]).

%%% ===================================================================
%%% Case 2: NBlocks > 0, both endpoints nonzero -> all 8 keys present,
%%%         window_interval BEFORE window_tx_count BEFORE txrate
%%% ===================================================================

all_keys_order_test() ->
    %% TxCount=8000, StartTxCount=5000 (both nonzero), TimeDiff=600 (>0):
    %% all conditional keys present.
    Result = build(1700000600, 8000, hashhex(), 200, 144, 600, 5000),
    Json = encode_wire(Result),

    %% Full Core order on the wire.
    assert_order(Json, all_keys()),

    %% Explicit guard on the relative order the bug got wrong: jsx-alphabetical
    %% would put window_interval AFTER window_final_*; and would put
    %% window_block_count before window_final_*. Assert the Core sequence.
    assert_order(Json, [<<"window_block_count">>, <<"window_interval">>,
                        <<"window_tx_count">>, <<"txrate">>]),

    %% All 8 present.
    lists:foreach(fun(K) -> ?assert(key_present(Json, K)) end, all_keys()),

    %% Proplist key sequence is exactly Core order.
    ?assertEqual(all_keys(), [K || {K, _} <- Result]),

    %% Sanity: window_tx_count value = End - Start, txrate = wtc / TimeDiff.
    ?assertEqual(3000, proplists:get_value(<<"window_tx_count">>, Result)),
    ?assertEqual(3000 / 600, proplists:get_value(<<"txrate">>, Result)).

%%% ===================================================================
%%% Case 3: NBlocks > 0, TimeDiff = 0 -> window_tx_count present, txrate absent
%%% ===================================================================

timediff_zero_test() ->
    %% Both endpoints nonzero but TimeDiff=0: window_interval(=0) and
    %% window_tx_count present, txrate ABSENT (Core: txrate only if nTimeDiff>0).
    Result = build(1700000000, 8000, hashhex(), 200, 144, 0, 5000),
    Json = encode_wire(Result),

    assert_order(Json, [<<"time">>, <<"txcount">>,
                        <<"window_final_block_hash">>,
                        <<"window_final_block_height">>,
                        <<"window_block_count">>,
                        <<"window_interval">>, <<"window_tx_count">>]),

    ?assert(key_present(Json, <<"window_interval">>)),
    ?assert(key_present(Json, <<"window_tx_count">>)),
    ?assertNot(key_present(Json, <<"txrate">>)),

    ?assertEqual([<<"time">>, <<"txcount">>, <<"window_final_block_hash">>,
                  <<"window_final_block_height">>, <<"window_block_count">>,
                  <<"window_interval">>, <<"window_tx_count">>],
                 [K || {K, _} <- Result]).

%%% ===================================================================
%%% Case 4: txcount absent (TxCount = undefined)
%%% ===================================================================

txcount_absent_test() ->
    %% TxCount undefined -> txcount omitted, and (per presence semantics)
    %% window_tx_count + txrate also omitted even though NBlocks>0 & TimeDiff>0.
    %% Remaining keys still in Core order.
    Result = build(1700000600, undefined, hashhex(), 200, 144, 600, 5000),
    Json = encode_wire(Result),

    %% txcount absent.
    ?assertNot(key_present(Json, <<"txcount">>)),
    %% window_tx_count / txrate absent (TxCount undefined endpoint).
    ?assertNot(key_present(Json, <<"window_tx_count">>)),
    ?assertNot(key_present(Json, <<"txrate">>)),

    %% Present keys, in Core order: time, window_final_block_hash,
    %% window_final_block_height, window_block_count, window_interval.
    assert_order(Json, [<<"time">>, <<"window_final_block_hash">>,
                        <<"window_final_block_height">>,
                        <<"window_block_count">>, <<"window_interval">>]),

    %% Specifically: time precedes window_final_block_hash with NO txcount in
    %% between (the slot is simply skipped, not reordered).
    ?assertEqual([<<"time">>, <<"window_final_block_hash">>,
                  <<"window_final_block_height">>, <<"window_block_count">>,
                  <<"window_interval">>],
                 [K || {K, _} <- Result]).

%%% ===================================================================
%%% Case 5: txcount present but endpoint zero -> window_tx_count/txrate absent,
%%%         and txcount STILL sits between time and window_final_block_hash.
%%% ===================================================================

zero_endpoint_test() ->
    %% TxCount=8000 (nonzero, so txcount emitted) but StartTxCount=0 ->
    %% window_tx_count + txrate omitted (Core: both m_chain_tx_count != 0).
    Result = build(1700000600, 8000, hashhex(), 200, 144, 600, 0),
    Json = encode_wire(Result),

    ?assert(key_present(Json, <<"txcount">>)),
    ?assert(key_present(Json, <<"window_interval">>)),
    ?assertNot(key_present(Json, <<"window_tx_count">>)),
    ?assertNot(key_present(Json, <<"txrate">>)),

    %% txcount in its Core slot (between time and window_final_block_hash).
    assert_order(Json, [<<"time">>, <<"txcount">>,
                        <<"window_final_block_hash">>,
                        <<"window_final_block_height">>,
                        <<"window_block_count">>, <<"window_interval">>]),

    ?assertEqual([<<"time">>, <<"txcount">>, <<"window_final_block_hash">>,
                  <<"window_final_block_height">>, <<"window_block_count">>,
                  <<"window_interval">>],
                 [K || {K, _} <- Result]).

%%% ===================================================================
%%% Case 6: NEGATIVE control — prove the test would catch a map regression.
%%% Encoding the SAME values as a plain map (the old buggy shape) must NOT be
%%% in Core order (jsx alphabetises), so assert_order would fail on it. We
%%% confirm the alphabetised order differs from Core order, guarding against a
%%% tautological assertion.
%%% ===================================================================

map_regression_is_caught_test() ->
    BuggyMap = #{
        <<"time">> => 1700000600,
        <<"txcount">> => 8000,
        <<"window_final_block_hash">> => hashhex(),
        <<"window_final_block_height">> => 200,
        <<"window_block_count">> => 144,
        <<"window_interval">> => 600,
        <<"window_tx_count">> => 3000,
        <<"txrate">> => 5.0
    },
    Json = encode_wire(BuggyMap),
    %% jsx alphabetises map keys: the alphabetical order is NOT Core order, so
    %% checking Core order against the buggy map must raise (this proves the
    %% assertion has teeth and is not satisfied by any ordering).
    ?assertError(_, assert_order(Json, all_keys())),
    %% Concretely, jsx puts txcount (alphabetical) before
    %% window_final_block_hash AND window_block_count before
    %% window_final_block_hash — but it also puts txrate (t...) before all the
    %% window_* keys, which Core puts LAST. Assert that mis-ordering exists.
    ?assert(key_pos(Json, <<"txrate">>) < key_pos(Json, <<"window_block_count">>)).
