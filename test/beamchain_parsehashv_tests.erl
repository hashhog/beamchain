-module(beamchain_parsehashv_tests).

%%% -------------------------------------------------------------------
%%% ParseHashV parse-boundary parity with Bitcoin Core v31.99.
%%%
%%% Core rpc/util.cpp ParseHashV (line 117): a txid/blockhash argument
%%% that is NOT a valid 64-char hex uint256 throws
%%% JSONRPCError(RPC_INVALID_PARAMETER) = code -8 at the PARSE boundary,
%%% BEFORE any lookup. Two message variants:
%%%   wrong length      -> "<name> must be of length 64 (not N, for '<hex>')"
%%%   right len, non-hex -> "<name> must be hexadecimal string (not '<hex>')"
%%% A WELL-FORMED 64-hex hash that is simply absent is NOT a parse error:
%%% the handler returns its own -5 (RPC_INVALID_ADDRESS_OR_KEY) or null
%%% (gettxout). This module asserts BOTH directions for every in-scope
%%% RPC: getrawtransaction, gettxout, getblock, getmempoolentry,
%%% getblockheader.
%%%
%%% The malformed direction is driven through the real handlers
%%% (beamchain_rpc:rpc_*/1) because ParseHashV throws BEFORE any db /
%%% mempool / chainstate lookup, so no live node processes are required.
%%% The well-formed-but-absent direction is asserted at the guard
%%% (parse_hash_v/2) level: a 64-zero hash decodes cleanly and does NOT
%%% throw -8, so the handler proceeds to its normal -5 / null path. (A
%%% full handler drive of the absent case would need a running
%%% beamchain_db gen_server, out of scope for a unit test.)
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

-define(RPC_INVALID_PARAMETER, -8).

%% Exactly 64 'z' chars: right length, NOT hex -> "hexadecimal string" variant.
%% Built programmatically so the length is provably 64 (no hand-counting).
-define(NONHEX64, binary:copy(<<"z">>, 64)).
%% "abc": too short (and odd length) -> "length 64" variant.
-define(SHORT, <<"abc">>).
%% Well-formed 64-zero hex: a valid uint256 that is simply absent.
-define(ZERO64, binary:copy(<<"0">>, 64)).

%%% ===================================================================
%%% Direction (a) — MALFORMED arg -> -8, driven through the real handler.
%%% ===================================================================

%% Each handler must return {error, -8, _} for BOTH a too-short hex and
%% a right-length non-hex string. The -8 fires at the ParseHashV boundary
%% before any lookup, so these run without a live db/mempool.

getrawtransaction_malformed_returns_minus8_test() ->
    assert_minus8(beamchain_rpc:rpc_getrawtransaction([?SHORT])),
    assert_minus8(beamchain_rpc:rpc_getrawtransaction([?NONHEX64])).

gettxout_malformed_returns_minus8_test() ->
    assert_minus8(beamchain_rpc:rpc_gettxout([?SHORT, 0])),
    assert_minus8(beamchain_rpc:rpc_gettxout([?NONHEX64, 0])).

getblock_malformed_returns_minus8_test() ->
    assert_minus8(beamchain_rpc:rpc_getblock([?SHORT])),
    assert_minus8(beamchain_rpc:rpc_getblock([?NONHEX64])).

getmempoolentry_malformed_returns_minus8_test() ->
    assert_minus8(beamchain_rpc:rpc_getmempoolentry([?SHORT])),
    assert_minus8(beamchain_rpc:rpc_getmempoolentry([?NONHEX64])).

getblockheader_malformed_returns_minus8_test() ->
    assert_minus8(beamchain_rpc:rpc_getblockheader([?SHORT])),
    assert_minus8(beamchain_rpc:rpc_getblockheader([?NONHEX64])).

%% getrawtransaction's OPTIONAL third blockhash argument must also parse
%% through ParseHashV (Core rawtransaction.cpp:300, "parameter 3").
%% A valid txid + malformed blockhash -> -8 (txid parse passes, blockhash
%% parse throws before the per-block lookup).
getrawtransaction_blockhash_arg_malformed_returns_minus8_test() ->
    assert_minus8(beamchain_rpc:rpc_getrawtransaction([?ZERO64, 0, ?NONHEX64])),
    assert_minus8(beamchain_rpc:rpc_getrawtransaction([?ZERO64, 0, ?SHORT])).

%%% ===================================================================
%%% Message-format parity — exact Core strprintf() rendering.
%%% ===================================================================

length_variant_message_matches_core_test() ->
    %% "abc" is length 3 -> "<name> must be of length 64 (not 3, for 'abc')".
    {error, ?RPC_INVALID_PARAMETER, Msg} = beamchain_rpc:rpc_getblock([?SHORT]),
    ?assertEqual(<<"blockhash must be of length 64 (not 3, for 'abc')">>, Msg).

hex_variant_message_matches_core_test() ->
    %% 64 'z' -> "<name> must be hexadecimal string (not '<hex>')".
    {error, ?RPC_INVALID_PARAMETER, Msg} =
        beamchain_rpc:rpc_gettxout([?NONHEX64, 0]),
    Expected = <<"txid must be hexadecimal string (not '",
                 (?NONHEX64)/binary, "')">>,
    ?assertEqual(Expected, Msg).

%% Core argument names per blockchain.cpp / rawtransaction.cpp / mempool.cpp:
%%   getblock -> "blockhash", getblockheader -> "hash",
%%   gettxout/getmempoolentry -> "txid", getrawtransaction -> "parameter 1".
core_argument_names_test() ->
    {error, _, B}  = beamchain_rpc:rpc_getblock([?SHORT]),
    {error, _, H}  = beamchain_rpc:rpc_getblockheader([?SHORT]),
    {error, _, T}  = beamchain_rpc:rpc_gettxout([?SHORT, 0]),
    {error, _, M}  = beamchain_rpc:rpc_getmempoolentry([?SHORT]),
    {error, _, R}  = beamchain_rpc:rpc_getrawtransaction([?SHORT]),
    ?assertMatch(<<"blockhash", _/binary>>, B),
    ?assertMatch(<<"hash ", _/binary>>, H),
    ?assertMatch(<<"txid", _/binary>>, T),
    ?assertMatch(<<"txid", _/binary>>, M),
    ?assertMatch(<<"parameter 1", _/binary>>, R).

%%% ===================================================================
%%% Direction (b) — WELL-FORMED but absent must NOT become -8.
%%%
%%% The 64-zero hash is a valid uint256: parse_hash_v/2 returns the
%%% decoded 32-byte hash and does NOT throw. The handler then resolves
%%% it to -5 / null on its own. We assert the guard does not steal the
%%% absent case into -8.
%%% ===================================================================

zero64_passes_guard_no_minus8_test() ->
    %% Must decode to a 32-byte internal hash, not throw.
    Bin = beamchain_rpc:parse_hash_v(?ZERO64, <<"txid">>),
    ?assertEqual(32, byte_size(Bin)),
    ?assertEqual(<<0:256>>, Bin).

%% Every Core argument name's guard accepts the well-formed 64-zero hash.
zero64_passes_guard_all_names_test() ->
    lists:foreach(
      fun(Name) ->
          ?assertEqual(32, byte_size(beamchain_rpc:parse_hash_v(?ZERO64, Name)))
      end,
      [<<"txid">>, <<"blockhash">>, <<"hash">>, <<"parameter 1">>,
       <<"parameter 3">>]).

%% And the guard itself rejects both malformed shapes with the right
%% code + variant (parse-boundary contract, independent of any handler).
guard_rejects_malformed_directly_test() ->
    LenExpected = <<"txid must be of length 64 (not 3, for 'abc')">>,
    HexExpected = <<"txid must be hexadecimal string (not '",
                    (?NONHEX64)/binary, "')">>,
    ?assertEqual({rpc_error, ?RPC_INVALID_PARAMETER, LenExpected},
                 catch_throw(fun() ->
                     beamchain_rpc:parse_hash_v(?SHORT, <<"txid">>) end)),
    ?assertEqual({rpc_error, ?RPC_INVALID_PARAMETER, HexExpected},
                 catch_throw(fun() ->
                     beamchain_rpc:parse_hash_v(?NONHEX64, <<"txid">>) end)).

catch_throw(Fun) ->
    try Fun() of
        V -> {no_throw, V}
    catch
        throw:T -> T
    end.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

assert_minus8({error, Code, Msg}) ->
    ?assertEqual(?RPC_INVALID_PARAMETER, Code),
    ?assert(is_binary(Msg)),
    ?assert(byte_size(Msg) > 0);
assert_minus8(Other) ->
    ?assertEqual({error, ?RPC_INVALID_PARAMETER, '_'}, Other).
