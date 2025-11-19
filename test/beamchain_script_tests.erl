-module(beamchain_script_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% -------------------------------------------------------------------
%%% Script number encoding/decoding tests
%%% -------------------------------------------------------------------

script_num_zero_test() ->
    ?assertEqual(<<>>, beamchain_script:encode_script_num(0)),
    ?assertEqual({ok, 0}, beamchain_script:decode_script_num(<<>>, 4)).

script_num_positive_test() ->
    ?assertEqual(<<1>>, beamchain_script:encode_script_num(1)),
    ?assertEqual(<<127>>, beamchain_script:encode_script_num(127)),
    %% 128 needs a sign byte: 0x80, 0x00
    ?assertEqual(<<128, 0>>, beamchain_script:encode_script_num(128)),
    ?assertEqual(<<255, 0>>, beamchain_script:encode_script_num(255)),
    ?assertEqual(<<0, 1>>, beamchain_script:encode_script_num(256)).

script_num_negative_test() ->
    %% -1 = 0x81 (1 with sign bit set)
    ?assertEqual(<<16#81>>, beamchain_script:encode_script_num(-1)),
    %% -127 = 0xff
    ?assertEqual(<<16#ff>>, beamchain_script:encode_script_num(-127)),
    %% -128 = 0x80, 0x80
    ?assertEqual(<<16#80, 16#80>>, beamchain_script:encode_script_num(-128)).

script_num_roundtrip_test_() ->
    Values = [0, 1, -1, 127, -127, 128, -128, 255, -255,
              256, -256, 32767, -32767, 32768, -32768,
              8388607, -8388607, 2147483647, -2147483647],
    [?_assertEqual({ok, V},
        beamchain_script:decode_script_num(
            beamchain_script:encode_script_num(V), 4))
     || V <- Values].

script_num_overflow_test() ->
    %% 5-byte number should fail with max 4
    ?assertEqual({error, script_num_overflow},
        beamchain_script:decode_script_num(<<1, 2, 3, 4, 5>>, 4)).

%%% -------------------------------------------------------------------
%%% Script boolean tests
%%% -------------------------------------------------------------------

script_bool_test() ->
    ?assertEqual(false, beamchain_script:script_bool(<<>>)),
    ?assertEqual(false, beamchain_script:script_bool(<<0>>)),
    ?assertEqual(false, beamchain_script:script_bool(<<0, 0>>)),
    %% negative zero
    ?assertEqual(false, beamchain_script:script_bool(<<16#80>>)),
    ?assertEqual(true, beamchain_script:script_bool(<<1>>)),
    ?assertEqual(true, beamchain_script:script_bool(<<16#81>>)),
    ?assertEqual(true, beamchain_script:script_bool(<<0, 1>>)).

%%% -------------------------------------------------------------------
%%% Basic eval_script tests (no sig checking needed)
%%% -------------------------------------------------------------------

%% Helper: evaluate script with no flags and no sig checker
eval(Script) ->
    eval(Script, []).
eval(Script, Stack) ->
    beamchain_script:eval_script(Script, Stack, 0, #{}, base).

%% OP_0 pushes empty
op_0_test() ->
    {ok, [<<>>]} = eval(<<0>>).

%% OP_1 through OP_16
op_n_test_() ->
    [?_assertEqual({ok, [beamchain_script:encode_script_num(N)]},
                   eval(<<(16#50 + N)>>))
     || N <- lists:seq(1, 16)].

%% OP_1NEGATE
op_1negate_test() ->
    {ok, [<<16#81>>]} = eval(<<16#4f>>).

%% Data push: push 3 bytes
data_push_test() ->
    {ok, [<<16#aa, 16#bb, 16#cc>>]} = eval(<<3, 16#aa, 16#bb, 16#cc>>).

%% OP_DUP
op_dup_test() ->
    %% OP_1 OP_DUP -> [1, 1]
    {ok, [<<1>>, <<1>>]} = eval(<<16#51, 16#76>>).

%% OP_DROP
op_drop_test() ->
    %% OP_1 OP_2 OP_DROP -> [1]
    {ok, [<<1>>]} = eval(<<16#51, 16#52, 16#75>>).

%% OP_SWAP
op_swap_test() ->
    %% OP_1 OP_2 OP_SWAP -> [2, 1]
    {ok, [<<1>>, <<2>>]} = eval(<<16#51, 16#52, 16#7c>>).

%% OP_ROT
op_rot_test() ->
    %% OP_1 OP_2 OP_3 OP_ROT -> [1, 3, 2]
    {ok, [<<1>>, <<3>>, <<2>>]} = eval(<<16#51, 16#52, 16#53, 16#7b>>).

%% OP_OVER
op_over_test() ->
    %% OP_1 OP_2 OP_OVER -> [1, 2, 1]
    {ok, [<<1>>, <<2>>, <<1>>]} = eval(<<16#51, 16#52, 16#78>>).

%% OP_NIP
op_nip_test() ->
    %% OP_1 OP_2 OP_NIP -> [2]
    {ok, [<<2>>]} = eval(<<16#51, 16#52, 16#77>>).

%% OP_TUCK
op_tuck_test() ->
    %% OP_1 OP_2 OP_TUCK -> [2, 1, 2]
    {ok, [<<2>>, <<1>>, <<2>>]} = eval(<<16#51, 16#52, 16#7d>>).

%% OP_2DUP
op_2dup_test() ->
    %% OP_1 OP_2 OP_2DUP -> stack [2,1] -> [2,1,2,1] (top first)
    {ok, [<<2>>, <<1>>, <<2>>, <<1>>]} = eval(<<16#51, 16#52, 16#6e>>).

%% OP_3DUP
op_3dup_test() ->
    %% stack [3,2,1] -> [3,2,1,3,2,1]
    {ok, [<<3>>, <<2>>, <<1>>, <<3>>, <<2>>, <<1>>]} =
        eval(<<16#51, 16#52, 16#53, 16#6f>>).

%% OP_2DROP
op_2drop_test() ->
    %% OP_1 OP_2 OP_3 OP_2DROP -> [1]
    {ok, [<<1>>]} = eval(<<16#51, 16#52, 16#53, 16#6d>>).

%% OP_2SWAP
op_2swap_test() ->
    %% stack [4,3,2,1] -> [2,1,4,3] (swap top pair with next pair)
    {ok, [<<2>>, <<1>>, <<4>>, <<3>>]} =
        eval(<<16#51, 16#52, 16#53, 16#54, 16#72>>).

%% OP_2OVER
op_2over_test() ->
    %% stack [4,3,2,1] -> [2,1,4,3,2,1] (copy 3rd and 4th to top)
    {ok, [<<2>>, <<1>>, <<4>>, <<3>>, <<2>>, <<1>>]} =
        eval(<<16#51, 16#52, 16#53, 16#54, 16#70>>).

%% OP_DEPTH
op_depth_test() ->
    %% OP_1 OP_2 OP_DEPTH -> [2, 1, 2] (depth = 2, on top)
    {ok, [<<2>>, <<2>>, <<1>>]} = eval(<<16#51, 16#52, 16#74>>).

%% OP_SIZE
op_size_test() ->
    %% push 3 bytes, OP_SIZE -> [3, <data>]
    {ok, [<<3>>, <<16#aa, 16#bb, 16#cc>>]} = eval(<<3, 16#aa, 16#bb, 16#cc, 16#82>>).

%% OP_IFDUP - duplicate if non-zero
op_ifdup_nonzero_test() ->
    %% OP_1 OP_IFDUP -> [1, 1]
    {ok, [<<1>>, <<1>>]} = eval(<<16#51, 16#73>>).

op_ifdup_zero_test() ->
    %% OP_0 OP_IFDUP -> [<<>>] (empty = false, no dup)
    {ok, [<<>>]} = eval(<<16#00, 16#73>>).

%% OP_PICK
op_pick_test() ->
    %% OP_1 OP_2 OP_3 OP_0 OP_PICK -> picks top (3)
    {ok, [<<3>>, <<3>>, <<2>>, <<1>>]} =
        eval(<<16#51, 16#52, 16#53, 16#00, 16#79>>).

%% OP_ROLL
op_roll_test() ->
    %% OP_1 OP_2 OP_3 OP_2 OP_ROLL -> moves item at index 2 (which is 1) to top
    {ok, [<<1>>, <<3>>, <<2>>]} =
        eval(<<16#51, 16#52, 16#53, 16#52, 16#7a>>).

%% OP_TOALTSTACK / OP_FROMALTSTACK
op_altstack_test() ->
    %% OP_1 OP_TOALTSTACK OP_2 OP_FROMALTSTACK -> [1, 2]
    {ok, [<<1>>, <<2>>]} = eval(<<16#51, 16#6b, 16#52, 16#6c>>).

%%% -------------------------------------------------------------------
%%% Equality tests
%%% -------------------------------------------------------------------

op_equal_true_test() ->
    %% OP_1 OP_1 OP_EQUAL -> [1]
    {ok, [<<1>>]} = eval(<<16#51, 16#51, 16#87>>).

op_equal_false_test() ->
    %% OP_1 OP_2 OP_EQUAL -> [<<>>]
    {ok, [<<>>]} = eval(<<16#51, 16#52, 16#87>>).

op_equalverify_test() ->
    %% OP_1 OP_1 OP_EQUALVERIFY -> []
    {ok, []} = eval(<<16#51, 16#51, 16#88>>).

op_equalverify_fail_test() ->
    %% OP_1 OP_2 OP_EQUALVERIFY -> error
    {error, equalverify_failed} = eval(<<16#51, 16#52, 16#88>>).

%%% -------------------------------------------------------------------
%%% Arithmetic tests
%%% -------------------------------------------------------------------

op_add_test() ->
    %% OP_3 OP_4 OP_ADD -> [7]
    {ok, [<<7>>]} = eval(<<16#53, 16#54, 16#93>>).

op_sub_test() ->
    %% OP_5 OP_3 OP_SUB -> [2]
    {ok, [<<2>>]} = eval(<<16#55, 16#53, 16#94>>).

op_1add_test() ->
    {ok, [<<6>>]} = eval(<<16#55, 16#8b>>).

op_1sub_test() ->
    {ok, [<<4>>]} = eval(<<16#55, 16#8c>>).

op_negate_test() ->
    %% OP_5 OP_NEGATE -> [-5]
    {ok, [<<16#85>>]} = eval(<<16#55, 16#8f>>).

op_abs_test() ->
    %% push -5 (0x85), OP_ABS -> [5]
    {ok, [<<5>>]} = eval(<<1, 16#85, 16#90>>).

op_not_test() ->
    %% OP_0 OP_NOT -> [1]
    {ok, [<<1>>]} = eval(<<16#00, 16#91>>),
    %% OP_1 OP_NOT -> [<<>>] (0)
    {ok, [<<>>]} = eval(<<16#51, 16#91>>).

op_0notequal_test() ->
    %% OP_0 OP_0NOTEQUAL -> [0]
    {ok, [<<>>]} = eval(<<16#00, 16#92>>),
    %% OP_5 OP_0NOTEQUAL -> [1]
    {ok, [<<1>>]} = eval(<<16#55, 16#92>>).

op_booland_test() ->
    %% OP_1 OP_1 OP_BOOLAND -> [1]
    {ok, [<<1>>]} = eval(<<16#51, 16#51, 16#9a>>),
    %% OP_1 OP_0 OP_BOOLAND -> [0]
    {ok, [<<>>]} = eval(<<16#51, 16#00, 16#9a>>).

op_boolor_test() ->
    %% OP_1 OP_0 OP_BOOLOR -> [1]
    {ok, [<<1>>]} = eval(<<16#51, 16#00, 16#9b>>),
    %% OP_0 OP_0 OP_BOOLOR -> [0]
    {ok, [<<>>]} = eval(<<16#00, 16#00, 16#9b>>).

op_numequal_test() ->
    {ok, [<<1>>]} = eval(<<16#53, 16#53, 16#9c>>),
    {ok, [<<>>]} = eval(<<16#53, 16#54, 16#9c>>).

op_numnotequal_test() ->
    {ok, [<<>>]} = eval(<<16#53, 16#53, 16#9e>>),
    {ok, [<<1>>]} = eval(<<16#53, 16#54, 16#9e>>).

op_lessthan_test() ->
    %% OP_3 OP_5 OP_LESSTHAN -> [1] (3 < 5)
    {ok, [<<1>>]} = eval(<<16#53, 16#55, 16#9f>>),
    %% OP_5 OP_3 OP_LESSTHAN -> [0] (5 < 3 is false)
    {ok, [<<>>]} = eval(<<16#55, 16#53, 16#9f>>).

op_greaterthan_test() ->
    %% OP_5 OP_3 OP_GREATERTHAN -> [1] (5 > 3)
    {ok, [<<1>>]} = eval(<<16#55, 16#53, 16#a0>>).

op_lessthanorequal_test() ->
    {ok, [<<1>>]} = eval(<<16#53, 16#53, 16#a1>>).

op_greaterthanorequal_test() ->
    {ok, [<<1>>]} = eval(<<16#53, 16#53, 16#a2>>).

op_min_test() ->
    {ok, [<<3>>]} = eval(<<16#53, 16#55, 16#a3>>).

op_max_test() ->
    {ok, [<<5>>]} = eval(<<16#53, 16#55, 16#a4>>).

op_within_test() ->
    %% OP_3 OP_2 OP_5 OP_WITHIN -> [1] (2 <= 3 < 5)
    {ok, [<<1>>]} = eval(<<16#53, 16#52, 16#55, 16#a5>>),
    %% OP_1 OP_2 OP_5 OP_WITHIN -> [0] (2 <= 1 is false)
    {ok, [<<>>]} = eval(<<16#51, 16#52, 16#55, 16#a5>>).

%%% -------------------------------------------------------------------
%%% Flow control tests
%%% -------------------------------------------------------------------

op_if_true_test() ->
    %% OP_1 OP_IF OP_2 OP_ENDIF -> [2]
    {ok, [<<2>>]} = eval(<<16#51, 16#63, 16#52, 16#68>>).

op_if_false_test() ->
    %% OP_0 OP_IF OP_2 OP_ENDIF -> []
    {ok, []} = eval(<<16#00, 16#63, 16#52, 16#68>>).

op_if_else_test() ->
    %% OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> [2]
    {ok, [<<2>>]} = eval(<<16#51, 16#63, 16#52, 16#67, 16#53, 16#68>>),
    %% OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> [3]
    {ok, [<<3>>]} = eval(<<16#00, 16#63, 16#52, 16#67, 16#53, 16#68>>).

op_notif_test() ->
    %% OP_0 OP_NOTIF OP_2 OP_ENDIF -> [2]
    {ok, [<<2>>]} = eval(<<16#00, 16#64, 16#52, 16#68>>),
    %% OP_1 OP_NOTIF OP_2 OP_ENDIF -> []
    {ok, []} = eval(<<16#51, 16#64, 16#52, 16#68>>).

op_nested_if_test() ->
    %% OP_1 OP_IF OP_1 OP_IF OP_3 OP_ENDIF OP_ENDIF -> [3]
    {ok, [<<3>>]} = eval(<<16#51, 16#63, 16#51, 16#63, 16#53, 16#68, 16#68>>).

op_verify_test() ->
    %% OP_1 OP_VERIFY -> []
    {ok, []} = eval(<<16#51, 16#69>>),
    %% OP_0 OP_VERIFY -> error
    {error, verify_failed} = eval(<<16#00, 16#69>>).

op_return_test() ->
    %% OP_RETURN -> error (script fails)
    {error, op_return} = eval(<<16#6a>>).

unbalanced_if_test() ->
    %% OP_1 OP_IF OP_2 (no ENDIF) -> error
    {error, unbalanced_conditional} = eval(<<16#51, 16#63, 16#52>>).

%%% -------------------------------------------------------------------
%%% Hash opcode tests
%%% -------------------------------------------------------------------

op_sha256_test() ->
    %% push empty, OP_SHA256
    {ok, [Expected]} = eval(<<0, 16#a8>>),
    ?assertEqual(crypto:hash(sha256, <<>>), Expected).

op_hash160_test() ->
    %% push empty, OP_HASH160
    {ok, [Expected]} = eval(<<0, 16#a9>>),
    ?assertEqual(beamchain_crypto:hash160(<<>>), Expected).

op_hash256_test() ->
    %% push empty, OP_HASH256
    {ok, [Expected]} = eval(<<0, 16#aa>>),
    ?assertEqual(beamchain_crypto:hash256(<<>>), Expected).

op_ripemd160_test() ->
    {ok, [Expected]} = eval(<<0, 16#a6>>),
    ?assertEqual(crypto:hash(ripemd160, <<>>), Expected).

op_sha1_test() ->
    {ok, [Expected]} = eval(<<0, 16#a7>>),
    ?assertEqual(crypto:hash(sha, <<>>), Expected).

%%% -------------------------------------------------------------------
%%% Disabled opcode tests
%%% -------------------------------------------------------------------

disabled_opcode_test_() ->
    DisabledOps = [16#7e, 16#7f, 16#80, 16#81, 16#83, 16#84, 16#85, 16#86,
                   16#8d, 16#8e, 16#95, 16#96, 16#97, 16#98, 16#99],
    [?_assertEqual({error, disabled_opcode}, eval(<<Op>>))
     || Op <- DisabledOps].

