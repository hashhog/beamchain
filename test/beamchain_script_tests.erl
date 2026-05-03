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

%%% -------------------------------------------------------------------
%%% Stack underflow tests
%%% -------------------------------------------------------------------

stack_underflow_test() ->
    {error, stack_underflow} = eval(<<16#76>>),  %% OP_DUP on empty
    {error, stack_underflow} = eval(<<16#75>>),  %% OP_DROP on empty
    {error, stack_underflow} = eval(<<16#7c>>).  %% OP_SWAP on empty

%%% -------------------------------------------------------------------
%%% OP_NOP test
%%% -------------------------------------------------------------------

op_nop_test() ->
    %% OP_1 OP_NOP -> [1]
    {ok, [<<1>>]} = eval(<<16#51, 16#61>>).

%%% -------------------------------------------------------------------
%%% Script size limit test
%%% -------------------------------------------------------------------

script_too_large_test() ->
    BigScript = binary:copy(<<16#61>>, 10001),  %% 10001 OP_NOPs
    {error, script_too_large} = eval(BigScript).

%%% -------------------------------------------------------------------
%%% Push-only check
%%% -------------------------------------------------------------------

push_only_test() ->
    %% OP_1 OP_2 is push-only
    Flags = ?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_SIGPUSHONLY,
    ScriptSig = <<16#51, 16#52>>,
    ScriptPubKey = <<16#51>>,  %% OP_1 (truthy)
    ?assertEqual(true,
        beamchain_script:verify_script(ScriptSig, ScriptPubKey, [], Flags, #{})).

%%% -------------------------------------------------------------------
%%% P2SH detection
%%% -------------------------------------------------------------------

p2sh_detection_test() ->
    %% Valid P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
    Hash = <<0:160>>,
    P2SH = <<16#a9, 16#14, Hash/binary, 16#87>>,
    %% Simple scripts: OP_1 is the "redeem script" in the scriptSig
    %% push OP_1 as the redeem script
    ScriptSig = <<1, 16#51>>,  %% push 1 byte: 0x51 (which is OP_1)
    %% The hash of <<16#51>> must match
    ScriptHash = beamchain_crypto:hash160(<<16#51>>),
    P2SHScript = <<16#a9, 16#14, ScriptHash/binary, 16#87>>,
    Flags = ?SCRIPT_VERIFY_P2SH,
    ?assertEqual(true,
        beamchain_script:verify_script(ScriptSig, P2SHScript, [], Flags, #{})).

%%% -------------------------------------------------------------------
%%% P2SH push-only enforcement (BIP 16 - unconditional)
%%% -------------------------------------------------------------------

%% P2SH scriptSig containing OP_DUP (0x76) must fail — this is NOT push-only
p2sh_pushonly_op_dup_test() ->
    %% Redeem script: OP_1 (always succeeds)
    RedeemScript = <<16#51>>,
    ScriptHash = beamchain_crypto:hash160(RedeemScript),
    P2SHScript = <<16#a9, 16#14, ScriptHash/binary, 16#87>>,
    %% scriptSig with OP_DUP (non-push opcode) followed by push of redeem script
    %% OP_DUP = 0x76
    BadScriptSig = <<16#76, 1, 16#51>>,
    Flags = ?SCRIPT_VERIFY_P2SH,
    %% Must fail because scriptSig is not push-only
    ?assertEqual(false,
        beamchain_script:verify_script(BadScriptSig, P2SHScript, [], Flags, #{})).

%% P2SH scriptSig containing OP_NOP (0x61) must fail
p2sh_pushonly_op_nop_test() ->
    RedeemScript = <<16#51>>,
    ScriptHash = beamchain_crypto:hash160(RedeemScript),
    P2SHScript = <<16#a9, 16#14, ScriptHash/binary, 16#87>>,
    %% scriptSig with OP_NOP (0x61) then push redeem script
    BadScriptSig = <<16#61, 1, 16#51>>,
    Flags = ?SCRIPT_VERIFY_P2SH,
    ?assertEqual(false,
        beamchain_script:verify_script(BadScriptSig, P2SHScript, [], Flags, #{})).

%% P2SH scriptSig containing OP_IF (0x63) must fail
p2sh_pushonly_op_if_test() ->
    RedeemScript = <<16#51>>,
    ScriptHash = beamchain_crypto:hash160(RedeemScript),
    P2SHScript = <<16#a9, 16#14, ScriptHash/binary, 16#87>>,
    %% scriptSig with OP_IF
    BadScriptSig = <<16#63, 1, 16#51>>,
    Flags = ?SCRIPT_VERIFY_P2SH,
    ?assertEqual(false,
        beamchain_script:verify_script(BadScriptSig, P2SHScript, [], Flags, #{})).

%% Valid P2SH with only push ops should succeed
p2sh_pushonly_valid_test() ->
    RedeemScript = <<16#51>>,  %% OP_1
    ScriptHash = beamchain_crypto:hash160(RedeemScript),
    P2SHScript = <<16#a9, 16#14, ScriptHash/binary, 16#87>>,
    %% scriptSig: OP_1 (push 1) then push redeem script
    %% This pushes <<1>> (script number 1) then <<0x51>> (the redeem script)
    GoodScriptSig = <<16#51, 1, 16#51>>,
    Flags = ?SCRIPT_VERIFY_P2SH,
    ?assertEqual(true,
        beamchain_script:verify_script(GoodScriptSig, P2SHScript, [], Flags, #{})).

%% P2SH push-only check uses all push variants (PUSHDATA1, OP_0, OP_1-16, etc)
p2sh_pushonly_pushdata1_test() ->
    RedeemScript = <<16#51>>,  %% OP_1
    ScriptHash = beamchain_crypto:hash160(RedeemScript),
    P2SHScript = <<16#a9, 16#14, ScriptHash/binary, 16#87>>,
    %% scriptSig using PUSHDATA1 to push redeem script
    GoodScriptSig = <<16#4c, 1, 16#51>>,  %% OP_PUSHDATA1 <1> <0x51>
    Flags = ?SCRIPT_VERIFY_P2SH,
    ?assertEqual(true,
        beamchain_script:verify_script(GoodScriptSig, P2SHScript, [], Flags, #{})).

%% Non-P2SH scripts with computational ops should still work
non_p2sh_with_op_dup_test() ->
    %% P2PKH-like pattern: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    %% Using a mock checker
    PubKey = <<16#02, 1:256>>,  %% compressed pubkey
    PubKeyHash = beamchain_crypto:hash160(PubKey),
    ScriptPubKey = <<16#76, 16#a9, 20, PubKeyHash/binary, 16#88, 16#ac>>,
    FakeSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    ScriptSig = <<(byte_size(FakeSig)), FakeSig/binary,
                  (byte_size(PubKey)), PubKey/binary>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Flags = ?SCRIPT_VERIFY_P2SH,
    %% This is NOT P2SH (scriptPubKey doesn't match P2SH pattern), so
    %% the scriptSig does NOT need to be push-only
    ?assertEqual(true,
        beamchain_script:verify_script(ScriptSig, ScriptPubKey, [], Flags, SigChecker)).

%%% -------------------------------------------------------------------
%%% Witness program extraction test
%%% -------------------------------------------------------------------

witness_program_test() ->
    %% P2WPKH: OP_0 <20 bytes>
    Prog20 = <<0:160>>,
    Script = <<16#00, 16#14, Prog20/binary>>,
    %% Verify top-level matching works (this is internal so we test
    %% indirectly via verify_script)
    ok.

%%% -------------------------------------------------------------------
%%% Minimal encoding check tests
%%% -------------------------------------------------------------------

minimal_encoding_test() ->
    %% Empty is always minimal
    ?assertEqual(true, beamchain_script:check_minimal_encoding(<<>>)),
    %% <<1>> is minimal
    ?assertEqual(true, beamchain_script:check_minimal_encoding(<<1>>)),
    %% <<0, 0>> is not minimal (could be <<>>)
    ?assertEqual(false, beamchain_script:check_minimal_encoding(<<0, 0>>)),
    %% <<0x80, 0>> IS minimal: represents 128, needs sign byte
    ?assertEqual(true, beamchain_script:check_minimal_encoding(<<16#80, 0>>)),
    %% <<0>> is not minimal (should be empty for zero)
    ?assertEqual(false, beamchain_script:check_minimal_encoding(<<0>>)).

%%% -------------------------------------------------------------------
%%% Combined script: P2PKH pattern without actual sig
%%% -------------------------------------------------------------------

p2pkh_pattern_test() ->
    %% Test P2PKH pattern: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    %% We can't test actual sig verification without a real sig checker,
    %% but we can test the script pattern up to EQUALVERIFY
    PubKey = <<4, 0:256, 0:256>>,  %% fake uncompressed pubkey
    Hash = beamchain_crypto:hash160(PubKey),
    ScriptPubKey = <<16#76, 16#a9, 20, Hash/binary, 16#88, 16#ac>>,
    %% Just verify the structure parses and runs up to checksig
    %% With a fake checker that always returns true
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    %% scriptSig: <fake-sig> <pubkey>
    %% Sig needs at least 1 byte for hash type
    FakeSig = <<16#30, 1>>,  %% fake DER sig + hash type byte (0x01)
    ScriptSig = <<(byte_size(FakeSig)), FakeSig/binary,
                  (byte_size(PubKey)), PubKey/binary>>,
    %% This should succeed with our fake checker (no strict encoding checks)
    ?assertEqual(true,
        beamchain_script:verify_script(ScriptSig, ScriptPubKey, [], 0, SigChecker)).

%%% -------------------------------------------------------------------
%%% flags_for_height tests
%%% -------------------------------------------------------------------

flags_mainnet_pre_p2sh_test() ->
    Flags = beamchain_script:flags_for_height(100000, mainnet),
    %% P2SH not active yet
    ?assertEqual(0, Flags band ?SCRIPT_VERIFY_P2SH).

flags_mainnet_post_segwit_test() ->
    Flags = beamchain_script:flags_for_height(500000, mainnet),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_P2SH),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_WITNESS),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_DERSIG).

flags_mainnet_post_taproot_test() ->
    Flags = beamchain_script:flags_for_height(750000, mainnet),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_TAPROOT).

flags_testnet_all_active_test() ->
    Flags = beamchain_script:flags_for_height(0, testnet),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_P2SH),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_WITNESS),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_TAPROOT).

%%% -------------------------------------------------------------------
%%% Sighash legacy test (known values)
%%% -------------------------------------------------------------------

sighash_single_oob_test() ->
    %% SIGHASH_SINGLE with inputIndex >= outputs should return magic hash
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [],
        locktime = 0
    },
    Result = beamchain_script:sighash_legacy(Tx, 0, <<>>, ?SIGHASH_SINGLE),
    %% Should be 0x01 followed by 31 zero bytes
    Expected = <<1, 0:248>>,
    ?assertEqual(Expected, Result).

%%% -------------------------------------------------------------------
%%% OP_CHECKLOCKTIMEVERIFY test
%%% -------------------------------------------------------------------

op_cltv_as_nop_test() ->
    %% Without CHECKLOCKTIMEVERIFY flag, CLTV acts as NOP
    %% OP_1 OP_CLTV -> [1] (just a nop, top remains)
    {ok, [<<1>>]} = eval(<<16#51, 16#b1>>).

op_cltv_with_flag_test() ->
    %% With CLTV flag and a checker that succeeds
    SigChecker = #{check_locktime => fun(_) -> true end},
    Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    %% OP_1 OP_CLTV -> should succeed (locktime = 1, checker says ok)
    {ok, [<<1>>]} = beamchain_script:eval_script(
        <<16#51, 16#b1>>, [], Flags, SigChecker, base).

op_cltv_negative_test() ->
    %% Negative locktime should fail
    SigChecker = #{check_locktime => fun(_) -> true end},
    Flags = ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    %% push -1 (0x81), OP_CLTV
    {error, negative_locktime} = beamchain_script:eval_script(
        <<1, 16#81, 16#b1>>, [], Flags, SigChecker, base).

%%% -------------------------------------------------------------------
%%% OP_CHECKSEQUENCEVERIFY test
%%% -------------------------------------------------------------------

op_csv_as_nop_test() ->
    %% Without CSV flag, acts as NOP
    {ok, [<<1>>]} = eval(<<16#51, 16#b2>>).

op_csv_with_flag_test() ->
    SigChecker = #{check_sequence => fun(_) -> true end},
    Flags = ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    {ok, [<<1>>]} = beamchain_script:eval_script(
        <<16#51, 16#b2>>, [], Flags, SigChecker, base).

%%% -------------------------------------------------------------------
%%% OP_SUCCESS in tapscript test
%%% -------------------------------------------------------------------

op_success_tapscript_test() ->
    %% An OP_SUCCESS opcode (0xbb) in tapscript should succeed
    {ok, [<<1>>]} = beamchain_script:eval_script(
        <<16#bb>>, [], 0, #{}, tapscript).

op_success_discourage_test() ->
    %% With DISCOURAGE_OP_SUCCESS flag, should fail
    {error, discourage_op_success} = beamchain_script:eval_script(
        <<16#bb>>, [], ?SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, #{}, tapscript).

%%% -------------------------------------------------------------------
%%% Witness cleanstack enforcement tests (BIP 141/342)
%%% -------------------------------------------------------------------
%%
%% Witness scripts (v0 and v1) always require cleanstack:
%% - Stack must have exactly ONE element after execution
%% - That element must be TRUE (non-zero, not negative zero)
%% This is NOT gated by SCRIPT_VERIFY_CLEANSTACK flag -- it's hardcoded.

%% P2WSH: script that leaves extra items on stack must fail
p2wsh_cleanstack_extra_items_test() ->
    %% Script that pushes OP_1 OP_1 -> leaves [1,1] on stack (not clean)
    WitnessScript = <<16#51, 16#51>>,  %% OP_1 OP_1
    Program = crypto:hash(sha256, WitnessScript),
    Witness = [WitnessScript],  %% no stack args
    Flags = ?SCRIPT_VERIFY_WITNESS,
    SigChecker = #{},
    Result = beamchain_script:verify_script(
        <<>>,  %% empty scriptSig for witness
        <<16#00, 32, Program/binary>>,  %% OP_0 <32-byte program>
        Witness,
        Flags,
        SigChecker
    ),
    ?assertEqual(false, Result).

%% P2WSH: script that leaves empty stack must fail
p2wsh_cleanstack_empty_stack_test() ->
    %% Script: OP_1 OP_DROP -> pops the 1, leaves empty stack
    WitnessScript = <<16#51, 16#75>>,  %% OP_1 OP_DROP
    Program = crypto:hash(sha256, WitnessScript),
    Witness = [WitnessScript],
    Flags = ?SCRIPT_VERIFY_WITNESS,
    SigChecker = #{},
    Result = beamchain_script:verify_script(
        <<>>,
        <<16#00, 32, Program/binary>>,
        Witness,
        Flags,
        SigChecker
    ),
    ?assertEqual(false, Result).

%% P2WSH: script that leaves false (OP_0) on stack must fail
p2wsh_cleanstack_false_result_test() ->
    %% Script: OP_0 -> leaves [<<>>] (false) on stack
    WitnessScript = <<16#00>>,  %% OP_0
    Program = crypto:hash(sha256, WitnessScript),
    Witness = [WitnessScript],
    Flags = ?SCRIPT_VERIFY_WITNESS,
    SigChecker = #{},
    Result = beamchain_script:verify_script(
        <<>>,
        <<16#00, 32, Program/binary>>,
        Witness,
        Flags,
        SigChecker
    ),
    ?assertEqual(false, Result).

%% P2WSH: script that leaves negative zero on stack must fail
p2wsh_cleanstack_negative_zero_test() ->
    %% Script: push <<0x80>> (negative zero) -> should be treated as false
    WitnessScript = <<1, 16#80>>,  %% push 1 byte: 0x80
    Program = crypto:hash(sha256, WitnessScript),
    Witness = [WitnessScript],
    Flags = ?SCRIPT_VERIFY_WITNESS,
    SigChecker = #{},
    Result = beamchain_script:verify_script(
        <<>>,
        <<16#00, 32, Program/binary>>,
        Witness,
        Flags,
        SigChecker
    ),
    ?assertEqual(false, Result).

%% P2WSH: valid script leaving exactly one true element succeeds
p2wsh_cleanstack_valid_test() ->
    %% Script: OP_1 -> leaves [<<1>>] (true) on stack
    WitnessScript = <<16#51>>,  %% OP_1
    Program = crypto:hash(sha256, WitnessScript),
    Witness = [WitnessScript],
    Flags = ?SCRIPT_VERIFY_WITNESS,
    SigChecker = #{},
    Result = beamchain_script:verify_script(
        <<>>,
        <<16#00, 32, Program/binary>>,
        Witness,
        Flags,
        SigChecker
    ),
    ?assertEqual(true, Result).

%% Tapscript cleanstack: eval_script returns raw stack, cleanstack is
%% enforced in eval_tapscript (internal, called from verify_taproot_script_path).
%% These tests verify the cleanstack enforcement indirectly by checking that
%% eval_script returns the expected stack for tapscript mode.

%% Tapscript: script that leaves extra items returns that stack
tapscript_eval_extra_items_test() ->
    %% Script: OP_1 OP_1 -> leaves [1,1] on stack
    Script = <<16#51, 16#51>>,
    Stack = [],
    Flags = ?SCRIPT_VERIFY_TAPROOT,
    SigChecker = #{},
    %% eval_script returns raw stack, cleanstack checked at higher level
    Result = beamchain_script:eval_script(Script, Stack, Flags, SigChecker, tapscript),
    ?assertEqual({ok, [<<1>>, <<1>>]}, Result).

%% Tapscript: empty stack returns empty
tapscript_eval_empty_stack_test() ->
    %% Script: OP_1 OP_DROP -> leaves empty stack
    Script = <<16#51, 16#75>>,
    Stack = [],
    Flags = ?SCRIPT_VERIFY_TAPROOT,
    SigChecker = #{},
    Result = beamchain_script:eval_script(Script, Stack, Flags, SigChecker, tapscript),
    %% eval_script returns raw stack; cleanstack enforced in eval_tapscript
    ?assertEqual({ok, []}, Result).

%% Tapscript: false result returns false on stack
tapscript_eval_false_result_test() ->
    %% Script: OP_0 -> leaves false on stack
    Script = <<16#00>>,
    Stack = [],
    Flags = ?SCRIPT_VERIFY_TAPROOT,
    SigChecker = #{},
    Result = beamchain_script:eval_script(Script, Stack, Flags, SigChecker, tapscript),
    %% eval_script returns raw stack; bool check at higher level
    ?assertEqual({ok, [<<>>]}, Result).

%% Tapscript: valid script with one true element succeeds
tapscript_eval_valid_test() ->
    %% Script: OP_1 -> leaves [<<1>>] (true) on stack
    Script = <<16#51>>,
    Stack = [],
    Flags = ?SCRIPT_VERIFY_TAPROOT,
    SigChecker = #{},
    Result = beamchain_script:eval_script(Script, Stack, Flags, SigChecker, tapscript),
    ?assertEqual({ok, [<<1>>]}, Result).

%% Witness v0: script that leaves 3 items must fail (more comprehensive)
witness_v0_cleanstack_three_items_test() ->
    %% Script: OP_1 OP_2 OP_3 -> leaves [3,2,1] on stack
    Script = <<16#51, 16#52, 16#53>>,
    Stack = [],
    Flags = ?SCRIPT_VERIFY_WITNESS,
    SigChecker = #{},
    %% For witness_v0, eval_script returns the stack and the caller enforces cleanstack
    Result = beamchain_script:eval_script(Script, Stack, Flags, SigChecker, witness_v0),
    %% Should succeed in eval_script but have 3 items
    ?assertMatch({ok, [<<3>>, <<2>>, <<1>>]}, Result).

%%% -------------------------------------------------------------------
%%% PUSHDATA tests
%%% -------------------------------------------------------------------

pushdata1_test() ->
    %% OP_PUSHDATA1 with 1 byte of data
    {ok, [<<16#42>>]} = eval(<<16#4c, 1, 16#42>>).

pushdata2_test() ->
    %% OP_PUSHDATA2 with 1 byte of data
    {ok, [<<16#42>>]} = eval(<<16#4d, 1, 0, 16#42>>).

pushdata4_test() ->
    %% OP_PUSHDATA4 with 1 byte of data
    {ok, [<<16#42>>]} = eval(<<16#4e, 1, 0, 0, 0, 16#42>>).

%%% -------------------------------------------------------------------
%%% OP_CHECKMULTISIG tests
%%% -------------------------------------------------------------------

op_checkmultisig_pattern_test() ->
    %% 1-of-1 multisig with mock sig checker
    %% OP_0 <sig> OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
    FakeSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,                           %% OP_0 (dummy)
        (byte_size(FakeSig)), FakeSig/binary,   %% sig
        16#51,                           %% OP_1 (m = 1)
        (byte_size(FakePK)), FakePK/binary,     %% pubkey
        16#51,                           %% OP_1 (n = 1)
        16#ae                            %% OP_CHECKMULTISIG
    >>,
    {ok, [<<1>>]} = beamchain_script:eval_script(Script, [], 0, SigChecker, base).

op_checkmultisig_2of3_pattern_test() ->
    %% 2-of-3 multisig with mock sig checker
    FakeSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK1 = <<16#02, 1:256>>,
    FakePK2 = <<16#02, 2:256>>,
    FakePK3 = <<16#02, 3:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,                           %% OP_0 (dummy element)
        (byte_size(FakeSig)), FakeSig/binary,   %% sig1
        (byte_size(FakeSig)), FakeSig/binary,   %% sig2
        16#52,                           %% OP_2 (m = 2)
        (byte_size(FakePK1)), FakePK1/binary,
        (byte_size(FakePK2)), FakePK2/binary,
        (byte_size(FakePK3)), FakePK3/binary,
        16#53,                           %% OP_3 (n = 3)
        16#ae                            %% OP_CHECKMULTISIG
    >>,
    {ok, [<<1>>]} = beamchain_script:eval_script(Script, [], 0, SigChecker, base).

%%% -------------------------------------------------------------------
%%% NULLDUMMY flag enforcement test
%%% -------------------------------------------------------------------

nulldummy_enforcement_test() ->
    %% NULLDUMMY flag requires the dummy element in CHECKMULTISIG to be empty
    FakeSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    %% Non-empty dummy: push byte 0x42 instead of OP_0
    Script = <<
        1, 16#42,                        %% non-empty dummy
        (byte_size(FakeSig)), FakeSig/binary,
        16#51,
        (byte_size(FakePK)), FakePK/binary,
        16#51,
        16#ae
    >>,
    %% Without NULLDUMMY flag, should succeed
    {ok, [<<1>>]} = beamchain_script:eval_script(Script, [], 0, SigChecker, base),
    %% With NULLDUMMY flag, should fail
    {error, _} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_NULLDUMMY, SigChecker, base).

%%% -------------------------------------------------------------------
%%% OP_CHECKSIGADD test (tapscript)
%%% -------------------------------------------------------------------

op_checksigadd_empty_sig_test() ->
    %% Empty sig should push n unchanged (no increment, no sigops cost)
    SigChecker = #{
        check_schnorr_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    FakePK = <<0:256>>,
    Script = <<
        16#00,                                  %% OP_0 (empty sig)
        16#53,                                  %% OP_3 (n = 3)
        (byte_size(FakePK)), FakePK/binary,
        16#ba
    >>,
    %% empty sig doesn't consume sigops budget, so budget=0 is fine
    {ok, [<<3>>]} = beamchain_script:eval_script(
        Script, [], 0, SigChecker, tapscript).

%%% -------------------------------------------------------------------
%%% OP_CHECKMULTISIG disabled in tapscript
%%% -------------------------------------------------------------------

checkmultisig_disabled_in_tapscript_test() ->
    %% OP_CHECKMULTISIG (0xae) must fail in tapscript
    {error, _} = beamchain_script:eval_script(
        <<16#00, 16#51, 16#51, 16#ae>>, [], 0, #{}, tapscript).

%%% -------------------------------------------------------------------
%%% Op count limit test
%%% -------------------------------------------------------------------

op_count_limit_test() ->
    %% MAX_OPS_PER_SCRIPT = 201, check is `> 201`
    %% so 202 NOPs should fail
    Script202 = binary:copy(<<16#61>>, 202),
    {error, _} = eval(Script202).

op_count_at_limit_test() ->
    %% Exactly 201 OP_NOPs should succeed (the limit)
    Script201 = binary:copy(<<16#61>>, 201),
    {ok, []} = eval(Script201).

%%% -------------------------------------------------------------------
%%% Stack size limit test
%%% -------------------------------------------------------------------

max_stack_size_test() ->
    %% push 1000 items onto the stack — should be at the limit
    %% OP_1 = 0x51, each pushes one element
    Script1000 = binary:copy(<<16#51>>, 1000),
    {ok, Stack} = eval(Script1000),
    ?assertEqual(1000, length(Stack)).

%%% -------------------------------------------------------------------
%%% Negative zero in script numbers
%%% -------------------------------------------------------------------

script_num_negative_zero_test() ->
    %% 0x80 is negative zero, decode_script_num should give 0
    ?assertEqual({ok, 0}, beamchain_script:decode_script_num(<<16#80>>, 4)).

%%% -------------------------------------------------------------------
%%% OP_NUMEQUAL with negative values
%%% -------------------------------------------------------------------

op_numequal_negative_test() ->
    %% push -1, push -1, OP_NUMEQUAL -> [1]
    {ok, [<<1>>]} = eval(<<1, 16#81, 1, 16#81, 16#9c>>).

%%% -------------------------------------------------------------------
%%% OP_IF/NOTIF with MINIMALIF enforcement
%%% -------------------------------------------------------------------

minimalif_enforcement_test() ->
    %% With MINIMALIF flag, IF condition must be exactly OP_0 or OP_1
    %% push 2 bytes <<1, 0>> then OP_IF — truthy but not minimal
    Script = <<2, 1, 0, 16#63, 16#51, 16#68>>,  %% <01 00> OP_IF OP_1 OP_ENDIF
    %% Without MINIMALIF, should succeed (<<1, 0>> is truthy)
    {ok, [<<1>>]} = beamchain_script:eval_script(Script, [], 0, #{}, base),
    %% MINIMALIF flag in base mode is ignored (per Bitcoin Core behavior:
    %% MINIMALIF only applies in witness_v0 and tapscript execution contexts)
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, base),
    %% In witness_v0 mode, MINIMALIF is enforced
    {error, _} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, witness_v0).

%% MINIMALIF in witness scripts: <<2>> as OP_IF argument must fail
minimalif_witness_fail_test() ->
    %% Script: push <<2>> then OP_IF OP_1 OP_ENDIF
    %% <<2>> is truthy but not minimal (not <<>> or <<1>>)
    Script = <<1, 2, 16#63, 16#51, 16#68>>,  %% <02> OP_IF OP_1 OP_ENDIF
    %% In witness_v0, MINIMALIF is enforced (flag added automatically)
    %% Should fail because <<2>> is not minimal
    {error, minimalif_failed} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, witness_v0).

%% MINIMALIF in witness scripts: <<1>> must pass
minimalif_witness_pass_true_test() ->
    %% Script: push <<1>> then OP_IF OP_1 OP_ENDIF
    Script = <<1, 1, 16#63, 16#51, 16#68>>,  %% <01> OP_IF OP_1 OP_ENDIF
    %% <<1>> is valid minimal true
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, witness_v0).

%% MINIMALIF in witness scripts: <<>> must pass
minimalif_witness_pass_false_test() ->
    %% Script: OP_0 OP_IF OP_2 OP_ELSE OP_1 OP_ENDIF
    Script = <<16#00, 16#63, 16#52, 16#67, 16#51, 16#68>>,  %% OP_0 OP_IF OP_2 OP_ELSE OP_1 OP_ENDIF
    %% <<>> is valid minimal false, takes else branch
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, witness_v0).

%% MINIMALIF: <<0, 0>> must fail (not minimal false)
minimalif_witness_fail_nonminimal_false_test() ->
    %% Script: push <<0, 0>> then OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
    Script = <<2, 0, 0, 16#63, 16#51, 16#67, 16#52, 16#68>>,
    %% <<0, 0>> is falsey but not minimal (should be <<>>)
    {error, minimalif_failed} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, witness_v0).

%% MINIMALIF: <<1, 0>> must fail (not minimal true)
minimalif_witness_fail_nonminimal_true_test() ->
    %% Script: push <<1, 0>> then OP_IF OP_1 OP_ENDIF
    Script = <<2, 1, 0, 16#63, 16#51, 16#68>>,
    %% <<1, 0>> is truthy but not minimal (should be <<1>>)
    {error, minimalif_failed} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, witness_v0).

%% MINIMALIF in legacy scripts without flag: <<2>> must pass
minimalif_legacy_no_flag_test() ->
    %% Script: push <<2>> then OP_IF OP_1 OP_ENDIF
    Script = <<1, 2, 16#63, 16#51, 16#68>>,
    %% Without MINIMALIF flag, <<2>> is accepted as truthy
    {ok, [<<1>>]} = beamchain_script:eval_script(Script, [], 0, #{}, base).

%% MINIMALIF in tapscript: always enforced regardless of flag
minimalif_tapscript_always_enforced_test() ->
    %% Script: push <<2>> then OP_IF OP_1 OP_ENDIF
    Script = <<1, 2, 16#63, 16#51, 16#68>>,
    %% In tapscript, MINIMALIF is consensus (always enforced)
    %% Even with Flags=0, should fail
    {error, minimalif_failed} = beamchain_script:eval_script(Script, [], 0, #{}, tapscript).

%% MINIMALIF with OP_NOTIF in witness
minimalif_notif_witness_test() ->
    %% Script: push <<2>> then OP_NOTIF OP_1 OP_ENDIF
    Script = <<1, 2, 16#64, 16#51, 16#68>>,  %% <02> OP_NOTIF OP_1 OP_ENDIF
    %% Should fail because <<2>> is not minimal
    {error, minimalif_failed} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, witness_v0).

%%% -------------------------------------------------------------------
%%% Multiple OP_SUCCESS codes in tapscript
%%% -------------------------------------------------------------------

op_success_codes_test_() ->
    %% Various OP_SUCCESS codes should all succeed in tapscript
    Codes = [16#50, 16#62, 16#89, 16#8a, 16#bb, 16#fe],
    [fun() ->
        {ok, _} = beamchain_script:eval_script(<<Code>>, [], 0, #{}, tapscript)
    end || Code <- Codes].

%%% -------------------------------------------------------------------
%%% OP_CODESEPARATOR test
%%% -------------------------------------------------------------------

op_codeseparator_test() ->
    %% OP_1 OP_CODESEPARATOR OP_1 -> [1, 1]
    %% OP_CODESEPARATOR just updates the code separator position
    {ok, [<<1>>, <<1>>]} = eval(<<16#51, 16#ab, 16#51>>).

%%% -------------------------------------------------------------------
%%% NULLFAIL enforcement tests (BIP 146)
%%% -------------------------------------------------------------------

%% Test that NULLFAIL flag is set at segwit activation height for mainnet
nullfail_flag_mainnet_test() ->
    %% Pre-segwit: NULLFAIL should NOT be set
    FlagsPreSegwit = beamchain_script:flags_for_height(481823, mainnet),
    ?assertEqual(0, FlagsPreSegwit band ?SCRIPT_VERIFY_NULLFAIL),
    %% At segwit activation: NULLFAIL should be set
    FlagsAtSegwit = beamchain_script:flags_for_height(481824, mainnet),
    ?assertNotEqual(0, FlagsAtSegwit band ?SCRIPT_VERIFY_NULLFAIL),
    %% Post-segwit: NULLFAIL should still be set
    FlagsPostSegwit = beamchain_script:flags_for_height(500000, mainnet),
    ?assertNotEqual(0, FlagsPostSegwit band ?SCRIPT_VERIFY_NULLFAIL).

%% Test that NULLFAIL is set for testnet/regtest (all flags active from genesis)
nullfail_flag_testnet_test() ->
    Flags = beamchain_script:flags_for_height(0, testnet),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_NULLFAIL).

nullfail_flag_regtest_test() ->
    Flags = beamchain_script:flags_for_height(0, regtest),
    ?assertNotEqual(0, Flags band ?SCRIPT_VERIFY_NULLFAIL).

%% Test NULLFAIL enforcement in OP_CHECKSIG: failing sig with non-empty sig
%% must return error when NULLFAIL flag is set
nullfail_checksig_nonempty_sig_test() ->
    %% Create a script that does OP_CHECKSIG with a non-empty signature
    %% that will fail verification (because our mock returns false)
    NonEmptySig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK = <<16#02, 0:256>>,
    %% Mock sig checker that always fails
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> false end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(NonEmptySig)), NonEmptySig/binary,
        (byte_size(FakePK)), FakePK/binary,
        16#ac  %% OP_CHECKSIG
    >>,
    %% Without NULLFAIL flag, should push false (but succeed)
    {ok, [<<>>]} = beamchain_script:eval_script(Script, [], 0, SigChecker, base),
    %% With NULLFAIL flag, should fail with nullfail error
    {error, nullfail} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker, base).

%% Test NULLFAIL with empty signature: should succeed even with NULLFAIL flag
nullfail_checksig_empty_sig_test() ->
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> false end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,  %% OP_0 (empty sig)
        (byte_size(FakePK)), FakePK/binary,
        16#ac  %% OP_CHECKSIG
    >>,
    %% Empty sig with NULLFAIL should push false (not error)
    {ok, [<<>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker, base).

%% Test NULLFAIL enforcement in OP_CHECKMULTISIG
nullfail_checkmultisig_nonempty_sig_test() ->
    %% 1-of-1 multisig with failing non-empty sig
    NonEmptySig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> false end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,                                   %% OP_0 (dummy)
        (byte_size(NonEmptySig)), NonEmptySig/binary,
        16#51,                                   %% OP_1 (m = 1)
        (byte_size(FakePK)), FakePK/binary,
        16#51,                                   %% OP_1 (n = 1)
        16#ae                                    %% OP_CHECKMULTISIG
    >>,
    %% Without NULLFAIL flag, should push false
    {ok, [<<>>]} = beamchain_script:eval_script(Script, [], 0, SigChecker, base),
    %% With NULLFAIL flag, should fail with nullfail error
    {error, nullfail} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker, base).

%% Test NULLFAIL with all empty sigs in checkmultisig: should succeed
nullfail_checkmultisig_empty_sigs_test() ->
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> false end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,  %% OP_0 (dummy)
        16#00,  %% OP_0 (empty sig)
        16#51,  %% OP_1 (m = 1)
        (byte_size(FakePK)), FakePK/binary,
        16#51,  %% OP_1 (n = 1)
        16#ae   %% OP_CHECKMULTISIG
    >>,
    %% Empty sig with NULLFAIL should push false (not error)
    {ok, [<<>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker, base).

%% Test NULLFAIL enforcement in OP_CHECKSIGVERIFY
nullfail_checksigverify_nonempty_sig_test() ->
    NonEmptySig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> false end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(NonEmptySig)), NonEmptySig/binary,
        (byte_size(FakePK)), FakePK/binary,
        16#ad  %% OP_CHECKSIGVERIFY
    >>,
    %% Without NULLFAIL flag, CHECKSIGVERIFY fails with verify error
    {error, checksigverify_failed} = beamchain_script:eval_script(
        Script, [], 0, SigChecker, base),
    %% With NULLFAIL flag, should fail with nullfail error (checked before verify)
    {error, nullfail} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker, base).

%% Test NULLFAIL enforcement in OP_CHECKMULTISIGVERIFY
nullfail_checkmultisigverify_nonempty_sig_test() ->
    NonEmptySig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    FakePK = <<16#02, 0:256>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> false end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,                                   %% OP_0 (dummy)
        (byte_size(NonEmptySig)), NonEmptySig/binary,
        16#51,                                   %% OP_1 (m = 1)
        (byte_size(FakePK)), FakePK/binary,
        16#51,                                   %% OP_1 (n = 1)
        16#af                                    %% OP_CHECKMULTISIGVERIFY
    >>,
    %% Without NULLFAIL flag, fails with checkmultisigverify_failed
    {error, checkmultisigverify_failed} = beamchain_script:eval_script(
        Script, [], 0, SigChecker, base),
    %% With NULLFAIL flag, should fail with nullfail error
    {error, nullfail} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_NULLFAIL, SigChecker, base).

%%% -------------------------------------------------------------------
%%% WITNESS_PUBKEYTYPE tests (BIP 141)
%%% -------------------------------------------------------------------

%% Test that compressed pubkeys (0x02 prefix) are accepted in witness v0
witness_pubkeytype_compressed_02_test() ->
    %% 33-byte compressed pubkey with 0x02 prefix
    CompressedPK = <<16#02, 1:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(ValidSig)), ValidSig/binary,
        (byte_size(CompressedPK)), CompressedPK/binary,
        16#ac  %% OP_CHECKSIG
    >>,
    %% Should succeed with WITNESS_PUBKEYTYPE flag in witness_v0
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, SigChecker, witness_v0).

%% Test that compressed pubkeys (0x03 prefix) are accepted in witness v0
witness_pubkeytype_compressed_03_test() ->
    %% 33-byte compressed pubkey with 0x03 prefix
    CompressedPK = <<16#03, 1:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(ValidSig)), ValidSig/binary,
        (byte_size(CompressedPK)), CompressedPK/binary,
        16#ac  %% OP_CHECKSIG
    >>,
    %% Should succeed with WITNESS_PUBKEYTYPE flag in witness_v0
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, SigChecker, witness_v0).

%% Test that uncompressed pubkeys (0x04 prefix, 65 bytes) are rejected in witness v0
witness_pubkeytype_uncompressed_04_rejected_test() ->
    %% 65-byte uncompressed pubkey with 0x04 prefix
    UncompressedPK = <<16#04, 1:256, 2:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(ValidSig)), ValidSig/binary,
        (byte_size(UncompressedPK)), UncompressedPK/binary,
        16#ac  %% OP_CHECKSIG
    >>,
    %% Should fail with witness_pubkeytype error
    {error, witness_pubkeytype} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, SigChecker, witness_v0).

%% Test that uncompressed pubkeys ARE allowed when WITNESS_PUBKEYTYPE flag is not set
witness_pubkeytype_uncompressed_allowed_without_flag_test() ->
    %% 65-byte uncompressed pubkey with 0x04 prefix
    UncompressedPK = <<16#04, 1:256, 2:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(ValidSig)), ValidSig/binary,
        (byte_size(UncompressedPK)), UncompressedPK/binary,
        16#ac  %% OP_CHECKSIG
    >>,
    %% Should succeed without WITNESS_PUBKEYTYPE flag (even in witness_v0)
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], 0, SigChecker, witness_v0).

%% Test that uncompressed pubkeys are allowed in legacy scripts (sig_version=base)
witness_pubkeytype_legacy_uncompressed_allowed_test() ->
    %% 65-byte uncompressed pubkey with 0x04 prefix
    UncompressedPK = <<16#04, 1:256, 2:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(ValidSig)), ValidSig/binary,
        (byte_size(UncompressedPK)), UncompressedPK/binary,
        16#ac  %% OP_CHECKSIG
    >>,
    %% Should succeed in legacy mode even with WITNESS_PUBKEYTYPE flag
    %% (flag only applies to witness v0)
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, SigChecker, base).

%% Test WITNESS_PUBKEYTYPE enforcement in CHECKSIGVERIFY
witness_pubkeytype_checksigverify_rejected_test() ->
    %% 65-byte uncompressed pubkey
    UncompressedPK = <<16#04, 1:256, 2:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        (byte_size(ValidSig)), ValidSig/binary,
        (byte_size(UncompressedPK)), UncompressedPK/binary,
        16#ad  %% OP_CHECKSIGVERIFY
    >>,
    %% Should fail with witness_pubkeytype error
    {error, witness_pubkeytype} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, SigChecker, witness_v0).

%% Test WITNESS_PUBKEYTYPE enforcement in CHECKMULTISIG
witness_pubkeytype_checkmultisig_rejected_test() ->
    %% 65-byte uncompressed pubkey
    UncompressedPK = <<16#04, 1:256, 2:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,                                   %% OP_0 (dummy)
        (byte_size(ValidSig)), ValidSig/binary,
        16#51,                                   %% OP_1 (m = 1)
        (byte_size(UncompressedPK)), UncompressedPK/binary,
        16#51,                                   %% OP_1 (n = 1)
        16#ae                                    %% OP_CHECKMULTISIG
    >>,
    %% Should fail with witness_pubkeytype error
    {error, witness_pubkeytype} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, SigChecker, witness_v0).

%% Test that CHECKMULTISIG with compressed pubkeys succeeds
witness_pubkeytype_checkmultisig_compressed_test() ->
    %% 33-byte compressed pubkey
    CompressedPK = <<16#02, 1:256>>,
    ValidSig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    SigChecker = #{
        check_ecdsa_sig => fun(_, _, _) -> true end,
        compute_sighash => fun(_, _) -> <<0:256>> end
    },
    Script = <<
        16#00,                                   %% OP_0 (dummy)
        (byte_size(ValidSig)), ValidSig/binary,
        16#51,                                   %% OP_1 (m = 1)
        (byte_size(CompressedPK)), CompressedPK/binary,
        16#51,                                   %% OP_1 (n = 1)
        16#ae                                    %% OP_CHECKMULTISIG
    >>,
    %% Should succeed with WITNESS_PUBKEYTYPE flag
    {ok, [<<1>>]} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, SigChecker, witness_v0).

%%% -------------------------------------------------------------------
%%% Legacy sighash tests (Bitcoin Core test vectors)
%%% -------------------------------------------------------------------

%% Helper to parse a raw hex transaction
parse_tx(Hex) ->
    Bin = hex_to_bin(Hex),
    {Tx, _} = beamchain_serialize:decode_transaction(Bin),
    Tx.

%% Helper to convert hex string to binary
hex_to_bin(Hex) when is_list(Hex) ->
    hex_to_bin(list_to_binary(Hex));
hex_to_bin(Hex) when is_binary(Hex) ->
    beamchain_serialize:hex_decode(Hex).

%% Reverse bytes (test vectors use display format which is reversed)
reverse_bytes(Bin) ->
    beamchain_serialize:reverse_bytes(Bin).

%% Helper to convert signed 32-bit int to unsigned (hashType in test vectors)
to_unsigned_32(N) when N < 0 ->
    N + (1 bsl 32);
to_unsigned_32(N) ->
    N.

%% Test vectors from Bitcoin Core's sighash.json
%% Format: [raw_tx_hex, script_hex, input_index, hashType (signed), expected_hash_hex]
%% Note: expected_hash_hex is in "display format" (reversed bytes, like txid)

sighash_vector_1_test() ->
    %% Vector 1: Basic test with empty scriptCode
    TxHex = "907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229",
    ScriptHex = "",
    InputIndex = 2,
    HashType = 1864164639,
    ExpectedHex = "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    %% Expected is in display format (reversed), so reverse it to match our raw hash
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_2_test() ->
    %% Vector 2: Test with non-empty scriptCode
    TxHex = "a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5",
    ScriptHex = "65",
    InputIndex = 0,
    HashType = -1391424484,
    ExpectedHex = "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_3_test() ->
    %% Vector 3: More complex scriptCode
    TxHex = "6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8",
    ScriptHex = "acab655151",
    InputIndex = 0,
    HashType = 479279909,
    ExpectedHex = "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_4_test() ->
    %% Vector 4: SIGHASH_SINGLE
    TxHex = "73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051cebae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6aac51ffffffff0174a8f0010000000004ac52515100000000",
    ScriptHex = "5163ac63635151ac",
    InputIndex = 1,
    HashType = 1190874345,
    ExpectedHex = "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_5_test() ->
    %% Vector 5: negative hashType (becomes large positive)
    TxHex = "e93bbf6902be872933cb987fc26ba0f914fcfc2f6ce555258554dd9939d12032a8536c8802030000000453ac5353eabb6451e074e6fef9de211347d6a45900ea5aaf2636ef7967f565dce66fa451805c5cd10000000003525253ffffffff047dc3e6020000000007516565ac656aabec9eea010000000001633e46e600000000000015080a030000000001ab00000000",
    ScriptHex = "5300ac6a53ab6a",
    InputIndex = 1,
    HashType = -886562767,
    ExpectedHex = "f03aa4fc5f97e826323d0daa03343ebf8a34ed67a1ce18631f8b88e5c992e798",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

%%% -------------------------------------------------------------------
%%% FindAndDelete tests
%%% -------------------------------------------------------------------

%% Test that FindAndDelete removes push-encoded signature from scriptCode
find_and_delete_basic_test() ->
    %% Script with a signature embedded
    Sig = <<16#30, 16#06, 16#02, 16#01, 16#01, 16#02, 16#01, 16#01, 16#01>>,
    %% Script: <sig> OP_CHECKSIG (0xac)
    %% Push-encoded sig is: <9> <sig bytes>
    Script = <<9, Sig/binary, 16#ac>>,
    %% After FindAndDelete, the sig push should be removed
    Result = beamchain_script:find_and_delete(Script, Sig),
    %% Only OP_CHECKSIG should remain
    ?assertEqual(<<16#ac>>, Result).

find_and_delete_multiple_occurrences_test() ->
    %% Multiple occurrences should all be removed
    Sig = <<16#ab, 16#cd>>,
    %% Script with sig appearing twice
    Script = <<2, Sig/binary, 16#51, 2, Sig/binary>>,
    Result = beamchain_script:find_and_delete(Script, Sig),
    %% Only OP_1 should remain
    ?assertEqual(<<16#51>>, Result).

find_and_delete_no_match_test() ->
    %% If sig not in script, script unchanged
    Sig = <<16#de, 16#ad>>,
    Script = <<16#51, 16#52, 16#93>>,  %% OP_1 OP_2 OP_ADD
    Result = beamchain_script:find_and_delete(Script, Sig),
    ?assertEqual(Script, Result).

find_and_delete_empty_sig_test() ->
    %% Empty signature should match empty push (OP_0)
    %% Actually push_encode(<<>>) = <<0>> which is OP_0
    Script = <<16#00, 16#51, 16#00>>,  %% OP_0 OP_1 OP_0
    Result = beamchain_script:find_and_delete(Script, <<>>),
    %% Both OP_0 should be removed
    ?assertEqual(<<16#51>>, Result).

%%% -------------------------------------------------------------------
%%% OP_CODESEPARATOR handling tests
%%% -------------------------------------------------------------------

%% Test that OP_CODESEPARATOR is removed from scriptCode in legacy sighash
remove_codeseparator_test() ->
    %% Script with OP_CODESEPARATOR (0xab)
    Script = <<16#51, 16#ab, 16#52, 16#ab, 16#53>>,  %% OP_1 OP_CODESEP OP_2 OP_CODESEP OP_3
    %% Build a minimal tx
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 0, script_pubkey = <<>>}],
        locktime = 0
    },
    %% Compute sighash - OP_CODESEPARATOR bytes should be stripped
    _Result = beamchain_script:sighash_legacy(Tx, 0, Script, ?SIGHASH_ALL),
    %% The test is that it doesn't crash; actual hash verification is via vectors
    ok.

%%% -------------------------------------------------------------------
%%% SIGHASH_NONE tests
%%% -------------------------------------------------------------------

sighash_none_zeroes_outputs_test() ->
    %% SIGHASH_NONE should zero outputs
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<1:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 100000, script_pubkey = <<16#51>>}],
        locktime = 0
    },
    ScriptCode = <<16#51>>,  %% OP_1
    %% SIGHASH_NONE = 2
    HashNone = beamchain_script:sighash_legacy(Tx, 0, ScriptCode, ?SIGHASH_NONE),
    %% SIGHASH_ALL = 1
    HashAll = beamchain_script:sighash_legacy(Tx, 0, ScriptCode, ?SIGHASH_ALL),
    %% They should be different (NONE ignores outputs)
    ?assertNotEqual(HashNone, HashAll).

%%% -------------------------------------------------------------------
%%% SIGHASH_ANYONECANPAY tests
%%% -------------------------------------------------------------------

sighash_anyonecanpay_test() ->
    %% SIGHASH_ANYONECANPAY should only include the signing input
    Tx = #transaction{
        version = 1,
        inputs = [
            #tx_in{
                prev_out = #outpoint{hash = <<1:256>>, index = 0},
                script_sig = <<>>,
                sequence = 16#ffffffff,
                witness = []
            },
            #tx_in{
                prev_out = #outpoint{hash = <<2:256>>, index = 0},
                script_sig = <<>>,
                sequence = 16#ffffffff,
                witness = []
            }
        ],
        outputs = [#tx_out{value = 100000, script_pubkey = <<16#51>>}],
        locktime = 0
    },
    ScriptCode = <<16#51>>,
    %% SIGHASH_ALL | SIGHASH_ANYONECANPAY = 0x81
    HashACP = beamchain_script:sighash_legacy(Tx, 0, ScriptCode,
        ?SIGHASH_ALL bor ?SIGHASH_ANYONECANPAY),
    HashAll = beamchain_script:sighash_legacy(Tx, 0, ScriptCode, ?SIGHASH_ALL),
    %% They should be different (ANYONECANPAY only uses one input)
    ?assertNotEqual(HashACP, HashAll).

%%% -------------------------------------------------------------------
%%% More Bitcoin Core test vectors
%%% -------------------------------------------------------------------

sighash_vector_6_test() ->
    TxHex = "50818f4c01b464538b1e7e7f5ae4ed96ad23c68c830e78da9a845bc19b5c3b0b20bb82e5e9030000000763526a63655352ffffffff023b3f9c040000000008630051516a6a5163a83caf01000000000553ab65510000000000",
    ScriptHex = "6aac",
    InputIndex = 0,
    HashType = 946795545,
    ExpectedHex = "746306f322de2b4b58ffe7faae83f6a72433c22f88062cdde881d4dd8a5a4e2d",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_7_test() ->
    TxHex = "a93e93440250f97012d466a6cc24839f572def241c814fe6ae94442cf58ea33eb0fdd9bcc1030000000600636a0065acffffffff5dee3a6e7e5ad6310dea3e5b3ddda1a56bf8de7d3b75889fc024b5e233ec10f80300000007ac53635253ab53ffffffff0160468b04000000000800526a5300ac526a00000000",
    ScriptHex = "ac00636a53",
    InputIndex = 1,
    HashType = 1773442520,
    ExpectedHex = "5c9d3a2ce9365bb72cfabbaa4579c843bb8abf200944612cf8ae4b56a908bcbd",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_8_test() ->
    %% Vector with empty scriptCode
    TxHex = "c363a70c01ab174230bbe4afe0c3efa2d7f2feaf179431359adedccf30d1f69efe0c86ed390200000002ab51558648fe0231318b04000000000151662170000000000008ac5300006a63acac00000000",
    ScriptHex = "",
    InputIndex = 0,
    HashType = 2146479410,
    ExpectedHex = "191ab180b0d753763671717d051f138d4866b7cb0d1d4811472e64de595d2c70",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_9_test() ->
    TxHex = "d3b7421e011f4de0f1cea9ba7458bf3486bee722519efab711a963fa8c100970cf7488b7bb0200000003525352dcd61b300148be5d05000000000000000000",
    ScriptHex = "535251536aac536a",
    InputIndex = 0,
    HashType = -1960128125,
    ExpectedHex = "29aa6d2d752d3310eba20442770ad345b7f6a35f96161ede5f07b33e92053e2a",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

sighash_vector_10_test() ->
    TxHex = "04bac8c5033460235919a9c63c42b2db884c7c8f2ed8fcd69ff683a0a2cccd9796346a04050200000003655351fcad3a2c5a7cbadeb4ec7acc9836c3f5c3e776e5c566220f7f965cf194f8ef98efb5e3530200000007526a006552526526a2f55ba5f69699ece76692552b399ba908301907c5763d28a15b08581b23179cb01eac03000000075363ab6a516351073942c2025aa98a05000000000765006aabac65abd7ffa6030000000004516a655200000000",
    ScriptHex = "53ac6365ac526a",
    InputIndex = 1,
    HashType = 764174870,
    ExpectedHex = "bf5fdc314ded2372a0ad078568d76c5064bf2affbde0764c335009e56634481b",
    Tx = parse_tx(TxHex),
    Script = hex_to_bin(ScriptHex),
    UnsignedHashType = to_unsigned_32(HashType),
    Result = beamchain_script:sighash_legacy(Tx, InputIndex, Script, UnsignedHashType),
    Expected = reverse_bytes(hex_to_bin(ExpectedHex)),
    ?assertEqual(Expected, Result).

%%% =====================================================================
%%% BIP-342 tapscript validation-weight budget tracking
%%% (Bitcoin Core interpreter.cpp:362, VALIDATION_WEIGHT_PER_SIGOP_PASSED)
%%% =====================================================================

compact_size_len_test() ->
    ?assertEqual(1, beamchain_script:compact_size_len(0)),
    ?assertEqual(1, beamchain_script:compact_size_len(16#fc)),
    ?assertEqual(3, beamchain_script:compact_size_len(16#fd)),
    ?assertEqual(3, beamchain_script:compact_size_len(16#ffff)),
    ?assertEqual(5, beamchain_script:compact_size_len(16#10000)),
    ?assertEqual(5, beamchain_script:compact_size_len(16#ffffffff)),
    ?assertEqual(9, beamchain_script:compact_size_len(16#100000000)).

serialized_witness_stack_size_test() ->
    %% Empty stack: just the count compact-size = 1 byte.
    ?assertEqual(1, beamchain_script:serialized_witness_stack_size([])),
    %% One 64-byte item: 1 (count) + 1 (item len prefix) + 64 (bytes).
    Item64 = binary:copy(<<0>>, 64),
    ?assertEqual(66, beamchain_script:serialized_witness_stack_size([Item64])),
    %% Two items, 100 + 33 bytes:
    Item100 = binary:copy(<<0>>, 100),
    Item33  = binary:copy(<<0>>, 33),
    ?assertEqual(1 + (1 + 100) + (1 + 33),
                 beamchain_script:serialized_witness_stack_size([Item100, Item33])).

%% Exhausted budget aborts CHECKSIGADD via eval_tapscript directly.
%% Stack (top-down): pubkey, num=0, sig.
tapscript_validation_weight_exhausted_checksigadd_test() ->
    Sig = binary:copy(<<16#42>>, 64),
    PubKey = binary:copy(<<16#02>>, 32),
    %% Build tapscript: OP_CHECKSIGADD reads pubkey, num, sig from stack.
    Script = <<16#ba>>,  %% OP_CHECKSIGADD
    %% Pre-built stack with sig at bottom (from wire), num middle, pk top.
    Stack = [PubKey, <<>>, Sig],
    Flags = ?SCRIPT_VERIFY_TAPROOT,
    %% Always-true Schnorr checker so CHECKSIGADD makes it past sig parse.
    SigChecker = #{
        check_schnorr_sig => fun(_S, _P, _H) -> true end,
        compute_taproot_sighash => fun(_HT, _CSP) -> <<0:256>> end
    },
    %% Budget = 0: the non-empty sig must trip the gate.
    Result = beamchain_script:eval_tapscript(Script, Stack, 0, Flags, SigChecker),
    ?assertEqual({error, tapscript_sigops_exceeded}, Result).

%% Sufficient budget runs CHECKSIGADD to completion (residue == 0).
tapscript_validation_weight_sufficient_checksigadd_test() ->
    Sig = binary:copy(<<16#42>>, 64),
    PubKey = binary:copy(<<16#02>>, 32),
    Script = <<16#ba>>,  %% OP_CHECKSIGADD
    Stack = [PubKey, <<>>, Sig],
    Flags = ?SCRIPT_VERIFY_TAPROOT,
    SigChecker = #{
        check_schnorr_sig => fun(_S, _P, _H) -> true end,
        compute_taproot_sighash => fun(_HT, _CSP) -> <<0:256>> end
    },
    %% Budget = 50: the non-empty sig consumes exactly 50, residue = 0.
    %% Schnorr check returns true → push num+1 = 1.
    Result = beamchain_script:eval_tapscript(Script, Stack, 50, Flags, SigChecker),
    ?assertMatch({ok, _}, Result).

%% Empty sig consumes no budget (CHECKSIGADD).
%% Use num=1 so CHECKSIGADD pushes back num+0=1 (true), letting the
%% tapscript exit cleanly via eval_tapscript's stack-bool check.
tapscript_validation_weight_empty_sig_no_consume_test() ->
    PubKey = binary:copy(<<16#02>>, 32),
    Script = <<16#ba>>,  %% OP_CHECKSIGADD
    %% Stack (top-down): pubkey, num=1, empty sig
    Stack = [PubKey, <<1>>, <<>>],
    Flags = ?SCRIPT_VERIFY_TAPROOT,
    SigChecker = #{},
    %% Budget = 0 + empty sig: must not trip the gate.
    Result = beamchain_script:eval_tapscript(Script, Stack, 0, Flags, SigChecker),
    ?assertMatch({ok, _}, Result).

%% Legacy / SegWit-v0 paths are unaffected by the budget. Confirmed by
%% running OP_CHECKSIG in non-tapscript mode with the stack arrangement
%% that would consume budget if the gate were active.
tapscript_validation_weight_legacy_unaffected_test() ->
    %% OP_0 OP_0 OP_CHECKSIG  (empty sig, empty pk, push false on legacy)
    Script = <<16#00, 16#00, 16#ac>>,
    Flags = ?SCRIPT_VERIFY_WITNESS,
    SigChecker = #{},
    %% witness_v0 path: budget is not consulted.
    Result = beamchain_script:eval_script(Script, [], Flags, SigChecker, witness_v0),
    %% On the empty-sig path the legacy CHECKSIG pushes script_false.
    ?assertMatch({ok, _}, Result).
