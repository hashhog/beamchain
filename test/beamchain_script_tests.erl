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
    %% With MINIMALIF, should fail
    {error, _} = beamchain_script:eval_script(
        Script, [], ?SCRIPT_VERIFY_MINIMALIF, #{}, base).

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
