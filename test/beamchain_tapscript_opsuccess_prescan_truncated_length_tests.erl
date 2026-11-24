%%% BIP-342 OP_SUCCESSx prescan: a PUSHDATA1/2/4 whose length field is cut
%%% off by the end of the leaf ends the scan with BAD_OPCODE.
%%%
%%% Item r3fix-beamchain-tapscript-opsuccess-prescan-truncated-length
%%% (R3 generating differential fuzzer, night 1, seed 739943, row R24).
%%%
%%% Core v31.1, src/script/interpreter.cpp ExecuteWitnessScript (tapscript):
%%%
%%%     while (pc < exec_script.end()) {
%%%         opcodetype opcode;
%%%         if (!exec_script.GetOp(pc, opcode))
%%%             return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
%%%         if (IsOpSuccess(opcode)) { ... return set_success(serror); }
%%%     }
%%%
%%% src/script/script.cpp GetScriptOp returns false when fewer than 1 / 2 / 4
%%% length bytes follow OP_PUSHDATA1 / 2 / 4. So the length bytes are never
%%% classified as opcodes.
%%%
%%% beamchain's scan_for_op_success/1 matched PUSHDATAn only when the whole
%%% length field was present; otherwise the catch-all clause treated 0x4c /
%%% 0x4d / 0x4e as an ordinary opcode and went on scanning the leftover length
%%% bytes. Leaf `4d 50` (PUSHDATA2 with a single length byte 0x50 =
%%% OP_SUCCESS80) was therefore anyone-can-spend under block flags, where
%%% Core refuses it with BAD_OPCODE: beamchain would follow a chain Core
%%% rejects.
%%%
%%% Every case below is a full P2TR script-path spend through
%%% beamchain_script:verify_script_error/5 (the call the block script-check
%%% queue makes) with mainnet block flags at a post-taproot height, so it
%%% covers the block path, not just the prescan helper.
-module(beamchain_tapscript_opsuccess_prescan_truncated_length_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% BIP-341 NUMS point H: a valid x-only key, so the fixture never has to
%% skip because the internal key is off the curve.
-define(NUMS_H, <<16#50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0:256>>).

block_flags() ->
    beamchain_script:flags_for_height(900000, mainnet).

%% Verdict of a single-leaf P2TR script-path spend of Leaf with an empty
%% argument stack (witness = [Leaf, ControlBlock]).
spend(LeafHex, Flags) ->
    Leaf = binary:decode_hex(LeafHex),
    LeafLen = byte_size(Leaf),
    true = LeafLen < 16#fd,
    LeafHash = beamchain_crypto:tagged_hash(
                 <<"TapLeaf">>, <<16#c0, LeafLen, Leaf/binary>>),
    Tweak = beamchain_crypto:tagged_hash(
              <<"TapTweak">>, <<?NUMS_H/binary, LeafHash/binary>>),
    {ok, OutputKey, Parity} =
        beamchain_crypto:xonly_pubkey_tweak_add(?NUMS_H, Tweak),
    SPK = <<16#51, 16#20, OutputKey/binary>>,
    ControlBlock = <<(16#c0 bor Parity), ?NUMS_H/binary>>,
    beamchain_script:verify_script_error(
      <<>>, SPK, [Leaf, ControlBlock], Flags, #{}).

block(LeafHex) ->
    spend(LeafHex, block_flags()).

%%% --- Hostile leaves: Core BAD_OPCODE under block flags -------------------

%% PUSHDATA2 with one length byte; that byte is 0x50 (OP_SUCCESS80).
pushdata2_one_len_byte_op_success80_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"4d50">>)).

%% PUSHDATA4 with one length byte 0xbb (OP_SUCCESS187).
pushdata4_one_len_byte_op_success_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"4ebb">>)).

%% PUSHDATA4 with two length bytes, the second an OP_SUCCESS value.
pushdata4_two_len_bytes_op_success_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"4e00bb">>)).

%% PUSHDATA4 with three length bytes, the third 0xfe (OP_SUCCESS254).
pushdata4_three_len_bytes_op_success_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"4e0000fe">>)).

%% PUSHDATA2 with one length byte 0x7e (OP_CAT, an OP_SUCCESS in tapscript).
pushdata2_one_len_byte_op_cat_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"4d7e">>)).

%% Night-1 minimised case R24: `0 0 CHECKSIG PUSHDATA1` with no length
%% byte. Core fails the prescan with BAD_OPCODE before execution; master
%% beamchain ran the script and failed at CHECKSIG with
%% TAPSCRIPT_EMPTY_PUBKEY.
r24_trailing_pushdata1_no_len_byte_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"0000ac4c">>)).

%% Lone PUSHDATA2 / PUSHDATA4 with no length bytes at all.
lone_pushdata2_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"4d">>)).

lone_pushdata4_is_bad_opcode_test() ->
    ?assertEqual({error, bad_opcode}, block(<<"4e">>)).

%% verify_script/5 (the boolean the block check queue folds) refuses the
%% hostile leaf.
pushdata2_one_len_byte_verify_script_false_test() ->
    Leaf = binary:decode_hex(<<"4d50">>),
    LeafHash = beamchain_crypto:tagged_hash(
                 <<"TapLeaf">>, <<16#c0, 2, Leaf/binary>>),
    Tweak = beamchain_crypto:tagged_hash(
              <<"TapTweak">>, <<?NUMS_H/binary, LeafHash/binary>>),
    {ok, OutputKey, Parity} =
        beamchain_crypto:xonly_pubkey_tweak_add(?NUMS_H, Tweak),
    SPK = <<16#51, 16#20, OutputKey/binary>>,
    CB = <<(16#c0 bor Parity), ?NUMS_H/binary>>,
    ?assertEqual(false,
                 beamchain_script:verify_script(
                   <<>>, SPK, [Leaf, CB], block_flags(), #{})).

%% With DISCOURAGE_OP_SUCCESS set, Core still answers BAD_OPCODE: GetOp fails
%% before IsOpSuccess is ever asked, so no OP_SUCCESS is "seen".
pushdata2_one_len_byte_with_discourage_is_bad_opcode_test() ->
    Flags = block_flags() bor ?SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    ?assertEqual({error, bad_opcode}, spend(<<"4d50">>, Flags)).

%%% --- Controls: Core accepts under block flags -----------------------------

%% OP_SUCCESS80 alone.
control_op_success80_valid_test() ->
    ?assertEqual(ok, block(<<"50">>)).

%% Empty PUSHDATA2 (complete 2-byte length 0), then OP_SUCCESS80.
control_empty_pushdata2_then_op_success_valid_test() ->
    ?assertEqual(ok, block(<<"4d000050">>)).

%% Empty PUSHDATA1, then OP_SUCCESS187.
control_empty_pushdata1_then_op_success_valid_test() ->
    ?assertEqual(ok, block(<<"4c00bb">>)).

%% Empty PUSHDATA4 (complete 4-byte length 0), then OP_SUCCESS254.
control_empty_pushdata4_then_op_success_valid_test() ->
    ?assertEqual(ok, block(<<"4e00000000fe">>)).

%% OP_SUCCESS before a cut-off PUSHDATA2: Core scans in order and returns
%% success at 0x50 before it reaches the bad push.
control_op_success_before_truncated_pushdata_valid_test() ->
    ?assertEqual(ok, block(<<"504d">>)).

%% A complete PUSHDATA2 whose payload contains OP_SUCCESS bytes: the payload
%% is data, not opcodes. Script = PUSHDATA2 len=1 <0x50>, leaves a non-zero
%% element -> valid, and is not an OP_SUCCESS spend.
control_pushdata2_payload_op_success_byte_is_data_test() ->
    ?assertEqual(ok, block(<<"4d010050">>)),
    %% Proof it was executed rather than short-circuited by OP_SUCCESS: the
    %% same leaf followed by OP_VERIFY OP_0 leaves false -> eval_false.
    ?assertMatch({error, _}, block(<<"4d0100506900">>)).
