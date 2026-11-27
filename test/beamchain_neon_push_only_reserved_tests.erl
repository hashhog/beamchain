-module(beamchain_neon_push_only_reserved_tests).

%% Finding 7 of the Gemini (Neon) audit of beamchain against Bitcoin Core
%% v31.1 (item verify-neon-beamchain-findings). CScript::IsPushOnly
%% (script.cpp) only asks `opcode > OP_16`, so OP_RESERVED (0x50) counts as
%% a push opcode. Solver (script/solver.cpp) therefore classifies
%% OP_RETURN OP_RESERVED (6a 50) as NULL_DATA, a standard output, and
%% decodescript reports it as "nulldata".

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

f7_is_push_only_accepts_op_reserved_test() ->
    ?assert(beamchain_script:is_push_only(<<16#50>>)),
    ?assert(beamchain_script:is_push_only(<<16#00, 16#50, 16#51, 16#02, 16#aa, 16#bb>>)).

f7_op_return_op_reserved_is_null_data_test() ->
    ?assertEqual(op_return, beamchain_mempool:classify_output_standard(<<16#6a, 16#50>>)).

f7_tx_with_op_return_op_reserved_output_is_standard_test() ->
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<9:256>>, index = 0},
                         script_sig = <<>>, sequence = 16#fffffffd, witness = []}],
        outputs = [#tx_out{value = 10000,
                           script_pubkey = <<16#00, 16#14, 0:160>>},
                   #tx_out{value = 0, script_pubkey = <<16#6a, 16#50>>}],
        locktime = 0},
    ?assertEqual(ok, beamchain_mempool:check_standard(Tx)).

%% Controls: an opcode above OP_16 is still not push-only, and a cut-off
%% push still is not.
f7_control_non_push_opcode_test() ->
    ?assertNot(beamchain_script:is_push_only(<<16#61>>)),
    ?assertEqual(nonstandard, beamchain_mempool:classify_output_standard(<<16#6a, 16#61>>)).

f7_control_cut_off_push_test() ->
    ?assertNot(beamchain_script:is_push_only(<<16#4d, 16#01>>)),
    ?assertNot(beamchain_script:is_push_only(<<16#02, 16#aa>>)).

%% Consensus control: a P2SH scriptSig holding OP_RESERVED now passes the
%% push-only test, but executing it still fails (BAD_OPCODE), as in Core,
%% under block flags. No spend that failed before passes.
f7_control_p2sh_script_sig_with_op_reserved_still_fails_test() ->
    Redeem = <<16#51>>,
    SPK = <<16#a9, 20, (beamchain_crypto:hash160(Redeem))/binary, 16#87>>,
    Flags = beamchain_script:flags_for_height(900000, mainnet),
    {error, E} = beamchain_script:verify_script_error(
                   <<1, 16#51, 16#50>>, SPK, [], Flags, #{}),
    ?assertEqual(<<"Opcode missing or not understood">>,
                 beamchain_script:script_error_string(E)),
    {error, E2} = beamchain_script:verify_script_error(
                    <<16#50, 1, 16#51>>, SPK, [], Flags, #{}),
    ?assertEqual(<<"Opcode missing or not understood">>,
                 beamchain_script:script_error_string(E2)).
