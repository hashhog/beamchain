-module(beamchain_neon_testnet3_flags_tests).

%% Finding 4 of the Gemini (Neon) audit of beamchain against Bitcoin Core
%% v31.1 (item verify-neon-beamchain-findings). beamchain supports testnet3
%% (`--network=testnet`, README). Core's GetBlockScriptFlags
%% (validation.cpp) height-gates DERSIG / CLTV / CSV / NULLDUMMY on testnet3
%% at CTestNetParams (kernel/chainparams.cpp):
%%   BIP66Height = 330776, BIP65Height = 581885, CSVHeight = 770112,
%%   SegwitHeight = 834624,
%% and its BIP16 exception block 514 (00000000dd30457c...) gets
%% SCRIPT_VERIFY_NONE as the base, with none of those four OR'd in below
%% their heights.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain_protocol.hrl").

-define(TRIO, (?SCRIPT_VERIFY_P2SH bor ?SCRIPT_VERIFY_WITNESS bor ?SCRIPT_VERIFY_TAPROOT)).

f(H) -> beamchain_script:flags_for_height(H, testnet).

has(Flag, Flags) -> (Flags band Flag) =/= 0.

testnet3_height_gates_test_() ->
    Gates = [{?SCRIPT_VERIFY_DERSIG, 330776},
             {?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, 581885},
             {?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, 770112},
             {?SCRIPT_VERIFY_NULLDUMMY, 834624}],
    [{lists:flatten(io_lib:format("flag ~.16b off below ~b, on at ~b", [Flag, H, H])),
      fun() ->
          ?assertNot(has(Flag, f(H - 1))),
          ?assert(has(Flag, f(H)))
      end} || {Flag, H} <- Gates].

testnet3_genesis_era_is_base_trio_only_test() ->
    ?assertEqual(?TRIO, f(1)),
    ?assertEqual(?TRIO, f(330775)).

%% Block 514, the testnet3 BIP16 exception: Core flags = SCRIPT_VERIFY_NONE.
testnet3_bip16_exception_block_514_is_none_test() ->
    Hash = beamchain_serialize:reverse_bytes(beamchain_serialize:hex_decode(
             "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105")),
    ?assertEqual(?SCRIPT_VERIFY_NONE, beamchain_script:flags_for_block(514, testnet, Hash)).

%% Controls: all seven consensus flags at testnet3's tip era, and the other
%% networks are unchanged (regtest/testnet4/signet: everything from height 1).
control_testnet3_all_flags_after_segwit_test() ->
    All = ?TRIO bor ?SCRIPT_VERIFY_DERSIG bor ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
          bor ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY bor ?SCRIPT_VERIFY_NULLDUMMY,
    ?assertEqual(All, f(834624)),
    ?assertEqual(All, f(4000000)),
    [?assertEqual(All, beamchain_script:flags_for_height(1, Net))
     || Net <- [regtest, testnet4, signet]].
