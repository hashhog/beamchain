-module(beamchain_witness_standard_tests).

%% EUnit tests for IsWitnessStandard (beamchain_mempool:is_witness_standard/2).
%% Reference: Bitcoin Core policy/policy.cpp:265-351.
%%
%% Tests are organised by gate number matching policy.cpp line references:
%%   Gate 1: coinbase exempt (policy.cpp:267-268)
%%   Gate 2: empty witness skipped (policy.cpp:273-275)
%%   Gate 3: P2A with witness → reject (policy.cpp:282-285)
%%   Gate 4: P2SH redeemScript extraction (policy.cpp:287-299)
%%   Gate 5: non-witness prevScript with non-empty witness → reject (policy.cpp:303-306)
%%   Gate 6: P2WSH limits (policy.cpp:308-319)
%%   Gate 7: Taproot limits (policy.cpp:321-349)

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% -------------------------------------------------------------------
%%% Helpers
%%% -------------------------------------------------------------------

%% Build a minimal transaction with one input and one output.
make_tx(Inputs) ->
    #transaction{
        version  = 2,
        inputs   = Inputs,
        outputs  = [#tx_out{value = 1000, script_pubkey = <<16#51, 16#20, 0:256>>}],
        locktime = 0,
        txid     = undefined,
        wtxid    = undefined
    }.

%% Build an input with a given scriptSig, witness, and prevout.
make_input(ScriptSig, Witness) ->
    #tx_in{
        prev_out   = #outpoint{hash = <<1:256>>, index = 0},
        script_sig = ScriptSig,
        sequence   = 16#ffffffff,
        witness    = Witness
    }.

%% Build a UTXO with the given scriptPubKey.
make_coin(ScriptPubKey) ->
    #utxo{value = 100000, script_pubkey = ScriptPubKey,
          is_coinbase = false, height = 1}.

%% Shorthand
ws(Tx, Coins) ->
    beamchain_mempool:is_witness_standard(Tx, Coins).

%%% ===================================================================
%%% Gate 1: Coinbase transactions are exempt
%%% ===================================================================

gate1_coinbase_exempt_test() ->
    %% A coinbase input has prevout hash = <<0:256>>, index = 16#ffffffff.
    %% Even with a non-empty witness it must pass.
    CoinbaseInput = #tx_in{
        prev_out   = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
        script_sig = <<16#03, 1, 2, 3>>,        %% arbitrary coinbase scriptSig
        sequence   = 16#ffffffff,
        witness    = [<<1, 2, 3>>]               %% non-empty witness
    },
    Tx = make_tx([CoinbaseInput]),
    %% Coinbase txs don't have UTXO coins in the usual sense; pass an empty list.
    %% is_witness_standard checks is_coinbase_tx first, so this never touches coins.
    ?assertEqual(true, ws(Tx, [])).

%%% ===================================================================
%%% Gate 2: Inputs with empty witness are skipped
%%% ===================================================================

gate2_empty_witness_skipped_test() ->
    %% P2PKH prevout with empty witness — should pass (no witness to inspect).
    P2PKH = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
    Input = make_input(<<>>, []),
    Tx = make_tx([Input]),
    Coin = make_coin(P2PKH),
    ?assertEqual(true, ws(Tx, [Coin])).

gate2_undefined_witness_skipped_test() ->
    P2PKH = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
    Input = make_input(<<>>, undefined),
    Tx = make_tx([Input]),
    Coin = make_coin(P2PKH),
    ?assertEqual(true, ws(Tx, [Coin])).

%%% ===================================================================
%%% Gate 3: P2A (pay-to-anchor) with any witness → reject
%%% ===================================================================

gate3_p2a_with_witness_rejected_test() ->
    %% P2A scriptPubKey: OP_1 OP_PUSHBYTES_2 0x4e73
    P2A = <<16#51, 16#02, 16#4e, 16#73>>,
    Input = make_input(<<>>, [<<>>]),   %% even a single empty push
    Tx = make_tx([Input]),
    Coin = make_coin(P2A),
    ?assertEqual(false, ws(Tx, [Coin])).

gate3_p2a_with_nonempty_witness_rejected_test() ->
    P2A = <<16#51, 16#02, 16#4e, 16#73>>,
    Input = make_input(<<>>, [<<1, 2, 3>>]),
    Tx = make_tx([Input]),
    Coin = make_coin(P2A),
    ?assertEqual(false, ws(Tx, [Coin])).

%%% ===================================================================
%%% Gate 4: P2SH — redeemScript extraction via scriptSig
%%% ===================================================================

gate4_p2sh_p2wsh_valid_test() ->
    %% Build a P2SH wrapping P2WSH: scriptSig = push(OP_0 <32-byte-hash>).
    %% The inner witness script is irrelevant for *this* gate test; we only
    %% verify that the scriptSig eval succeeds and the redeemScript is a
    %% valid witness program.
    WitnessScript = binary:copy(<<0>>, 32),   %% 32 bytes of zeros as script
    P2WSHProgram = crypto:hash(sha256, WitnessScript),
    %% Redeem script: OP_0 <32-byte-hash>
    RedeemScript = <<16#00, 16#20, P2WSHProgram/binary>>,
    %% scriptSig pushes the redeem script
    RSLen = byte_size(RedeemScript),
    ScriptSig = <<RSLen, RedeemScript/binary>>,
    %% P2SH scriptPubKey: OP_HASH160 <20-byte-hash160> OP_EQUAL
    P2SH_hash = crypto:hash(ripemd160, crypto:hash(sha256, RedeemScript)),
    P2SH = <<16#a9, 16#14, P2SH_hash/binary, 16#87>>,
    %% The witness is: [<signature>, RedeemScript] (simplified — the actual
    %% P2WSH witness would include the witness script as the last element).
    %% For the policy check, the key thing is: the last witness item is the
    %% script, and no data item exceeds 80 bytes.
    WitnessData = [<<16#30, 16#44, 0:510>>,   %% 68-byte DER sig (fits ≤ 80)
                   WitnessScript],
    Input = make_input(ScriptSig, WitnessData),
    Tx = make_tx([Input]),
    Coin = make_coin(P2SH),
    ?assertEqual(true, ws(Tx, [Coin])).

gate4_p2sh_empty_scriptsig_rejected_test() ->
    %% scriptSig is empty → eval returns [] → reject.
    P2SH = <<16#a9, 16#14, 0:160, 16#87>>,
    Input = make_input(<<>>, [<<1, 2>>]),   %% non-empty witness
    Tx = make_tx([Input]),
    Coin = make_coin(P2SH),
    ?assertEqual(false, ws(Tx, [Coin])).

%%% ===================================================================
%%% Gate 5: non-witness prevScript with non-empty witness → reject
%%% ===================================================================

gate5_p2pkh_with_witness_rejected_test() ->
    %% P2PKH is not a witness program. A non-empty witness alongside it is
    %% witness-stuffing and must be rejected. (policy.cpp:303-306)
    P2PKH = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
    Input = make_input(<<>>, [<<1, 2, 3>>]),
    Tx = make_tx([Input]),
    Coin = make_coin(P2PKH),
    ?assertEqual(false, ws(Tx, [Coin])).

gate5_bare_multisig_with_witness_rejected_test() ->
    %% Bare 1-of-1 multisig is not a witness program.
    %% OP_1 <33-byte-key> OP_1 OP_CHECKMULTISIG
    PubKey = binary:copy(<<16#02>>, 33),
    BareMultisig = <<16#51, 16#21, PubKey/binary, 16#51, 16#ae>>,
    Input = make_input(<<>>, [<<>>]),
    Tx = make_tx([Input]),
    Coin = make_coin(BareMultisig),
    ?assertEqual(false, ws(Tx, [Coin])).

%%% ===================================================================
%%% Gate 6: P2WSH limits
%%% ===================================================================

gate6_p2wsh_script_size_at_limit_test() ->
    %% Script exactly at MAX_STANDARD_P2WSH_SCRIPT_SIZE (3600 bytes) → OK.
    WitnessScript = binary:copy(<<16#61>>, 3600),   %% 3600 × OP_NOP
    P2WSH = <<16#00, 16#20, (crypto:hash(sha256, WitnessScript))/binary>>,
    Input = make_input(<<>>, [WitnessScript]),
    Tx = make_tx([Input]),
    Coin = make_coin(P2WSH),
    ?assertEqual(true, ws(Tx, [Coin])).

gate6_p2wsh_script_too_large_test() ->
    %% Script 1 byte over limit → reject.
    WitnessScript = binary:copy(<<16#61>>, 3601),
    P2WSH = <<16#00, 16#20, (crypto:hash(sha256, WitnessScript))/binary>>,
    Input = make_input(<<>>, [WitnessScript]),
    Tx = make_tx([Input]),
    Coin = make_coin(P2WSH),
    ?assertEqual(false, ws(Tx, [Coin])).

gate6_p2wsh_stack_items_at_limit_test() ->
    %% Exactly 100 non-script stack items → OK (policy.cpp:312-314).
    WitnessScript = <<16#51>>,   %% OP_1
    StackItems = lists:duplicate(100, <<1>>),   %% 100 × 1-byte items
    Witness = StackItems ++ [WitnessScript],
    P2WSH = <<16#00, 16#20, (crypto:hash(sha256, WitnessScript))/binary>>,
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(P2WSH),
    ?assertEqual(true, ws(Tx, [Coin])).

gate6_p2wsh_stack_items_over_limit_test() ->
    %% 101 non-script stack items → reject.
    WitnessScript = <<16#51>>,
    StackItems = lists:duplicate(101, <<1>>),
    Witness = StackItems ++ [WitnessScript],
    P2WSH = <<16#00, 16#20, (crypto:hash(sha256, WitnessScript))/binary>>,
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(P2WSH),
    ?assertEqual(false, ws(Tx, [Coin])).

gate6_p2wsh_item_size_at_limit_test() ->
    %% One stack item at exactly 80 bytes → OK.
    BigItem = binary:copy(<<0>>, 80),
    WitnessScript = <<16#51>>,
    Witness = [BigItem, WitnessScript],
    P2WSH = <<16#00, 16#20, (crypto:hash(sha256, WitnessScript))/binary>>,
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(P2WSH),
    ?assertEqual(true, ws(Tx, [Coin])).

gate6_p2wsh_item_size_over_limit_test() ->
    %% One stack item at 81 bytes → reject.
    BigItem = binary:copy(<<0>>, 81),
    WitnessScript = <<16#51>>,
    Witness = [BigItem, WitnessScript],
    P2WSH = <<16#00, 16#20, (crypto:hash(sha256, WitnessScript))/binary>>,
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(P2WSH),
    ?assertEqual(false, ws(Tx, [Coin])).

%%% ===================================================================
%%% Gate 7: Taproot policy limits (P2TR, not P2SH-wrapped)
%%% ===================================================================

%% Helper: 32-byte all-zero taproot output key (no specific validity needed for policy tests)
p2tr_spk() ->
    <<16#51, 16#20, 0:256>>.

gate7_p2tr_annex_rejected_test() ->
    %% Annex: last element starts with 0x50 and stack has ≥ 2 elements.
    %% (policy.cpp:327-330)
    Annex = <<?ANNEX_TAG, 1, 2, 3>>,
    StackElem = <<1, 2, 3>>,
    Witness = [StackElem, Annex],
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(p2tr_spk()),
    ?assertEqual(false, ws(Tx, [Coin])).

gate7_p2tr_empty_stack_skipped_test() ->
    %% 0 stack elements in the witness: Core's scriptWitness.IsNull() check at
    %% policy.cpp:274 skips inputs with an empty witness stack before reaching
    %% the P2TR branch.  The "0 elements" branch in Core (lines 345-348) is
    %% unreachable in practice because it would require a non-null witness that
    %% becomes empty after annex stripping — impossible given the annex check
    %% requires size >= 2.  So an empty witness on P2TR is skipped → standard.
    Witness = [],
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(p2tr_spk()),
    ?assertEqual(true, ws(Tx, [Coin])).

gate7_p2tr_key_path_valid_test() ->
    %% Key-path spend: exactly 1 element (64-byte Schnorr sig). No size limit
    %% beyond 80 bytes applies here (policy.cpp:342-344).
    Sig64 = binary:copy(<<16#aa>>, 64),
    Witness = [Sig64],
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(p2tr_spk()),
    ?assertEqual(true, ws(Tx, [Coin])).

gate7_p2tr_tapscript_item_at_limit_test() ->
    %% Script-path spend with leaf version 0xc0 (tapscript).
    %% Stack args each ≤ 80 bytes → OK.
    LeafVersion = 16#c0,
    ControlBlock = <<LeafVersion, 0:256>>,   %% leaf version + 32-byte internal key
    WitnessScript = <<16#51>>,               %% OP_1
    Arg = binary:copy(<<1>>, 80),            %% exactly 80 bytes
    Witness = [Arg, WitnessScript, ControlBlock],
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(p2tr_spk()),
    ?assertEqual(true, ws(Tx, [Coin])).

gate7_p2tr_tapscript_item_over_limit_test() ->
    %% Script-path spend with leaf version 0xc0: one arg > 80 bytes → reject.
    LeafVersion = 16#c0,
    ControlBlock = <<LeafVersion, 0:256>>,
    WitnessScript = <<16#51>>,
    BigArg = binary:copy(<<1>>, 81),
    Witness = [BigArg, WitnessScript, ControlBlock],
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(p2tr_spk()),
    ?assertEqual(false, ws(Tx, [Coin])).

gate7_p2tr_non_tapscript_leaf_no_limit_test() ->
    %% Script-path spend with a non-tapscript leaf version (e.g. 0xc2).
    %% No per-item size limit applies for unknown leaf versions.
    LeafVersion = 16#c2,
    ControlBlock = <<LeafVersion, 0:256>>,
    WitnessScript = <<16#51>>,
    BigArg = binary:copy(<<1>>, 200),   %% > 80 bytes — still OK for non-tapscript
    Witness = [BigArg, WitnessScript, ControlBlock],
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(p2tr_spk()),
    ?assertEqual(true, ws(Tx, [Coin])).

gate7_p2tr_script_path_no_annex_valid_test() ->
    %% Script-path spend without annex, all args ≤ 80 bytes → OK.
    LeafVersion = 16#c0,
    ControlBlock = <<LeafVersion, 0:256>>,
    WitnessScript = <<16#61>>,   %% OP_NOP
    Arg1 = binary:copy(<<2>>, 32),
    Arg2 = binary:copy(<<3>>, 32),
    Witness = [Arg1, Arg2, WitnessScript, ControlBlock],
    Input = make_input(<<>>, Witness),
    Tx = make_tx([Input]),
    Coin = make_coin(p2tr_spk()),
    ?assertEqual(true, ws(Tx, [Coin])).

%%% ===================================================================
%%% Multi-input: first input OK, second input fails
%%% ===================================================================

multi_input_second_fails_test() ->
    %% First input: P2WPKH with a valid 1-item witness.
    P2WPKH = <<16#00, 16#14, 0:160>>,
    Input1 = make_input(<<>>, [binary:copy(<<1>>, 73)]),  %% 73-byte sig (fits)
    Coin1 = make_coin(P2WPKH),
    %% Second input: P2PKH with a non-empty witness → reject (gate 5).
    P2PKH = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>,
    Input2 = make_input(<<>>, [<<1, 2, 3>>]),
    Coin2 = make_coin(P2PKH),
    Tx = make_tx([Input1, Input2]),
    ?assertEqual(false, ws(Tx, [Coin1, Coin2])).

multi_input_both_ok_test() ->
    %% Two P2WPKH inputs each with valid single-element witness.
    P2WPKH = <<16#00, 16#14, 0:160>>,
    Input1 = make_input(<<>>, [binary:copy(<<1>>, 73)]),
    Input2 = make_input(<<>>, [binary:copy(<<2>>, 73)]),
    Coin = make_coin(P2WPKH),
    Tx = make_tx([Input1, Input2]),
    ?assertEqual(true, ws(Tx, [Coin, Coin])).
