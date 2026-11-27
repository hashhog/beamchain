-module(beamchain_neon_validation_findings_tests).

%% Findings 9, 15 and 18 of the Gemini (Neon) audit of beamchain against
%% Bitcoin Core v31.1 (item verify-neon-beamchain-findings).
%%
%%   F9   P2SH and P2SH-wrapped witness sigop counting.
%%        CScript::GetSigOpCount(scriptSig) (script.cpp) returns 0 when
%%        GetOp fails (a cut-off push) and every GetOp clears vData first,
%%        so a trailing OP_RESERVED / OP_n leaves an empty subscript.
%%        CountWitnessSigOps (interpreter.cpp) looks inside a P2SH scriptSig
%%        only when scriptSig.IsPushOnly(), and takes the last GetOp's data.
%%   F15  ConnectBlock (validation.cpp) skips BIP30 only when
%%        pindex->pprev->GetAncestor(BIP34Height) is BIP34Hash. For the
%%        block AT BIP34Height, pprev is one below it, the ancestor is null,
%%        and BIP30 is enforced.
%%   F18  CheckTransaction (consensus/tx_check.cpp) rejects a transaction
%%        whose stripped size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT with
%%        bad-txns-oversize, before the output checks.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(OP_RESERVED, 16#50).
-define(OP_NOP, 16#61).
-define(OP_CHECKSIG, 16#ac).

p2sh_spk() -> <<16#a9, 20, 0:160, 16#87>>.

coin(SPK) -> #utxo{value = 1000, script_pubkey = SPK, is_coinbase = false, height = 1}.

tx_with_script_sig(ScriptSig, Witness) ->
    #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<5:256>>, index = 0},
                         script_sig = ScriptSig, sequence = 16#ffffffff,
                         witness = Witness}],
        outputs = [#tx_out{value = 500, script_pubkey = <<16#51>>}],
        locktime = 0}.

push(Data) when byte_size(Data) =< 75 -> <<(byte_size(Data)), Data/binary>>.

p2sh_sigops(ScriptSig) ->
    beamchain_validation:count_p2sh_sigops(tx_with_script_sig(ScriptSig, []),
                                           [coin(p2sh_spk())]).

witness_sigops(ScriptSig, Witness) ->
    beamchain_validation:count_witness_sigops(tx_with_script_sig(ScriptSig, Witness),
                                              [coin(p2sh_spk())]).

%% A redeem script with 2 sigops, and a P2WPKH redeem script (1 witness sigop).
redeem2() -> <<16#51, ?OP_CHECKSIG, ?OP_CHECKSIG>>.
p2wpkh_redeem() -> <<0, 20, 0:160>>.

%%% ===================================================================
%%% F9: P2SH sigops (GetSigOpCount(scriptSig))
%%% ===================================================================

%% Cut-off pushes: Core's GetOp fails -> 0. master: function_clause crash.
f9_p2sh_cutoff_pushdata1_counts_zero_test() ->
    ?assertEqual(0, p2sh_sigops(<<(push(redeem2()))/binary, 16#4c>>)).

f9_p2sh_cutoff_pushdata2_counts_zero_test() ->
    ?assertEqual(0, p2sh_sigops(<<(push(redeem2()))/binary, 16#4d, 16#01>>)).

f9_p2sh_cutoff_pushdata4_counts_zero_test() ->
    ?assertEqual(0, p2sh_sigops(<<(push(redeem2()))/binary, 16#4e, 0, 0, 0>>)).

%% OP_RESERVED after the redeem script: GetOp clears vData -> empty
%% subscript -> 0. master kept the redeem script and counted 2.
f9_p2sh_trailing_op_reserved_counts_zero_test() ->
    ?assertEqual(0, p2sh_sigops(<<(push(redeem2()))/binary, ?OP_RESERVED>>)).

%% get_p2sh_redeem_script/1 itself must answer, not crash, on a cut-off push.
f9_get_p2sh_redeem_script_cutoff_no_crash_test() ->
    ?assertEqual(error, beamchain_validation:get_p2sh_redeem_script(<<16#4c>>)),
    ?assertEqual(error, beamchain_validation:get_p2sh_redeem_script(<<16#4d, 1>>)),
    ?assertEqual(error, beamchain_validation:get_p2sh_redeem_script(<<16#4e, 1, 0>>)).

%% Controls: the plain redeem-script push counts 2; a non-push opcode
%% (> OP_16) counts 0; a push after OP_RESERVED is the one counted.
f9_control_p2sh_plain_counts_two_test() ->
    ?assertEqual(2, p2sh_sigops(push(redeem2()))).

f9_control_p2sh_non_push_counts_zero_test() ->
    ?assertEqual(0, p2sh_sigops(<<(push(redeem2()))/binary, ?OP_NOP>>)).

f9_control_p2sh_push_after_reserved_counts_test() ->
    ?assertEqual(2, p2sh_sigops(<<?OP_RESERVED, (push(redeem2()))/binary>>)).

%%% ===================================================================
%%% F9: P2SH-wrapped witness sigops (CountWitnessSigOps)
%%% ===================================================================

%% Not push-only (OP_NOP after the P2WPKH push): Core counts 0, master 1.
f9_witness_non_push_only_script_sig_counts_zero_test() ->
    ?assertEqual(0, witness_sigops(<<(push(p2wpkh_redeem()))/binary, ?OP_NOP>>,
                                   [<<1>>, <<2>>])).

%% OP_RESERVED is push-only, but its GetOp leaves data empty: the subscript
%% is empty, not a witness program -> 0. master 1.
f9_witness_trailing_op_reserved_counts_zero_test() ->
    ?assertEqual(0, witness_sigops(<<(push(p2wpkh_redeem()))/binary, ?OP_RESERVED>>,
                                   [<<1>>, <<2>>])).

f9_control_witness_p2sh_p2wpkh_counts_one_test() ->
    ?assertEqual(1, witness_sigops(push(p2wpkh_redeem()), [<<1>>, <<2>>])).

%%% ===================================================================
%%% F15: BIP30 is still enforced at exactly BIP34Height
%%% ===================================================================

with_slot(Hash, Fun) ->
    ok = meck:new(beamchain_db, [passthrough, non_strict]),
    try
        meck:expect(beamchain_db, get_block_index,
                    fun(_H) -> {ok, #{hash => Hash}} end),
        Fun()
    after
        meck:unload(beamchain_db)
    end.

f15_bip30_still_enforced_at_bip34_height_test() ->
    H = <<16#11:256>>,
    with_slot(H, fun() ->
        %% Core: pprev (227930) has no ancestor at 227931 -> enforce BIP30.
        ?assertNot(beamchain_validation:bip34_canonical_chain_active(227931, 227931, H))
    end).

f15_control_bip30_skipped_above_bip34_height_test() ->
    H = <<16#11:256>>,
    with_slot(H, fun() ->
        ?assert(beamchain_validation:bip34_canonical_chain_active(227932, 227931, H)),
        ?assertNot(beamchain_validation:bip34_canonical_chain_active(227932, 227931, <<16#22:256>>))
    end).

%%% ===================================================================
%%% F18: bad-txns-oversize
%%% ===================================================================

%% One output whose scriptPubKey makes the stripped tx just over 1,000,000
%% bytes (4,000,000 weight units / 4).
oversize_tx(StrippedSize) ->
    Base = tx_with_script_sig(<<>>, []),
    Empty = byte_size(beamchain_serialize:encode_transaction(
                        Base#transaction{outputs = [#tx_out{value = 1, script_pubkey = <<>>}]},
                        no_witness)),
    %% A scriptPubKey of L >= 0x10000 bytes costs L + 5 bytes (0xfe + 4-byte
    %% CompactSize) instead of the empty script's 1.
    L = StrippedSize - Empty - 4,
    Tx = Base#transaction{outputs = [#tx_out{value = 1, script_pubkey = binary:copy(<<16#6a>>, L)}]},
    StrippedSize = byte_size(beamchain_serialize:encode_transaction(Tx, no_witness)),
    Tx.

f18_oversize_tx_rejected_test() ->
    ?assertEqual({error, oversize},
                 beamchain_validation:check_transaction(oversize_tx(1000001))).

%% Core checks oversize before the output values: a tx that is both
%% oversize and has a negative output is bad-txns-oversize.
f18_oversize_checked_before_outputs_test() ->
    Tx = oversize_tx(1000001),
    [Out] = Tx#transaction.outputs,
    ?assertEqual({error, oversize},
                 beamchain_validation:check_transaction(
                   Tx#transaction{outputs = [Out#tx_out{value = -1}]})).

f18_oversize_maps_to_core_token_test() ->
    %% sendrawtransaction's {validation, Atom} route (Core: RPC_VERIFY_REJECTED).
    ?assertEqual({error, -26, <<"bad-txns-oversize">>},
                 beamchain_rpc:format_mempool_error({validation, oversize}, <<0:256>>)).

%% Control: exactly 1,000,000 stripped bytes is allowed (> not >=).
f18_control_max_size_tx_ok_test() ->
    ?assertEqual(ok, beamchain_validation:check_transaction(oversize_tx(1000000))).

%%% F18 at block level. Core's CheckBlock (validation.cpp) checks the size
%%% limits ("bad-blk-length": stripped block size * 4 > MAX_BLOCK_WEIGHT)
%%% right after the merkle root and BEFORE CheckTransaction runs on each tx.
%%% So a block holding an oversize tx is bad-blk-length, never a per-tx
%%% bad-txns-oversize: the new CheckTransaction rule must not change the
%%% block's reason (P2P treats bad_blk_length as a consensus verdict).

f18_block(Txs) ->
    Root = beamchain_serialize:compute_merkle_root(
             [beamchain_serialize:tx_hash(T) || T <- Txs]),
    Hdr = #block_header{version = 4, prev_hash = <<1:256>>,
                        merkle_root = Root, timestamp = 1700000000,
                        bits = 16#207fffff, nonce = 0},
    #block{header = Hdr, transactions = Txs}.

f18_coinbase() ->
    #transaction{version = 1,
                 inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                                       index = 16#ffffffff},
                                  script_sig = <<1, 100, 0>>,
                                  sequence = 16#ffffffff, witness = []}],
                 outputs = [#tx_out{value = 50 * 100000000,
                                    script_pubkey = <<16#51>>}],
                 locktime = 0}.

check_block_nopow(Block) ->
    beamchain_validation:check_block(
      Block, beamchain_chain_params:params(regtest), false, false).

f18_block_with_oversize_tx_is_bad_blk_length_test() ->
    ?assertEqual({error, bad_blk_length},
                 check_block_nopow(f18_block([f18_coinbase(),
                                              oversize_tx(1000001)]))).

%% Core runs the size limits before the coinbase checks too: an oversize
%% block whose first tx is not a coinbase is still bad-blk-length.
f18_oversize_block_without_coinbase_is_bad_blk_length_test() ->
    ?assertEqual({error, bad_blk_length},
                 check_block_nopow(f18_block([oversize_tx(1000001)]))).

%% Control: under the size limit, a bad tx is still reported per tx.
f18_control_small_block_bad_tx_still_per_tx_test() ->
    Bad = tx_with_script_sig(<<>>, []),
    [Out] = Bad#transaction.outputs,
    ?assertEqual({error, {bad_tx, negative_output}},
                 check_block_nopow(f18_block([f18_coinbase(),
                     Bad#transaction{outputs = [Out#tx_out{value = -1}]}]))).

%% Control: a small valid-shaped block passes check_block.
f18_control_small_block_ok_test() ->
    ?assertEqual(ok, check_block_nopow(
                       f18_block([f18_coinbase(), tx_with_script_sig(<<>>, [])]))).
