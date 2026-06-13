-module(beamchain_converttopsbt_joinpsbts_tests).

%%% -------------------------------------------------------------------
%%% W137 — converttopsbt + joinpsbts (Bitcoin Core v31.99 parity).
%%%
%%% Pure offline eunit (NO node, NO regtest). Drives the RPC handlers
%%% (`beamchain_rpc:rpc_converttopsbt/1`, `rpc_joinpsbts/1`) directly.
%%%
%%% Reference Core source:
%%%   src/rpc/rawtransaction.cpp converttopsbt() (:1663) / joinpsbts() (:1778)
%%%   src/core_io.cpp DecodeTx (full-byte-consumption gate)
%%%   src/psbt.cpp PartiallySignedTransaction::AddInput (:52 — clears
%%%     partial_sigs / final_script_sig / final_script_witness; duplicate
%%%     rejected only on FULL CTxIn match).
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_psbt.hrl").

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% PSBT magic.
-define(MAGIC, <<16#70, 16#73, 16#62, 16#74, 16#ff>>).

%% A simple unsigned tx with the given (outpoint, sequence) inputs and
%% (script, value) outputs. scriptSigs empty, no witness (BIP-174 shape).
mk_unsigned_tx(Ins, Outs) ->
    TxIns = [#tx_in{prev_out = #outpoint{hash = H, index = N},
                    script_sig = <<>>, sequence = Seq, witness = []}
             || {H, N, Seq} <- Ins],
    TxOuts = [#tx_out{value = V, script_pubkey = S} || {S, V} <- Outs],
    #transaction{version = 2, inputs = TxIns, outputs = TxOuts, locktime = 0}.

encode_kv(Key, Value) ->
    KeyLen = beamchain_serialize:encode_varint(byte_size(Key)),
    ValLen = beamchain_serialize:encode_varint(byte_size(Value)),
    <<KeyLen/binary, Key/binary, ValLen/binary, Value/binary>>.

%% Build a PSBT binary by hand. GlobalKVs/InputKVs/OutputKVs are lists of
%% {KeyBin, ValueBin}; InputKVs/OutputKVs are lists-of-lists (one inner
%% list per input/output map).
build_psbt(GlobalKVs, InputMaps, OutputMaps) ->
    Global = iolist_to_binary([ encode_kv(K, V) || {K, V} <- GlobalKVs ] ++ [<<0>>]),
    Inputs = iolist_to_binary(
               [ iolist_to_binary([ encode_kv(K, V) || {K, V} <- M ] ++ [<<0>>])
                 || M <- InputMaps ]),
    Outputs = iolist_to_binary(
                [ iolist_to_binary([ encode_kv(K, V) || {K, V} <- M ] ++ [<<0>>])
                  || M <- OutputMaps ]),
    iolist_to_binary([?MAGIC, Global, Inputs, Outputs]).

%% Build a base64 PSBT around an unsigned tx, with optional per-input KVs.
mk_psbt_b64(Tx, InputMaps, OutputMaps) ->
    TxBin = beamchain_serialize:encode_transaction(Tx, no_witness),
    Bin = build_psbt([{<<16#00>>, TxBin}], InputMaps, OutputMaps),
    base64:encode(Bin).

zero32(K) -> <<K:8, 0:248>>.

op_return(Payload) ->
    L = byte_size(Payload),
    <<16#6a, L:8, Payload/binary>>.

%%% ===================================================================
%%% converttopsbt
%%% ===================================================================

%% Input carrying a scriptSig + permitsigdata=false -> -22.
converttopsbt_rejects_sigdata_test() ->
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>, index = 0},
                         script_sig = <<16#51>>,   %% non-empty scriptSig
                         sequence = 16#fffffffd, witness = []}],
        outputs = [#tx_out{value = 0, script_pubkey = op_return(<<1,2,3>>)}],
        locktime = 0
    },
    Hex = beamchain_serialize:hex_encode(
            beamchain_serialize:encode_transaction(Tx, no_witness)),
    ?assertMatch({error, -22, <<"Inputs must not have scriptSigs and scriptWitnesses">>},
                 beamchain_rpc:rpc_converttopsbt([Hex])),
    %% permitsigdata=true -> succeeds, scriptSig stripped.
    {ok, B64} = beamchain_rpc:rpc_converttopsbt([Hex, true]),
    {ok, Psbt} = beamchain_psbt:decode(base64:decode(B64)),
    [In] = (beamchain_psbt:get_unsigned_tx(Psbt))#transaction.inputs,
    ?assertEqual(<<>>, In#tx_in.script_sig).

%% A blank PSBT has one empty per-input map and one empty per-output map.
converttopsbt_blank_maps_test() ->
    Tx = mk_unsigned_tx(
           [{<<7:256>>, 1, 16#fffffffe}],
           [{op_return(<<9,9>>), 0}]),
    Hex = beamchain_serialize:hex_encode(
            beamchain_serialize:encode_transaction(Tx, no_witness)),
    {ok, B64} = beamchain_rpc:rpc_converttopsbt([Hex]),
    {ok, Psbt} = beamchain_psbt:decode(base64:decode(B64)),
    %% One empty input map, one empty output map.
    ?assertEqual(#{}, beamchain_psbt:get_input(Psbt, 0)),
    ?assertEqual(#{}, beamchain_psbt:get_output(Psbt, 0)),
    ?assertEqual(undefined, beamchain_psbt:get_input(Psbt, 1)),
    ?assertEqual(undefined, beamchain_psbt:get_output(Psbt, 1)).

%%% --- The empty-vin full-consumption regression (W137 TRAP 1) --------
%%% hex 0200000000010000000000000000066a040001020300000000 :
%%%   legacy decode  -> 0 inputs, 1 OP_RETURN output (6a0400010203) -> OK
%%%   witness decode -> consumes only 12 of 25 bytes -> MUST be rejected.

-define(REGRESSION_HEX,
        <<"0200000000010000000000000000066a040001020300000000">>).
-define(EXPECTED_B64,
        <<"cHNidP8BABkCAAAAAAEAAAAAAAAAAAZqBAABAgMAAAAAAAA=">>).

%% Heuristic (no iswitness): legacy decode wins, OP_RETURN survives.
converttopsbt_empty_vin_heuristic_test() ->
    {ok, B64} = beamchain_rpc:rpc_converttopsbt([?REGRESSION_HEX]),
    ?assertEqual(?EXPECTED_B64, B64),
    {ok, Psbt} = beamchain_psbt:decode(base64:decode(B64)),
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    ?assertEqual(0, length(Tx#transaction.inputs)),
    ?assertEqual([op_return(<<0,1,2,3>>)],
                 [O#tx_out.script_pubkey || O <- Tx#transaction.outputs]).

%% iswitness=false: legacy-only, same result.
converttopsbt_empty_vin_iswitness_false_test() ->
    {ok, B64} = beamchain_rpc:rpc_converttopsbt([?REGRESSION_HEX, false, false]),
    ?assertEqual(?EXPECTED_B64, B64),
    {ok, Psbt} = beamchain_psbt:decode(base64:decode(B64)),
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    ?assertEqual(0, length(Tx#transaction.inputs)),
    ?assertEqual(1, length(Tx#transaction.outputs)).

%% iswitness=true: witness-only decode does NOT fully consume -> -22.
converttopsbt_empty_vin_iswitness_true_rejected_test() ->
    ?assertMatch({error, -22, <<"TX decode failed">>},
                 beamchain_rpc:rpc_converttopsbt([?REGRESSION_HEX, false, true])).

%% Garbage hex -> -22.
converttopsbt_garbage_test() ->
    ?assertMatch({error, -22, <<"TX decode failed">>},
                 beamchain_rpc:rpc_converttopsbt([<<"deadbeef">>])).

%%% ===================================================================
%%% joinpsbts
%%% ===================================================================

%% < 2 PSBTs -> RPC_INVALID_PARAMETER (-8).
joinpsbts_requires_two_test() ->
    One = mk_psbt_b64(mk_unsigned_tx([{<<1:256>>, 0, 16#ffffffff}], []), [[]], []),
    ?assertMatch({error, -8, <<"At least two PSBTs are required to join PSBTs.">>},
                 beamchain_rpc:rpc_joinpsbts([[One]])).

%% Duplicate FULL TxIn (same prevout AND same sequence) -> -8.
joinpsbts_duplicate_full_txin_test() ->
    OP = {<<5:256>>, 3, 16#fffffffd},
    A = mk_psbt_b64(mk_unsigned_tx([OP], [{op_return(<<1>>), 0}]), [[]], [[]]),
    B = mk_psbt_b64(mk_unsigned_tx([OP], [{op_return(<<2>>), 0}]), [[]], [[]]),
    Res = beamchain_rpc:rpc_joinpsbts([[A, B]]),
    ?assertMatch({error, -8, _}, Res),
    {error, -8, Msg} = Res,
    ?assertNotEqual(nomatch, binary:match(Msg, <<"exists in multiple PSBTs">>)).

%% Same outpoint, DIFFERENT sequence -> both kept (CTxIn::operator==
%% includes nSequence).
joinpsbts_same_outpoint_diff_seq_kept_test() ->
    H = <<6:256>>,
    A = mk_psbt_b64(mk_unsigned_tx([{H, 0, 16#fffffffd}], []), [[]], []),
    B = mk_psbt_b64(mk_unsigned_tx([{H, 0, 16#fffffffe}], []), [[]], []),
    {ok, B64} = beamchain_rpc:rpc_joinpsbts([[A, B]]),
    {ok, Psbt} = beamchain_psbt:decode(base64:decode(B64)),
    Ins = (beamchain_psbt:get_unsigned_tx(Psbt))#transaction.inputs,
    ?assertEqual(2, length(Ins)),
    SeqSet = lists:sort([I#tx_in.sequence || I <- Ins]),
    ?assertEqual([16#fffffffd, 16#fffffffe], SeqSet),
    %% Both share the same outpoint.
    ?assertEqual([H, H],
                 [ (I#tx_in.prev_out)#outpoint.hash || I <- Ins ]).

%% Set-union of inputs+outputs, with max-version / min-locktime.
joinpsbts_set_union_version_locktime_test() ->
    %% PSBT A: version 2, locktime 500000, input X, output P.
    TxA = #transaction{version = 2,
                       inputs = [#tx_in{prev_out = #outpoint{hash = <<10:256>>, index = 0},
                                        script_sig = <<>>, sequence = 16#ffffffff,
                                        witness = []}],
                       outputs = [#tx_out{value = 0, script_pubkey = op_return(<<"A">>)}],
                       locktime = 500000},
    %% PSBT B: version 7, locktime 100, input Y, output Q.
    TxB = #transaction{version = 7,
                       inputs = [#tx_in{prev_out = #outpoint{hash = <<20:256>>, index = 1},
                                        script_sig = <<>>, sequence = 16#ffffffff,
                                        witness = []}],
                       outputs = [#tx_out{value = 0, script_pubkey = op_return(<<"B">>)}],
                       locktime = 100},
    A = mk_psbt_b64(TxA, [[]], [[]]),
    B = mk_psbt_b64(TxB, [[]], [[]]),
    {ok, B64} = beamchain_rpc:rpc_joinpsbts([[A, B]]),
    {ok, Psbt} = beamchain_psbt:decode(base64:decode(B64)),
    Tx = beamchain_psbt:get_unsigned_tx(Psbt),
    %% max version, min locktime.
    ?assertEqual(7, Tx#transaction.version),
    ?assertEqual(100, Tx#transaction.locktime),
    %% Input SET = {X, Y} (order is shuffled, so compare as a set).
    InSet = lists:sort([ (I#tx_in.prev_out)#outpoint.hash
                         || I <- Tx#transaction.inputs ]),
    ?assertEqual([<<10:256>>, <<20:256>>], InSet),
    %% Output SET = {P, Q}.
    OutSet = lists:sort([ O#tx_out.script_pubkey
                          || O <- Tx#transaction.outputs ]),
    ?assertEqual(lists:sort([op_return(<<"A">>), op_return(<<"B">>)]), OutSet).

%% AddInput clears partial_sigs / final_script_sig / final_script_witness
%% on every merged input (Core psbt.cpp:58-60). Joining SIGNED PSBTs must
%% drop those fields.
joinpsbts_clears_sig_data_test() ->
    %% PSBT A: input carries a partial sig + a final scriptSig.
    PubKey = <<2, 0:248, 1>>,
    PartialSigKV = {<<16#02, PubKey/binary>>, <<"sig-bytes">>},
    FinalScriptSigKV = {<<16#07>>, <<16#51, 16#52>>},
    TxA = mk_unsigned_tx([{<<30:256>>, 0, 16#ffffffff}], [{op_return(<<"x">>), 0}]),
    A = mk_psbt_b64(TxA, [[PartialSigKV, FinalScriptSigKV]], [[]]),
    %% PSBT B: a distinct input, also with a partial sig.
    PartialSigKV2 = {<<16#02, PubKey/binary>>, <<"sig2">>},
    TxB = mk_unsigned_tx([{<<31:256>>, 0, 16#ffffffff}], [{op_return(<<"y">>), 0}]),
    B = mk_psbt_b64(TxB, [[PartialSigKV2]], [[]]),

    %% Sanity: pre-join, the crafted inputs DO carry sig data.
    {ok, PA} = beamchain_psbt:decode(base64:decode(A)),
    InA = beamchain_psbt:get_input(PA, 0),
    ?assert(maps:is_key(partial_sigs, InA)),
    ?assert(maps:is_key(final_script_sig, InA)),

    {ok, B64} = beamchain_rpc:rpc_joinpsbts([[A, B]]),
    {ok, Joined} = beamchain_psbt:decode(base64:decode(B64)),
    %% EVERY input map in the joined PSBT must be sig-data-free.
    Tx = beamchain_psbt:get_unsigned_tx(Joined),
    NumIn = length(Tx#transaction.inputs),
    lists:foreach(fun(I) ->
        M = beamchain_psbt:get_input(Joined, I),
        ?assertNot(maps:is_key(partial_sigs, M)),
        ?assertNot(maps:is_key(final_script_sig, M)),
        ?assertNot(maps:is_key(final_script_witness, M))
    end, lists:seq(0, NumIn - 1)).

%% Undecodable base64 PSBT -> -22.
joinpsbts_bad_psbt_test() ->
    Good = mk_psbt_b64(mk_unsigned_tx([{<<1:256>>, 0, 16#ffffffff}], []), [[]], []),
    Res = beamchain_rpc:rpc_joinpsbts([[Good, <<"bm90LWEtcHNidA==">>]]),
    ?assertMatch({error, -22, _}, Res).
