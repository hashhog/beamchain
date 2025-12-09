-module(beamchain_validation).

%% Block and transaction validation — Bitcoin consensus rules.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Context-free checks
-export([check_transaction/1]).
-export([check_block_header/2, check_block/2]).

%% Contextual checks (need chain state)
-export([contextual_check_block_header/3]).
-export([median_time_past/1]).

%% Contextual block checks
-export([contextual_check_block/4]).

%% Sigops counting
-export([count_legacy_sigops/1]).
-export([count_p2sh_sigops/2, count_witness_sigops/2]).
-export([get_tx_sigop_cost/3]).

%%% -------------------------------------------------------------------
%%% Context-free block header validation
%%% -------------------------------------------------------------------

%% @doc Validate a block header without chain context.
%% Checks PoW and basic timestamp sanity.
-spec check_block_header(#block_header{}, map()) -> ok | {error, atom()}.
check_block_header(Header, Params) ->
    try
        PowLimit = maps:get(pow_limit, Params),

        %% 1. verify PoW: block hash <= target from bits
        BlockHash = beamchain_serialize:block_hash(Header),
        beamchain_pow:check_pow(BlockHash, Header#block_header.bits, PowLimit)
            orelse throw(high_hash),

        %% 2. verify timestamp is not more than 2 hours in the future
        MaxFutureTime = erlang:system_time(second) + 2 * 60 * 60,
        Header#block_header.timestamp =< MaxFutureTime
            orelse throw(time_too_new),

        %% 3. verify bits is within pow_limit
        Target = beamchain_pow:bits_to_target(Header#block_header.bits),
        PowLimitInt = binary:decode_unsigned(PowLimit, big),
        Target > 0 orelse throw(bad_diffbits),
        Target =< PowLimitInt orelse throw(bad_diffbits),

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%%% -------------------------------------------------------------------
%%% Context-free block validation
%%% -------------------------------------------------------------------

%% @doc Validate block structure without chain context.
-spec check_block(#block{}, map()) -> ok | {error, atom()}.
check_block(#block{header = Header, transactions = Txs}, Params) ->
    try
        %% 1. check header
        case check_block_header(Header, Params) of
            ok -> ok;
            {error, E} -> throw(E)
        end,

        %% 2. at least one transaction
        Txs =/= [] orelse throw(no_transactions),

        %% 3. first transaction must be coinbase
        [CoinbaseTx | RestTxs] = Txs,
        is_coinbase_tx(CoinbaseTx) orelse throw(first_tx_not_coinbase),

        %% 4. no other transaction may be coinbase
        lists:foreach(fun(Tx) ->
            is_coinbase_tx(Tx) andalso throw(extra_coinbase)
        end, RestTxs),

        %% 5. check each transaction
        lists:foreach(fun(Tx) ->
            case check_transaction(Tx) of
                ok -> ok;
                {error, E2} -> throw({bad_tx, E2})
            end
        end, Txs),

        %% 6. verify merkle root
        TxHashes = [beamchain_serialize:tx_hash(Tx) || Tx <- Txs],
        ComputedMerkle = beamchain_serialize:compute_merkle_root(TxHashes),
        ComputedMerkle =:= Header#block_header.merkle_root
            orelse throw(bad_merkle_root),

        %% 7. check for merkle tree malleation (CVE-2012-2459)
        %% if the last two tx hashes at any level are the same, the
        %% merkle tree could be mutated. We check for duplicate final
        %% leaves which is the simplest form of this attack.
        check_merkle_malleation(TxHashes),

        %% 8. verify block weight <= MAX_BLOCK_WEIGHT
        BlockWeight = compute_block_weight(Txs),
        BlockWeight =< ?MAX_BLOCK_WEIGHT orelse throw(bad_blk_weight),

        %% 9. count legacy sigops
        LegacySigops = lists:foldl(fun(Tx, Acc) ->
            Acc + count_legacy_sigops_tx(Tx)
        end, 0, Txs),
        %% legacy sigops are scaled by witness factor
        LegacySigops * ?WITNESS_SCALE_FACTOR =< ?MAX_BLOCK_SIGOPS_COST
            orelse throw(bad_blk_sigops),

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%%% -------------------------------------------------------------------
%%% Contextual block header validation
%%% -------------------------------------------------------------------

%% @doc Validate a block header with chain context (previous block info).
%% PrevIndex is a map with keys: height, header, chainwork, status.
-spec contextual_check_block_header(#block_header{}, map(), map()) ->
    ok | {error, atom()}.
contextual_check_block_header(Header, PrevIndex, Params) ->
    try
        PrevHeight = maps:get(height, PrevIndex),
        Height = PrevHeight + 1,

        %% 1. verify difficulty matches expected
        ExpectedBits = beamchain_pow:get_next_work_required(
            PrevIndex, Header, Params),
        Header#block_header.bits =:= ExpectedBits
            orelse throw(bad_diffbits),

        %% 2. verify timestamp > median time past
        MTP = median_time_past(PrevIndex),
        Header#block_header.timestamp > MTP
            orelse throw(time_too_old),

        %% 3. verify block version (BIP 34: version >= 2 after activation)
        Bip34Height = maps:get(bip34_height, Params, 0),
        case Height >= Bip34Height of
            true ->
                Header#block_header.version >= 2
                    orelse throw(bad_version);
            false -> ok
        end,

        %% BIP 66: version >= 3 after activation
        Bip66Height = maps:get(bip66_height, Params, 0),
        case Height >= Bip66Height of
            true ->
                Header#block_header.version >= 3
                    orelse throw(bad_version);
            false -> ok
        end,

        %% BIP 65: version >= 4 after activation
        Bip65Height = maps:get(bip65_height, Params, 0),
        case Height >= Bip65Height of
            true ->
                Header#block_header.version >= 4
                    orelse throw(bad_version);
            false -> ok
        end,

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%% @doc Compute median time past from the previous block index.
%% Returns the median timestamp of the last 11 blocks.
-spec median_time_past(map()) -> non_neg_integer().
median_time_past(PrevIndex) ->
    Timestamps = collect_timestamps(PrevIndex, 11, []),
    Sorted = lists:sort(Timestamps),
    lists:nth((length(Sorted) div 2) + 1, Sorted).

%% Collect up to N timestamps walking backwards through the chain
collect_timestamps(_Index, 0, Acc) -> Acc;
collect_timestamps(Index, N, Acc) ->
    Header = maps:get(header, Index),
    Height = maps:get(height, Index),
    Ts = Header#block_header.timestamp,
    case Height of
        0 -> [Ts | Acc];
        _ ->
            PrevIndex = case beamchain_db:get_block_index(Height - 1) of
                {ok, PI} -> PI;
                not_found -> error({block_index_not_found, Height - 1})
            end,
            collect_timestamps(PrevIndex, N - 1, [Ts | Acc])
    end.

%%% -------------------------------------------------------------------
%%% Contextual block validation
%%% -------------------------------------------------------------------

%% @doc Validate a block with chain context.
%% Checks BIP 34 coinbase height, witness commitment, etc.
-spec contextual_check_block(#block{}, non_neg_integer(), map(), map()) ->
    ok | {error, atom()}.
contextual_check_block(#block{header = _Header, transactions = Txs},
                       Height, _PrevIndex, Params) ->
    try
        [CoinbaseTx | _] = Txs,

        %% 1. BIP 34: coinbase must contain block height
        Bip34Height = maps:get(bip34_height, Params, 0),
        case Height >= Bip34Height of
            true ->
                check_coinbase_height(CoinbaseTx, Height);
            false -> ok
        end,

        %% 2. BIP 141: witness commitment in coinbase
        SegwitHeight = maps:get(segwit_height, Params, 0),
        case Height >= SegwitHeight of
            true ->
                HasWitnessTx = lists:any(fun has_witness/1, tl(Txs)),
                case HasWitnessTx of
                    true ->
                        check_witness_commitment(CoinbaseTx, Txs);
                    false ->
                        %% no witness txs, commitment is optional
                        ok
                end;
            false -> ok
        end,

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%% @doc Check BIP 34: coinbase scriptSig must start with a push of the height.
%% Bitcoin Core uses the direct push encoding:
%%   <<NumBytes, Height:NumBytes*8/little>>
check_coinbase_height(#transaction{inputs = [#tx_in{script_sig = ScriptSig}]},
                      Height) ->
    case Height of
        0 ->
            %% height 0: OP_0 is acceptable (empty push)
            ok;
        _ when Height >= 1, Height =< 16 ->
            %% heights 1-16: could use OP_1..OP_16 but Bitcoin Core
            %% uses the push encoding: <<0x01, Height>>
            case ScriptSig of
                <<16#01, H:8, _/binary>> when H =:= Height -> ok;
                <<OpN:8, _/binary>> when OpN =:= 16#50 + Height -> ok;
                _ -> throw(bad_cb_height)
            end;
        _ ->
            %% general case: <<NumBytes, Height:NumBytes*8/little, ...>>
            NumBytes = height_byte_len(Height),
            case ScriptSig of
                <<NB:8, _/binary>> when NB =:= NumBytes ->
                    <<_:8, HeightBytes:NumBytes/binary, _/binary>> = ScriptSig,
                    %% decode little-endian height
                    Decoded = decode_le_uint(HeightBytes),
                    Decoded =:= Height orelse throw(bad_cb_height),
                    ok;
                _ ->
                    throw(bad_cb_height)
            end
    end.

%% Calculate minimum bytes needed to encode a height in little-endian
height_byte_len(N) when N =< 16#ff -> 1;
height_byte_len(N) when N =< 16#ffff -> 2;
height_byte_len(N) when N =< 16#ffffff -> 3;
height_byte_len(N) when N =< 16#ffffffff -> 4;
height_byte_len(_) -> 5.

%% Decode a little-endian unsigned integer from bytes
decode_le_uint(Bytes) ->
    decode_le_uint(Bytes, 0, 0).

decode_le_uint(<<>>, _Shift, Acc) -> Acc;
decode_le_uint(<<B:8, Rest/binary>>, Shift, Acc) ->
    decode_le_uint(Rest, Shift + 8, Acc bor (B bsl Shift)).

%% @doc Check BIP 141 witness commitment in coinbase.
%% The coinbase must contain an output whose scriptPubKey starts with:
%%   OP_RETURN 0x24 0xaa21a9ed <32-byte commitment>
%% Use the LAST matching output if multiple exist.
check_witness_commitment(CoinbaseTx, AllTxs) ->
    %% find the witness commitment output (last matching one)
    Outputs = CoinbaseTx#transaction.outputs,
    WitnessCommitmentPrefix = <<16#6a, 16#24, 16#aa, 16#21, 16#a9, 16#ed>>,
    CommitmentOutputs = lists:filter(fun(#tx_out{script_pubkey = SPK}) ->
        byte_size(SPK) >= 38 andalso
        binary:part(SPK, 0, 6) =:= WitnessCommitmentPrefix
    end, Outputs),

    case CommitmentOutputs of
        [] ->
            throw(missing_witness_commitment);
        _ ->
            %% use the last matching output
            #tx_out{script_pubkey = CommitSPK} = lists:last(CommitmentOutputs),
            <<_:6/binary, ExpectedCommitment:32/binary, _/binary>> = CommitSPK,

            %% get witness nonce from coinbase witness
            [CbInput | _] = CoinbaseTx#transaction.inputs,
            WitnessNonce = case CbInput#tx_in.witness of
                [Nonce | _] when byte_size(Nonce) =:= 32 -> Nonce;
                _ -> throw(bad_witness_nonce)
            end,

            %% compute expected commitment
            %% wtxids: coinbase wtxid is 32 zero bytes
            Wtxids = [<<0:256>> | [beamchain_serialize:wtx_hash(Tx) || Tx <- tl(AllTxs)]],
            Commitment = beamchain_serialize:compute_witness_commitment(
                Wtxids, WitnessNonce),

            Commitment =:= ExpectedCommitment orelse throw(bad_witness_commitment),
            ok
    end.

%% Check if a transaction has witness data
has_witness(#transaction{inputs = Inputs}) ->
    lists:any(fun(#tx_in{witness = W}) ->
        W =/= [] andalso W =/= undefined
    end, Inputs).

%%% -------------------------------------------------------------------
%%% Context-free transaction validation
%%% -------------------------------------------------------------------

%% @doc Validate a transaction without any chain context.
%% Checks structural rules that can be verified in isolation.
-spec check_transaction(#transaction{}) -> ok | {error, atom()}.
check_transaction(#transaction{inputs = Inputs, outputs = Outputs} = Tx) ->
    try
        %% 1. must have at least one input and one output
        Inputs =/= [] orelse throw(no_inputs),
        Outputs =/= [] orelse throw(no_outputs),

        %% 2. check serialized size is non-empty
        %% (implicit: we have inputs and outputs)

        %% 3. each output value must be non-negative and <= MAX_MONEY
        lists:foreach(fun(#tx_out{value = V}) ->
            V >= 0 orelse throw(negative_output),
            V =< ?MAX_MONEY orelse throw(output_too_large)
        end, Outputs),

        %% 4. total output value <= MAX_MONEY (check for overflow)
        TotalOut = lists:foldl(fun(#tx_out{value = V}, Acc) ->
            Sum = Acc + V,
            Sum =< ?MAX_MONEY orelse throw(total_output_overflow),
            Sum
        end, 0, Outputs),
        TotalOut =< ?MAX_MONEY orelse throw(total_output_overflow),

        %% 5. no duplicate input outpoints
        check_duplicate_inputs(Inputs),

        %% 6. coinbase-specific checks
        IsCoinbase = is_coinbase_tx(Tx),
        case IsCoinbase of
            true ->
                %% coinbase scriptSig must be 2-100 bytes
                [#tx_in{script_sig = CbScript} | _] = Inputs,
                SigLen = byte_size(CbScript),
                (SigLen >= 2 andalso SigLen =< 100) orelse
                    throw(bad_coinbase_length);
            false ->
                %% 7. non-coinbase: no null outpoints
                lists:foreach(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
                    case H =:= <<0:256>> andalso I =:= 16#ffffffff of
                        true -> throw(null_input);
                        false -> ok
                    end
                end, Inputs)
        end,

        %% 8. transaction weight >= MIN_TRANSACTION_WEIGHT
        Weight = beamchain_serialize:tx_weight(Tx),
        Weight >= ?MIN_TRANSACTION_WEIGHT orelse throw(tx_underweight),

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%%% -------------------------------------------------------------------
%%% Internal helpers
%%% -------------------------------------------------------------------

%% @doc Check if a transaction is a coinbase transaction.
is_coinbase_tx(#transaction{inputs = [#tx_in{prev_out =
    #outpoint{hash = <<0:256>>, index = 16#ffffffff}}]}) -> true;
is_coinbase_tx(_) -> false.

%% @doc Check for duplicate input outpoints.
check_duplicate_inputs(Inputs) ->
    Outpoints = [{H, I} || #tx_in{prev_out = #outpoint{hash = H, index = I}} <- Inputs],
    case length(Outpoints) =:= length(lists:usort(Outpoints)) of
        true -> ok;
        false -> throw(duplicate_inputs)
    end.

%% @doc Compute total block weight from transactions.
compute_block_weight(Txs) ->
    %% 80-byte header * 4 (witness scale) + sum of tx weights
    HeaderWeight = 80 * ?WITNESS_SCALE_FACTOR,
    TxWeight = lists:foldl(fun(Tx, Acc) ->
        Acc + beamchain_serialize:tx_weight(Tx)
    end, 0, Txs),
    HeaderWeight + TxWeight.

%% @doc Count legacy sigops in a transaction (context-free).
%% Counts OP_CHECKSIG/VERIFY as 1 each, OP_CHECKMULTISIG/VERIFY as 20 each.
count_legacy_sigops_tx(#transaction{inputs = Inputs, outputs = Outputs}) ->
    InputSigops = lists:foldl(fun(#tx_in{script_sig = S}, Acc) ->
        Acc + count_legacy_sigops(S)
    end, 0, Inputs),
    OutputSigops = lists:foldl(fun(#tx_out{script_pubkey = S}, Acc) ->
        Acc + count_legacy_sigops(S)
    end, 0, Outputs),
    InputSigops + OutputSigops.

%% @doc Count legacy sigops in a script (raw opcode scan).
count_legacy_sigops(Script) ->
    count_legacy_sigops(Script, 0).

count_legacy_sigops(<<>>, Count) -> Count;
%% data push: 1-75 bytes
count_legacy_sigops(<<N:8, Rest/binary>>, Count) when N >= 1, N =< 75 ->
    case Rest of
        <<_:N/binary, Rest2/binary>> ->
            count_legacy_sigops(Rest2, Count);
        _ -> Count  %% truncated script
    end;
%% OP_PUSHDATA1
count_legacy_sigops(<<16#4c:8, Len:8, Rest/binary>>, Count) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> ->
            count_legacy_sigops(Rest2, Count);
        _ -> Count
    end;
%% OP_PUSHDATA2
count_legacy_sigops(<<16#4d:8, Len:16/little, Rest/binary>>, Count) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> ->
            count_legacy_sigops(Rest2, Count);
        _ -> Count
    end;
%% OP_PUSHDATA4
count_legacy_sigops(<<16#4e:8, Len:32/little, Rest/binary>>, Count) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> ->
            count_legacy_sigops(Rest2, Count);
        _ -> Count
    end;
%% OP_CHECKSIG, OP_CHECKSIGVERIFY
count_legacy_sigops(<<16#ac:8, Rest/binary>>, Count) ->
    count_legacy_sigops(Rest, Count + 1);
count_legacy_sigops(<<16#ad:8, Rest/binary>>, Count) ->
    count_legacy_sigops(Rest, Count + 1);
%% OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY: use max (20) in legacy counting
count_legacy_sigops(<<16#ae:8, Rest/binary>>, Count) ->
    count_legacy_sigops(Rest, Count + ?MAX_PUBKEYS_PER_MULTISIG);
count_legacy_sigops(<<16#af:8, Rest/binary>>, Count) ->
    count_legacy_sigops(Rest, Count + ?MAX_PUBKEYS_PER_MULTISIG);
%% any other opcode
count_legacy_sigops(<<_:8, Rest/binary>>, Count) ->
    count_legacy_sigops(Rest, Count).

%% @doc Check for merkle tree malleation (CVE-2012-2459).
%% If the tx list has duplicate trailing entries, the merkle root
%% could be made identical with a different set of transactions.
check_merkle_malleation([]) -> ok;
check_merkle_malleation([_]) -> ok;
check_merkle_malleation(Hashes) ->
    %% Check if the last two hashes are equal at any odd-length level
    Last = lists:last(Hashes),
    SecondLast = lists:nth(length(Hashes) - 1, Hashes),
    case length(Hashes) rem 2 =:= 1 of
        false -> ok;
        true ->
            case Last =:= SecondLast of
                true -> throw(mutated_merkle);
                false -> ok
            end
    end.

%%% -------------------------------------------------------------------
%%% Sigops counting (context-dependent)
%%% -------------------------------------------------------------------

%% @doc Count P2SH sigops for a transaction.
%% For each P2SH input, deserializes the redeem script from scriptSig
%% and counts sigops in it.
-spec count_p2sh_sigops(#transaction{}, [#utxo{}]) -> non_neg_integer().
count_p2sh_sigops(#transaction{inputs = Inputs}, InputCoins) ->
    lists:foldl(fun({Input, Coin}, Acc) ->
        case is_p2sh_script(Coin#utxo.script_pubkey) of
            true ->
                %% get the redeem script (last push in scriptSig)
                case get_last_push(Input#tx_in.script_sig) of
                    {ok, RedeemScript} ->
                        Acc + count_legacy_sigops(RedeemScript, 0);
                    error ->
                        Acc
                end;
            false ->
                Acc
        end
    end, 0, lists:zip(Inputs, InputCoins)).

%% @doc Count witness sigops for a transaction.
%% P2WPKH: 1 sigop
%% P2WSH: count sigops in the witness script
%% P2SH-wrapped witness: check the redeem script for witness program
-spec count_witness_sigops(#transaction{}, [#utxo{}]) -> non_neg_integer().
count_witness_sigops(#transaction{inputs = Inputs}, InputCoins) ->
    lists:foldl(fun({Input, Coin}, Acc) ->
        ScriptPubKey = Coin#utxo.script_pubkey,
        Witness = Input#tx_in.witness,
        case classify_witness_program(ScriptPubKey) of
            {ok, Version, Program} ->
                Acc + witness_sigops_for_program(Version, Program, Witness);
            not_witness ->
                %% check for P2SH-wrapped witness
                case is_p2sh_script(ScriptPubKey) of
                    true ->
                        case get_last_push(Input#tx_in.script_sig) of
                            {ok, RedeemScript} ->
                                case classify_witness_program(RedeemScript) of
                                    {ok, V, P} ->
                                        Acc + witness_sigops_for_program(V, P, Witness);
                                    not_witness ->
                                        Acc
                                end;
                            error ->
                                Acc
                        end;
                    false ->
                        Acc
                end
        end
    end, 0, lists:zip(Inputs, InputCoins)).

%% @doc Get total sigop cost for a transaction.
%% Cost = legacy_sigops * WITNESS_SCALE_FACTOR + witness_sigops
-spec get_tx_sigop_cost(#transaction{}, [#utxo{}], non_neg_integer()) ->
    non_neg_integer().
get_tx_sigop_cost(Tx, InputCoins, Flags) ->
    LegacySigops = count_legacy_sigops_tx(Tx),
    P2shSigops = case (Flags band ?SCRIPT_VERIFY_P2SH) =/= 0 of
        true -> count_p2sh_sigops(Tx, InputCoins);
        false -> 0
    end,
    WitnessSigops = case (Flags band ?SCRIPT_VERIFY_WITNESS) =/= 0 of
        true -> count_witness_sigops(Tx, InputCoins);
        false -> 0
    end,
    (LegacySigops + P2shSigops) * ?WITNESS_SCALE_FACTOR + WitnessSigops.

%% Count sigops for a witness program
witness_sigops_for_program(0, Program, _Witness) when byte_size(Program) =:= 20 ->
    %% P2WPKH: 1 sigop
    1;
witness_sigops_for_program(0, Program, Witness) when byte_size(Program) =:= 32 ->
    %% P2WSH: count sigops in the witness script (last item)
    case Witness of
        [] -> 0;
        _ ->
            WitnessScript = lists:last(Witness),
            count_legacy_sigops(WitnessScript, 0)
    end;
witness_sigops_for_program(_Version, _Program, _Witness) ->
    %% unknown witness version: 0 sigops
    0.

%% Check if a scriptPubKey is P2SH: OP_HASH160 <20 bytes> OP_EQUAL
is_p2sh_script(<<16#a9, 16#14, _Hash:20/binary, 16#87>>) -> true;
is_p2sh_script(_) -> false.

%% Classify a script as a witness program.
%% Witness program: OP_n <2-40 bytes>
%% OP_0 = 0x00, OP_1..OP_16 = 0x51..0x60
classify_witness_program(<<0:8, Len:8, Program:Len/binary>>)
    when Len >= 2, Len =< 40 ->
    {ok, 0, Program};
classify_witness_program(<<OpN:8, Len:8, Program:Len/binary>>)
    when OpN >= 16#51, OpN =< 16#60, Len >= 2, Len =< 40 ->
    {ok, OpN - 16#50, Program};
classify_witness_program(_) ->
    not_witness.

%% Get the last data push from a script (used to extract P2SH redeem script)
get_last_push(Script) ->
    get_last_push(Script, error).

get_last_push(<<>>, Last) -> Last;
%% direct push: 1-75 bytes
get_last_push(<<N:8, Rest/binary>>, _Last) when N >= 1, N =< 75 ->
    case Rest of
        <<Data:N/binary, Rest2/binary>> ->
            get_last_push(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_PUSHDATA1
get_last_push(<<16#4c:8, Len:8, Rest/binary>>, _Last) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            get_last_push(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_PUSHDATA2
get_last_push(<<16#4d:8, Len:16/little, Rest/binary>>, _Last) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            get_last_push(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_PUSHDATA4
get_last_push(<<16#4e:8, Len:32/little, Rest/binary>>, _Last) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            get_last_push(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_0: pushes empty
get_last_push(<<16#00:8, Rest/binary>>, _Last) ->
    get_last_push(Rest, {ok, <<>>});
%% OP_1NEGATE .. OP_16: small number pushes
get_last_push(<<16#4f:8, Rest/binary>>, _Last) ->
    get_last_push(Rest, {ok, <<16#81>>});
get_last_push(<<OpN:8, Rest/binary>>, _Last) when OpN >= 16#51, OpN =< 16#60 ->
    get_last_push(Rest, {ok, <<(OpN - 16#50):8>>});
%% any other opcode: not a push, reset
get_last_push(<<_:8, Rest/binary>>, Last) ->
    get_last_push(Rest, Last).
