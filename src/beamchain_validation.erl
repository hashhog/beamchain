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

%% Connect / disconnect
-export([connect_block/4, disconnect_block/3]).

%% Sigops counting
-export([count_legacy_sigops/1]).
-export([count_p2sh_sigops/2, count_witness_sigops/2]).
-export([get_tx_sigop_cost/3]).

%% Utility
-export([is_coinbase_tx/1]).

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
contextual_check_block_header(_Header, #{height := -1}, _Params) ->
    %% Genesis block has no previous context to validate against
    ok;
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

%% Calculate minimum bytes needed to encode a height in CScriptNum encoding.
%% Script numbers use the MSB as a sign bit. If the high bit of the MSByte
%% would be set, an extra 0x00 byte is needed to keep the number positive.
height_byte_len(N) when N =< 16#7f -> 1;
height_byte_len(N) when N =< 16#7fff -> 2;
height_byte_len(N) when N =< 16#7fffff -> 3;
height_byte_len(N) when N =< 16#7fffffff -> 4;
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
%% At each level of the merkle tree, if the count is odd and the last
%% two entries are equal, the tree can be mutated.
check_merkle_malleation([]) -> ok;
check_merkle_malleation([_]) -> ok;
check_merkle_malleation(Hashes) ->
    check_merkle_malleation_level(Hashes).

check_merkle_malleation_level([_]) -> ok;
check_merkle_malleation_level([]) -> ok;
check_merkle_malleation_level(Hashes) ->
    Len = length(Hashes),
    case Len rem 2 =:= 1 andalso Len >= 2 of
        true ->
            Last = lists:last(Hashes),
            SecondLast = lists:nth(Len - 1, Hashes),
            case Last =:= SecondLast of
                true -> throw(mutated_merkle);
                false -> ok
            end;
        false -> ok
    end,
    %% check next level up
    NextLevel = merkle_pairs_check(Hashes),
    check_merkle_malleation_level(NextLevel).

merkle_pairs_check([]) -> [];
merkle_pairs_check([A]) ->
    [beamchain_serialize:hash256(<<A/binary, A/binary>>)];
merkle_pairs_check([A, B | Rest]) ->
    [beamchain_serialize:hash256(<<A/binary, B/binary>>) | merkle_pairs_check(Rest)].

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

%%% -------------------------------------------------------------------
%%% Connect block (full consensus validation + UTXO update)
%%% -------------------------------------------------------------------

%% @doc Connect a block to the chain: full validation + UTXO set update.
%% This is the main consensus enforcement function.
-spec connect_block(#block{}, non_neg_integer(), map(), map()) ->
    ok | {error, atom()}.
connect_block(#block{header = Header, transactions = Txs} = Block,
              Height, PrevIndex, Params) ->
    try
        %% 1. contextual header checks
        case contextual_check_block_header(Header, PrevIndex, Params) of
            ok -> ok;
            {error, E1} -> throw(E1)
        end,

        %% 2. contextual block checks (BIP 34, witness commitment)
        case contextual_check_block(Block, Height, PrevIndex, Params) of
            ok -> ok;
            {error, E2} -> throw(E2)
        end,

        %% 3. BIP 30: no duplicate txids in UTXO set
        Bip30Exceptions = maps:get(bip30_exceptions, Params, []),
        case lists:member(Height, Bip30Exceptions) of
            false ->
                lists:foreach(fun(Tx) ->
                    Txid = beamchain_serialize:tx_hash(Tx),
                    NumOutputs = length(Tx#transaction.outputs),
                    check_no_existing_outputs(Txid, NumOutputs)
                end, Txs);
            true ->
                ok  %% skip BIP 30 for exception heights
        end,

        %% get script flags for this height
        Network = maps:get(network, Params, mainnet),
        Flags = beamchain_script:flags_for_height(Height, Network),

        %% get assume_valid hash (convert from display to internal byte order)
        AssumeValidDisplay = maps:get(assume_valid, Params, <<0:256>>),
        AssumeValid = case AssumeValidDisplay of
            <<0:256>> -> <<0:256>>;
            _ -> beamchain_serialize:reverse_bytes(AssumeValidDisplay)
        end,
        BlockHash = beamchain_serialize:block_hash(Header),
        %% Skip script verification for all blocks up to the assume_valid block.
        %% Cache the assume_valid height in process dictionary to avoid
        %% repeated DB lookups.
        SkipScripts = case AssumeValid of
            <<0:256>> -> false;
            _ ->
                AVHeight = case get(assume_valid_height) of
                    undefined ->
                        H = case beamchain_db:get_block_index_by_hash(AssumeValid) of
                            {ok, #{height := HH}} -> HH;
                            not_found -> -1
                        end,
                        put(assume_valid_height, H),
                        H;
                    Cached -> Cached
                end,
                Height =< AVHeight
        end,

        %% 4. validate each transaction (sequential: UTXO checks)
        %% Script verification is deferred and run in parallel below.
        [CoinbaseTx | _RegularTxs] = Txs,
        {TotalFees, AllUndoData, TotalSigopCost, ScriptJobs} = lists:foldl(
            fun(Tx, {FeesAcc, UndoAcc, SigopsAcc, JobsAcc}) ->
                IsCoinbase = is_coinbase_tx(Tx),
                case IsCoinbase of
                    true ->
                        %% coinbase: no inputs to validate
                        {FeesAcc, UndoAcc, SigopsAcc, JobsAcc};
                    false ->
                        %% a. verify all inputs exist in UTXO set
                        InputCoins = fetch_input_coins(Tx),

                        %% b. verify total input value >= total output value
                        TotalIn = lists:foldl(fun(C, A) ->
                            A + C#utxo.value
                        end, 0, InputCoins),
                        TotalOut = lists:foldl(fun(#tx_out{value = V}, A) ->
                            A + V
                        end, 0, Tx#transaction.outputs),

                        %% c. verify amounts
                        TotalIn >= 0 orelse throw(negative_input),
                        TotalIn =< ?MAX_MONEY orelse throw(input_overflow),
                        TotalIn >= TotalOut orelse throw(insufficient_input),

                        %% d. check coinbase maturity
                        check_coinbase_maturity(InputCoins, Height),

                        %% e. BIP 68 relative locktime
                        case Tx#transaction.version >= 2 of
                            true ->
                                check_sequence_locks(Tx, InputCoins,
                                                     Height, PrevIndex);
                            false -> ok
                        end,

                        %% f. count sigops
                        TxSigopCost = get_tx_sigop_cost(Tx, InputCoins, Flags),
                        NewSigops = SigopsAcc + TxSigopCost,
                        NewSigops =< ?MAX_BLOCK_SIGOPS_COST
                            orelse throw(bad_blk_sigops),

                        %% g. collect script verification job (deferred)
                        NewJobs = case SkipScripts of
                            true -> JobsAcc;
                            false -> [{Tx, InputCoins} | JobsAcc]
                        end,

                        Fee = TotalIn - TotalOut,
                        SpentCoins = lists:zip(
                            [#outpoint{hash = H, index = I} ||
                             #tx_in{prev_out = #outpoint{hash = H, index = I}}
                             <- Tx#transaction.inputs],
                            InputCoins),

                        %% Apply UTXO changes immediately so subsequent
                        %% transactions in this block can spend these outputs.
                        %% Spend inputs
                        lists:foreach(fun(#tx_in{prev_out = #outpoint{hash = HH, index = II}}) ->
                            beamchain_chainstate:spend_utxo(HH, II)
                        end, Tx#transaction.inputs),
                        %% Create outputs
                        Txid2 = beamchain_serialize:tx_hash(Tx),
                        lists:foldl(fun(#tx_out{value = V2, script_pubkey = SPK2}, Idx) ->
                            Utxo = #utxo{
                                value = V2,
                                script_pubkey = SPK2,
                                is_coinbase = false,
                                height = Height
                            },
                            beamchain_chainstate:add_utxo(Txid2, Idx, Utxo),
                            Idx + 1
                        end, 0, Tx#transaction.outputs),

                        {FeesAcc + Fee, UndoAcc ++ SpentCoins, NewSigops,
                         NewJobs}
                end
            end,
            {0, [], 0, []},
            Txs),

        %% 4b. verify scripts in parallel (one process per tx)
        %% Save undo info in process dictionary so we can roll back on failure.
        %% AllUndoData has the spent coins; Txs has the added outputs.
        put(connect_block_undo, {Txs, AllUndoData}),

        case ScriptJobs of
            [] -> ok;
            _ -> verify_scripts_parallel(ScriptJobs, Flags)
        end,

        erase(connect_block_undo),

        %% Also count coinbase legacy sigops in the total
        CbSigops = count_legacy_sigops_tx(CoinbaseTx) * ?WITNESS_SCALE_FACTOR,
        (TotalSigopCost + CbSigops) =< ?MAX_BLOCK_SIGOPS_COST
            orelse throw(bad_blk_sigops),

        %% 5. verify block subsidy
        Subsidy = beamchain_chain_params:block_subsidy(Height, Network),
        CbValue = lists:foldl(fun(#tx_out{value = V}, A) -> A + V end,
                              0, CoinbaseTx#transaction.outputs),
        CbValue =< Subsidy + TotalFees orelse throw(bad_cb_amount),

        %% 6. add coinbase outputs to UTXO set
        CbTxid = beamchain_serialize:tx_hash(CoinbaseTx),
        lists:foldl(fun(#tx_out{value = V, script_pubkey = SPK}, Idx) ->
            Utxo = #utxo{
                value = V,
                script_pubkey = SPK,
                is_coinbase = true,
                height = Height
            },
            beamchain_chainstate:add_utxo(CbTxid, Idx, Utxo),
            Idx + 1
        end, 0, CoinbaseTx#transaction.outputs),

        %% 7. store undo data
        UndoBin = encode_undo_data(AllUndoData),
        beamchain_db:store_undo(BlockHash, UndoBin),

        %% Chain tip is updated in ETS by chainstate:do_connect_block.
        %% The RocksDB chain_tip is written during flush (atomically with
        %% UTXO changes) to avoid tip/UTXO mismatch on crash.

        ok
    catch
        throw:Reason ->
            %% Roll back UTXO changes from the failed block
            case erase(connect_block_undo) of
                {UndoTxs, UndoCoins} ->
                    rollback_block_utxos(UndoTxs, UndoCoins);
                _ -> ok
            end,
            {error, Reason};
        error:Reason2:_Stack ->
            case erase(connect_block_undo) of
                {UndoTxs2, UndoCoins2} ->
                    rollback_block_utxos(UndoTxs2, UndoCoins2);
                _ -> ok
            end,
            {error, {internal_error, Reason2}}
    end.

%% Roll back UTXO changes from a failed block validation.
%% Removes outputs added by non-coinbase txs and restores spent inputs.
rollback_block_utxos(Txs, UndoCoins) ->
    %% Collect txids of transactions in this block (for intra-block filtering)
    BlockTxids = sets:from_list(
        [beamchain_serialize:tx_hash(Tx) || Tx <- Txs]),
    %% Remove outputs added by ALL txs including coinbase
    lists:foreach(fun(Tx) ->
        Txid = beamchain_serialize:tx_hash(Tx),
        NumOutputs = length(Tx#transaction.outputs),
        lists:foreach(fun(Idx) ->
            beamchain_chainstate:spend_utxo(Txid, Idx)
        end, lists:seq(0, NumOutputs - 1))
    end, Txs),
    %% Restore spent inputs from undo data, but skip coins that were
    %% created within this same block (intra-block spends). Those
    %% outputs were already removed above and shouldn't be restored.
    lists:foreach(fun({#outpoint{hash = H, index = I}, Coin}) ->
        case sets:is_element(H, BlockTxids) of
            true -> ok;  %% intra-block coin, don't restore
            false -> beamchain_chainstate:add_utxo(H, I, Coin)
        end
    end, UndoCoins),
    ok.

%% @doc Fetch UTXO coins for all inputs of a transaction.
%% Uses the chainstate ETS cache with RocksDB fallback.
fetch_input_coins(#transaction{inputs = Inputs}) ->
    lists:map(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
        case beamchain_chainstate:get_utxo(H, I) of
            {ok, Coin} -> Coin;
            not_found ->
                logger:error("missing_inputs: txid=~s vout=~B",
                             [binary:encode_hex(beamchain_serialize:reverse_bytes(H)), I]),
                throw(missing_inputs)
        end
    end, Inputs).

%% @doc Check BIP 30: no existing unspent outputs for this txid.
check_no_existing_outputs(Txid, NumOutputs) ->
    lists:foreach(fun(Idx) ->
        case beamchain_chainstate:has_utxo(Txid, Idx) of
            true -> throw(duplicate_txid);
            false -> ok
        end
    end, lists:seq(0, NumOutputs - 1)).

%% @doc Check coinbase maturity: inputs spending coinbase outputs must
%% have at least COINBASE_MATURITY confirmations.
check_coinbase_maturity(InputCoins, Height) ->
    lists:foreach(fun(Coin) ->
        case Coin#utxo.is_coinbase of
            true ->
                Confirmations = Height - Coin#utxo.height,
                Confirmations >= ?COINBASE_MATURITY
                    orelse throw(premature_spend_of_coinbase);
            false -> ok
        end
    end, InputCoins).

%% @doc Check BIP 68 sequence locks.
%% For tx version >= 2, verify relative timelocks are satisfied.
check_sequence_locks(#transaction{inputs = Inputs}, InputCoins,
                     Height, PrevIndex) ->
    MTP = median_time_past(PrevIndex),
    lists:foreach(fun({Input, Coin}) ->
        Seq = Input#tx_in.sequence,
        %% if disable flag is set, skip
        case (Seq band ?SEQUENCE_LOCKTIME_DISABLE_FLAG) =/= 0 of
            true -> ok;
            false ->
                Masked = Seq band ?SEQUENCE_LOCKTIME_MASK,
                case (Seq band ?SEQUENCE_LOCKTIME_TYPE_FLAG) =/= 0 of
                    false ->
                        %% height-based: input must have Masked confirmations
                        MinHeight = Coin#utxo.height + Masked,
                        Height >= MinHeight
                            orelse throw(sequence_lock_not_met);
                    true ->
                        %% time-based: check against MTP
                        %% BIP 68: MTP(spending block - 1) - MTP(coin block - 1) >= masked * 512
                        CoinMTPIndex = case beamchain_db:get_block_index(
                                Coin#utxo.height - 1) of
                            {ok, CI} -> CI;
                            not_found -> throw(missing_block_index)
                        end,
                        CoinMTP = median_time_past(CoinMTPIndex),
                        MinTime = CoinMTP + (Masked bsl ?SEQUENCE_LOCKTIME_GRANULARITY),
                        MTP >= MinTime
                            orelse throw(sequence_lock_not_met)
                end
        end
    end, lists:zip(Inputs, InputCoins)).

%% @doc Verify scripts for all inputs of a transaction.
verify_tx_scripts(Tx, InputCoins, _Height, Flags) ->
    Inputs = Tx#transaction.inputs,
    %% Build prevouts list for taproot sighash (all inputs' amount + scriptPubKey)
    AllPrevOuts = [{C#utxo.value, C#utxo.script_pubkey} || C <- InputCoins],
    lists:foldl(fun({Input, Coin}, Idx) ->
        ScriptSig = Input#tx_in.script_sig,
        ScriptPubKey = Coin#utxo.script_pubkey,
        Witness = Input#tx_in.witness,
        Amount = Coin#utxo.value,
        SigChecker = {Tx, Idx, Amount, AllPrevOuts},
        case beamchain_script:verify_script(
                ScriptSig, ScriptPubKey, Witness, Flags, SigChecker) of
            true -> ok;
            false ->
                Txid = beamchain_serialize:tx_hash(Tx),
                ScriptType = classify_script(ScriptPubKey),
                logger:error("script_verify_failed: txid=~s input=~B type=~s "
                             "scriptPubKey=~s scriptSig=~s witness_items=~B",
                             [binary:encode_hex(Txid), Idx, ScriptType,
                              binary:encode_hex(ScriptPubKey),
                              binary:encode_hex(ScriptSig),
                              length(Witness)]),
                throw({script_verify_failed, Idx})
        end,
        Idx + 1
    end, 0, lists:zip(Inputs, InputCoins)),
    ok.

%% Classify a scriptPubKey for diagnostic logging.
classify_script(<<16#76, 16#a9, 16#14, _:20/binary, 16#88, 16#ac>>) -> <<"p2pkh">>;
classify_script(<<16#a9, 16#14, _:20/binary, 16#87>>) -> <<"p2sh">>;
classify_script(<<16#00, 16#14, _:20/binary>>) -> <<"p2wpkh">>;
classify_script(<<16#00, 16#20, _:32/binary>>) -> <<"p2wsh">>;
classify_script(<<16#51, 16#20, _:32/binary>>) -> <<"p2tr">>;
classify_script(_) -> <<"other">>.

%% @doc Verify scripts for multiple transactions in parallel.
%% Spawns one process per transaction. Each process verifies all inputs.
%% If any verification fails, throws the error.
verify_scripts_parallel(Jobs, Flags) ->
    %% Spawn a worker per transaction.
    %% Wrap in try/catch so that throw exits with the reason directly
    %% (otherwise throw becomes {nocatch, Reason} which breaks pattern matching).
    Workers = lists:map(fun({Tx, InputCoins}) ->
        spawn_monitor(fun() ->
            try
                verify_tx_scripts(Tx, InputCoins, 0, Flags)
            catch
                throw:Reason -> exit(Reason)
            end
        end)
    end, Jobs),
    %% Collect results — all workers must complete normally
    collect_script_results(Workers).

collect_script_results([]) ->
    ok;
collect_script_results([{Pid, Ref} | Rest]) ->
    receive
        {'DOWN', Ref, process, Pid, normal} ->
            collect_script_results(Rest);
        {'DOWN', Ref, process, Pid, {script_verify_failed, _} = Reason} ->
            %% Kill remaining workers
            kill_remaining(Rest),
            throw(Reason);
        {'DOWN', Ref, process, Pid, Reason} ->
            kill_remaining(Rest),
            throw({script_verify_failed, Reason})
    end.

kill_remaining([]) -> ok;
kill_remaining([{Pid, Ref} | Rest]) ->
    erlang:demonitor(Ref, [flush]),
    exit(Pid, kill),
    kill_remaining(Rest).

%% @doc Encode undo data (list of {outpoint, utxo} pairs) to binary.
encode_undo_data(SpentCoins) ->
    Count = length(SpentCoins),
    Entries = lists:map(fun({#outpoint{hash = H, index = I}, Coin}) ->
        CbFlag = case Coin#utxo.is_coinbase of true -> 1; false -> 0 end,
        SPK = Coin#utxo.script_pubkey,
        SPKLen = byte_size(SPK),
        <<H:32/binary, I:32/little,
          (Coin#utxo.value):64/little,
          (Coin#utxo.height):32/little,
          CbFlag:8,
          SPKLen:32/little, SPK/binary>>
    end, SpentCoins),
    <<Count:32/little, (list_to_binary(Entries))/binary>>.

%% @doc Decode undo data back to list of {outpoint, utxo} pairs.
decode_undo_data(<<Count:32/little, Rest/binary>>) ->
    decode_undo_entries(Count, Rest, []).

decode_undo_entries(0, <<>>, Acc) ->
    lists:reverse(Acc);
decode_undo_entries(N, <<H:32/binary, I:32/little,
                         Value:64/little, CoinHeight:32/little,
                         CbFlag:8,
                         SPKLen:32/little, SPK:SPKLen/binary,
                         Rest/binary>>, Acc) ->
    Outpoint = #outpoint{hash = H, index = I},
    Coin = #utxo{
        value = Value,
        script_pubkey = SPK,
        is_coinbase = CbFlag =:= 1,
        height = CoinHeight
    },
    decode_undo_entries(N - 1, Rest, [{Outpoint, Coin} | Acc]).

%%% -------------------------------------------------------------------
%%% Disconnect block (reverse a connected block for reorgs)
%%% -------------------------------------------------------------------

%% @doc Disconnect a block, reversing its effects on the UTXO set.
%% Uses stored undo data to restore spent outputs.
-spec disconnect_block(#block{}, non_neg_integer(), map()) ->
    ok | {error, atom()}.
disconnect_block(#block{header = Header, transactions = Txs},
                 Height, _Params) ->
    try
        BlockHash = beamchain_serialize:block_hash(Header),

        %% 1. load undo data
        UndoData = case beamchain_db:get_undo(BlockHash) of
            {ok, UndoBin} -> decode_undo_data(UndoBin);
            not_found -> throw(missing_undo_data)
        end,

        %% 2. process transactions in reverse order
        RevTxs = lists:reverse(Txs),
        lists:foldl(fun(Tx, RemainingUndo) ->
            Txid = beamchain_serialize:tx_hash(Tx),

            %% 2a. remove created outputs from UTXO set
            NumOutputs = length(Tx#transaction.outputs),
            lists:foreach(fun(Idx) ->
                beamchain_chainstate:spend_utxo(Txid, Idx)
            end, lists:seq(0, NumOutputs - 1)),

            %% 2b. restore spent inputs from undo data
            case is_coinbase_tx(Tx) of
                true ->
                    %% coinbase has no inputs to restore
                    RemainingUndo;
                false ->
                    NumInputs = length(Tx#transaction.inputs),
                    %% take NumInputs entries from the end of undo data
                    %% (since we're processing in reverse)
                    {ToRestore, Rest} = split_last_n(RemainingUndo, NumInputs),
                    lists:foreach(fun({#outpoint{hash = H, index = I}, Coin}) ->
                        beamchain_chainstate:add_utxo(H, I, Coin)
                    end, ToRestore),
                    Rest
            end
        end, UndoData, RevTxs),

        %% 3. update chain tip to previous block
        PrevHash = Header#block_header.prev_hash,
        PrevHeight = Height - 1,
        beamchain_db:set_chain_tip(PrevHash, PrevHeight),

        %% 4. delete undo data
        %% (we keep it for now; could add a delete_undo function later)

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%% Split a list, taking the last N elements.
%% Returns {LastN, Rest} where Rest ++ LastN = List.
split_last_n(List, N) ->
    Len = length(List),
    {lists:sublist(List, Len - N), lists:nthtail(Len - N, List)}.
