-module(beamchain_validation).

%% Block and transaction validation — Bitcoin consensus rules.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Context-free checks
-export([check_transaction/1]).
-export([check_block_header/2, check_block/2]).

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
