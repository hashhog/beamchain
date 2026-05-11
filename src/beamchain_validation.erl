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
-export([count_legacy_sigops/1, count_sigops_accurate/1]).
-export([count_p2sh_sigops/2, count_witness_sigops/2]).
-export([get_tx_sigop_cost/3]).

%% Utility
-export([is_coinbase_tx/1]).

%% Coinbase maturity (exported for testing)
-export([check_coinbase_maturity/2]).

%% BIP 68 sequence locks
-export([calculate_sequence_lock_pair/3]).

%% IsFinalTx (exported for testing)
-export([is_final_tx/3]).

%% Undo data serialization (exported for testing)
-export([encode_undo_data/1, decode_undo_data/1]).

%% Checkpoint enforcement
-export([check_against_checkpoint/3]).

%% BIP-34 height encoder and consensus check (exported for testing)
-export([encode_bip34_height/1, check_coinbase_height/2]).

%% Assumevalid ancestor check (exported for testing)
-export([skip_scripts/3, skip_scripts_eval/6]).

%% UTXO rollback (used by chainstate terminate for crash recovery)
-export([rollback_block_utxos/2]).

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

        %% 5b. Explicit duplicate-txid pre-check (Core BIP-22 parity).
        %% Iterate non-coinbase transactions and accumulate txids into a set.
        %% If any non-coinbase txid appears more than once, reject with
        %% dup_txid before the merkle root check fires.  This ensures the
        %% BIP-22 reason string maps to "bad-txns-inputs-missingorspent"
        %% (matching Bitcoin Core's ConnectBlock path) rather than the
        %% implementation-specific "bad-txnmrklroot" we would otherwise
        %% emit.  Note: coinbase uniqueness is enforced by BIP-34 / height
        %% commitment, not here.
        NonCbTxids = [beamchain_serialize:tx_hash(Tx) || Tx <- RestTxs],
        check_no_dup_txids(NonCbTxids),

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
%% When PrevIndex contains a cached mtp_timestamps list (injected by
%% chainstate during connect_block), we use it directly instead of
%% walking the DB for 11 block index lookups per block.
-spec median_time_past(map()) -> non_neg_integer().
median_time_past(#{mtp_timestamps := Ts}) when is_list(Ts), Ts =/= [] ->
    Sorted = lists:sort(Ts),
    lists:nth((length(Sorted) div 2) + 1, Sorted);
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

%% @doc Check whether a transaction is final at a given block height and time.
%% A transaction is final if:
%%   1. nLockTime == 0, OR
%%   2. nLockTime < threshold (height-based if < 500_000_000, else time-based), OR
%%   3. All inputs have sequence == 0xFFFFFFFF
%%
%% Reference: Bitcoin Core consensus/tx_verify.cpp IsFinalTx()
%% Called from ContextualCheckBlock (validation.cpp:4146)
%% LOCKTIME_THRESHOLD (500_000_000) is defined in beamchain_protocol.hrl
-spec is_final_tx(#transaction{}, non_neg_integer(), non_neg_integer()) -> boolean().
is_final_tx(#transaction{locktime = 0}, _Height, _BlockTime) ->
    true;
is_final_tx(#transaction{locktime = LockTime, inputs = Inputs}, Height, BlockTime) ->
    %% Determine threshold: height-based or time-based
    Threshold = if LockTime < ?LOCKTIME_THRESHOLD -> Height; true -> BlockTime end,
    if
        LockTime < Threshold ->
            true;
        true ->
            %% Still final if all inputs have SEQUENCE_FINAL (0xFFFFFFFF)
            lists:all(fun(#tx_in{sequence = Seq}) -> Seq =:= 16#FFFFFFFF end, Inputs)
    end.

%% @doc Validate a block with chain context.
%% Checks BIP 34 coinbase height, IsFinalTx for all txs, witness commitment.
-spec contextual_check_block(#block{}, non_neg_integer(), map(), map()) ->
    ok | {error, atom()}.
contextual_check_block(#block{header = Header, transactions = Txs},
                       Height, PrevIndex, Params) ->
    try
        [CoinbaseTx | _] = Txs,

        %% 1. BIP 34: coinbase must contain block height
        Bip34Height = maps:get(bip34_height, Params, 0),
        case Height >= Bip34Height of
            true ->
                check_coinbase_height(CoinbaseTx, Height);
            false -> ok
        end,

        %% 2. IsFinalTx: every transaction must be final (Core validation.cpp:4146).
        %% lock_time_cutoff = MTP when BIP-113/CSV is active, block timestamp otherwise.
        %% BIP-113 (MEDIAN_TIME_PAST) gates on csv_height (419328 mainnet).
        CsvHeight = maps:get(csv_height, Params, 419328),
        LockTimeCutoff = case Height >= CsvHeight of
            true  -> median_time_past(PrevIndex);
            false -> Header#block_header.timestamp
        end,
        lists:foreach(fun(Tx) ->
            is_final_tx(Tx, Height, LockTimeCutoff)
                orelse throw(bad_txns_nonfinal)
        end, Txs),

        %% 3. Coinbase scriptSig length must be 2..100 bytes (context-free,
        %%    but placed here so it fires on the connect_block path which
        %%    does NOT call check_block).
        %%    Bitcoin Core consensus/tx_check.cpp:49.
        [#tx_in{script_sig = CbSig} | _] = CoinbaseTx#transaction.inputs,
        CbSigLen = byte_size(CbSig),
        (CbSigLen >= 2 andalso CbSigLen =< 100)
            orelse throw(bad_coinbase_length),

        %% 4. BIP 141: witness commitment in coinbase.
        %% Bitcoin Core CheckWitnessMalleation (validation.cpp:3870-3901) validates
        %% the commitment whenever a commitment OP_RETURN is PRESENT in the coinbase,
        %% regardless of whether non-coinbase transactions carry witness data.
        %% The previous guard (HasWitnessTx on tl(Txs)) was wrong — it skipped
        %% the recomputation when the commitment existed but no non-coinbase tx
        %% had witness data, allowing a crafted wrong commitment to pass.
        SegwitHeight = maps:get(segwit_height, Params, 0),
        case Height >= SegwitHeight of
            true ->
                %% Check if commitment output is present in coinbase
                WitnessCommitmentPrefix = <<16#6a, 16#24, 16#aa, 16#21, 16#a9, 16#ed>>,
                HasCommitmentOutput = lists:any(
                    fun(#tx_out{script_pubkey = SPK}) ->
                        byte_size(SPK) >= 38 andalso
                        binary:part(SPK, 0, 6) =:= WitnessCommitmentPrefix
                    end, CoinbaseTx#transaction.outputs),
                case HasCommitmentOutput of
                    true ->
                        %% Commitment is present — always recompute and verify
                        %% (matches Core: commitpos != NO_WITNESS_COMMITMENT)
                        check_witness_commitment(CoinbaseTx, Txs);
                    false ->
                        %% No commitment output. Reject if any tx has witness data.
                        HasWitnessTx = lists:any(fun has_witness/1, Txs),
                        case HasWitnessTx of
                            true -> throw(missing_witness_commitment);
                            false -> ok
                        end
                end;
            false -> ok
        end,

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%% @doc Check BIP 34: coinbase scriptSig must start with the byte-exact
%% canonical encoding of Height, matching Bitcoin Core's ContextualCheckBlock
%% (validation.cpp:4151-4159):
%%
%%   CScript expect = CScript() << nHeight;
%%   sig.size() >= expect.size() && equal(expect, sig[:expect.size()])
%%
%% Canonical encoding per script.h:433-448:
%%   0       → <<0x00>>              (OP_0, single byte)
%%   1..16   → <<0x50 + Height>>     (OP_1..OP_16, single byte)
%%   17+     → <<Len, LE-bytes...>>  (length-prefixed sign-magnitude CScriptNum)
%%
%% Non-canonical forms (length-prefixed 1..16, zero-padded, OP_PUSHDATA1
%% prefix, missing sign byte at 0x80/0x8000/0x800000) are rejected.
check_coinbase_height(#transaction{inputs = [#tx_in{script_sig = ScriptSig}]},
                      Height) ->
    Expect = encode_bip34_height(Height),
    ExpectLen = byte_size(Expect),
    case ScriptSig of
        <<Prefix:ExpectLen/binary, _/binary>> when Prefix =:= Expect ->
            ok;
        _ ->
            throw(bad_cb_height)
    end.

%% @doc Encode a block height as the canonical BIP-34 byte sequence.
%% Mirrors Bitcoin Core's CScript() << nHeight (script.h:433-448).
encode_bip34_height(0) ->
    <<16#00>>;  %% OP_0
encode_bip34_height(H) when H >= 1, H =< 16 ->
    <<(16#50 + H)>>;  %% OP_1..OP_16
encode_bip34_height(H) ->
    %% CScriptNum: minimal little-endian sign-magnitude with length prefix.
    LE = encode_le_magnitude(H),
    Len = byte_size(LE),
    <<Len:8, LE/binary>>.

%% Encode a positive integer as minimal little-endian bytes,
%% appending a zero sign byte if the MSB of the last byte is set.
encode_le_magnitude(H) ->
    Bytes = encode_le_bytes(H, <<>>),
    %% If the high bit of the last byte is set, we must append 0x00
    %% (the sign bit is the MSB of the last byte in CScriptNum).
    LastByte = binary:last(Bytes),
    case LastByte band 16#80 of
        0 -> Bytes;
        _ -> <<Bytes/binary, 0>>
    end.

%% Accumulate little-endian bytes for a positive integer.
encode_le_bytes(0, Acc) -> Acc;
encode_le_bytes(H, Acc) ->
    encode_le_bytes(H bsr 8, <<Acc/binary, (H band 16#ff)>>).

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
%%% Checkpoint enforcement
%%% -------------------------------------------------------------------

%% @doc Check if a block at the given height matches the checkpoint.
%% When connecting a block at a checkpoint height, the block hash must match.
%% Returns ok if the block passes or if there's no checkpoint at that height.
%% Returns {error, checkpoint_mismatch} if the hash doesn't match.
%% BlockHash is in internal byte order.
-spec check_against_checkpoint(non_neg_integer(), binary(), atom()) ->
    ok | {error, checkpoint_mismatch}.
check_against_checkpoint(Height, BlockHash, Network) ->
    case beamchain_chain_params:get_checkpoint(Height, Network) of
        none ->
            ok;
        ExpectedHashDisplay ->
            %% Checkpoint hashes are in display byte order; convert to internal
            ExpectedHash = beamchain_serialize:reverse_bytes(ExpectedHashDisplay),
            case BlockHash =:= ExpectedHash of
                true -> ok;
                false -> {error, checkpoint_mismatch}
            end
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
%% Delegates to beamchain_serialize:block_weight/1 which correctly
%% includes the varint-encoded transaction count (80-hdr*4 + varint*4 + sum-tx-weights).
%% Bitcoin Core: consensus/validation.h GetBlockWeight.
compute_block_weight(Txs) ->
    beamchain_serialize:block_weight(Txs).

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

%% @doc Count sigops in a script with accurate mode.
%% In accurate mode, OP_CHECKMULTISIG(VERIFY) counts as the actual number
%% of pubkeys (from preceding OP_N), not MAX_PUBKEYS_PER_MULTISIG (20).
%% This is used for P2SH redeem scripts and witness scripts.
%% Reference: Bitcoin Core script.cpp GetSigOpCount(fAccurate=true)
-spec count_sigops_accurate(binary()) -> non_neg_integer().
count_sigops_accurate(Script) ->
    count_sigops_accurate(Script, none, 0).

%% Internal: tracks last opcode to decode pubkey count for CHECKMULTISIG
count_sigops_accurate(<<>>, _LastOp, Count) -> Count;
%% data push: 1-75 bytes
count_sigops_accurate(<<N:8, Rest/binary>>, _LastOp, Count) when N >= 1, N =< 75 ->
    case Rest of
        <<_:N/binary, Rest2/binary>> ->
            count_sigops_accurate(Rest2, N, Count);
        _ -> Count  %% truncated script
    end;
%% OP_PUSHDATA1
count_sigops_accurate(<<16#4c:8, Len:8, Rest/binary>>, _LastOp, Count) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> ->
            count_sigops_accurate(Rest2, 16#4c, Count);
        _ -> Count
    end;
%% OP_PUSHDATA2
count_sigops_accurate(<<16#4d:8, Len:16/little, Rest/binary>>, _LastOp, Count) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> ->
            count_sigops_accurate(Rest2, 16#4d, Count);
        _ -> Count
    end;
%% OP_PUSHDATA4
count_sigops_accurate(<<16#4e:8, Len:32/little, Rest/binary>>, _LastOp, Count) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> ->
            count_sigops_accurate(Rest2, 16#4e, Count);
        _ -> Count
    end;
%% OP_CHECKSIG, OP_CHECKSIGVERIFY
count_sigops_accurate(<<16#ac:8, Rest/binary>>, _LastOp, Count) ->
    count_sigops_accurate(Rest, 16#ac, Count + 1);
count_sigops_accurate(<<16#ad:8, Rest/binary>>, _LastOp, Count) ->
    count_sigops_accurate(Rest, 16#ad, Count + 1);
%% OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY: decode pubkey count from LastOp
count_sigops_accurate(<<16#ae:8, Rest/binary>>, LastOp, Count) ->
    N = decode_op_n(LastOp),
    count_sigops_accurate(Rest, 16#ae, Count + N);
count_sigops_accurate(<<16#af:8, Rest/binary>>, LastOp, Count) ->
    N = decode_op_n(LastOp),
    count_sigops_accurate(Rest, 16#af, Count + N);
%% any other opcode
count_sigops_accurate(<<Op:8, Rest/binary>>, _LastOp, Count) ->
    count_sigops_accurate(Rest, Op, Count).

%% @doc Decode OP_N (OP_1 through OP_16) to integer.
%% Returns MAX_PUBKEYS_PER_MULTISIG (20) for invalid/non-number opcodes.
%% OP_0 (0x00) decodes to 0, OP_1..OP_16 (0x51..0x60) decode to 1..16.
%% Reference: Bitcoin Core script.h DecodeOP_N
-spec decode_op_n(integer() | none) -> non_neg_integer().
decode_op_n(16#00) -> 0;  %% OP_0
decode_op_n(Op) when Op >= 16#51, Op =< 16#60 -> Op - 16#50;  %% OP_1..OP_16
decode_op_n(_) -> ?MAX_PUBKEYS_PER_MULTISIG.  %% invalid: use max

%% @doc Check for merkle tree malleation (CVE-2012-2459).
%% At each level of the merkle tree, if the count is odd and the last
%% two entries are equal, the tree can be mutated.
%% check_no_dup_txids/1 — reject if any txid appears more than once.
%% Called before the merkle root check so that blocks with duplicate
%% non-coinbase txids emit "bad-txns-inputs-missingorspent" (Core BIP-22
%% canonical string) rather than "bad-txnmrklroot".
check_no_dup_txids(Txids) ->
    check_no_dup_txids(Txids, #{}).

check_no_dup_txids([], _Seen) -> ok;
check_no_dup_txids([Txid | Rest], Seen) ->
    case maps:is_key(Txid, Seen) of
        true  -> throw(dup_txid);
        false -> check_no_dup_txids(Rest, Seen#{Txid => true})
    end.

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
%% and counts sigops in it using accurate mode.
%% Reference: Bitcoin Core script.cpp GetSigOpCount(const CScript& scriptSig)
%%
%% Core iterates every opcode in scriptSig and returns 0 immediately if
%% any opcode > OP_16 (0x60) is encountered (i.e. not a push).  Only
%% push-only scriptSigs are valid for P2SH (BIP-16 consensus rule), so a
%% non-push opcode means the redeem script cannot be correctly identified
%% and sigops must be treated as 0 for that input, exactly as Core does.
-spec count_p2sh_sigops(#transaction{}, [#utxo{}]) -> non_neg_integer().
count_p2sh_sigops(#transaction{inputs = Inputs}, InputCoins) ->
    lists:foldl(fun({Input, Coin}, Acc) ->
        case is_p2sh_script(Coin#utxo.script_pubkey) of
            true ->
                %% Extract the redeem script (last data item pushed by scriptSig).
                %% Return 0 for this input if scriptSig contains any non-push opcode.
                %% Mirrors Core: if (opcode > OP_16) return 0; (script.cpp:197-198)
                case get_p2sh_redeem_script(Input#tx_in.script_sig) of
                    {ok, RedeemScript} ->
                        %% P2SH uses accurate sigop counting
                        Acc + count_sigops_accurate(RedeemScript);
                    not_pushonly ->
                        %% Core returns 0 for non-push-only scriptSig
                        Acc;
                    error ->
                        Acc
                end;
            false ->
                Acc
        end
    end, 0, lists:zip(Inputs, InputCoins)).

%% @doc Extract the redeem script (last data push) from a P2SH scriptSig.
%% Returns {ok, RedeemScript} on success, not_pushonly if any opcode > OP_16
%% (= 0x60) is encountered, or error if the script is malformed/truncated.
%%
%% Mirrors Bitcoin Core CScript::GetSigOpCount(const CScript& scriptSig):
%%   while (pc < end()) {
%%     if (!GetOp(pc, opcode, vData)) return 0;
%%     if (opcode > OP_16) return 0;      ← any non-push kills the count
%%   }
%%   return CScript(vData).GetSigOpCount(true);
%%
%% OP_16 = 0x60 in Core's opcode enum; so only opcodes > 0x60 trigger
%% early return 0.  Opcodes 0x00..0x60 are all either push opcodes or
%% small-number encodings that Core allows through.
get_p2sh_redeem_script(Script) ->
    get_p2sh_redeem_script(Script, error).

get_p2sh_redeem_script(<<>>, Last) -> Last;
%% OP_0 (0x00): pushes empty bytes
get_p2sh_redeem_script(<<16#00:8, Rest/binary>>, _Last) ->
    get_p2sh_redeem_script(Rest, {ok, <<>>});
%% direct push: 0x01..0x4b (1–75 bytes)
get_p2sh_redeem_script(<<N:8, Rest/binary>>, _Last) when N >= 1, N =< 16#4b ->
    case Rest of
        <<Data:N/binary, Rest2/binary>> ->
            get_p2sh_redeem_script(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_PUSHDATA1 (0x4c)
get_p2sh_redeem_script(<<16#4c:8, Len:8, Rest/binary>>, _Last) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            get_p2sh_redeem_script(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_PUSHDATA2 (0x4d)
get_p2sh_redeem_script(<<16#4d:8, Len:16/little, Rest/binary>>, _Last) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            get_p2sh_redeem_script(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_PUSHDATA4 (0x4e)
get_p2sh_redeem_script(<<16#4e:8, Len:32/little, Rest/binary>>, _Last) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            get_p2sh_redeem_script(Rest2, {ok, Data});
        _ -> error
    end;
%% OP_1NEGATE (0x4f): push -1 (sign-magnitude: <<0x81>>)
get_p2sh_redeem_script(<<16#4f:8, Rest/binary>>, _Last) ->
    get_p2sh_redeem_script(Rest, {ok, <<16#81>>});
%% OP_RESERVED (0x50): not a data push; Core's GetOp doesn't fill vData but
%% 0x50 ≤ OP_16 (0x60) so Core does NOT return 0 here.  vData retains its
%% previous value.  Mirror: keep Last unchanged.
get_p2sh_redeem_script(<<16#50:8, Rest/binary>>, Last) ->
    get_p2sh_redeem_script(Rest, Last);
%% OP_1..OP_16 (0x51..0x60): push small integers 1..16
get_p2sh_redeem_script(<<OpN:8, Rest/binary>>, _Last)
        when OpN >= 16#51, OpN =< 16#60 ->
    get_p2sh_redeem_script(Rest, {ok, <<(OpN - 16#50):8>>});
%% Any opcode > 0x60: Core returns 0 immediately.  Map to not_pushonly.
get_p2sh_redeem_script(<<Op:8, _Rest/binary>>, _Last) when Op > 16#60 ->
    not_pushonly.

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
%% Reference: Bitcoin Core interpreter.cpp WitnessSigOps
witness_sigops_for_program(0, Program, _Witness) when byte_size(Program) =:= 20 ->
    %% P2WPKH: 1 sigop
    1;
witness_sigops_for_program(0, Program, Witness) when byte_size(Program) =:= 32 ->
    %% P2WSH: count sigops in the witness script (last item) using accurate mode
    case Witness of
        [] -> 0;
        _ ->
            WitnessScript = lists:last(Witness),
            count_sigops_accurate(WitnessScript)
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
%% Special case for the genesis block, skipping connection of its
%% transactions (its coinbase is unspendable). Mirrors
%% bitcoin-core/src/validation.cpp:2337-2343:
%%
%%   // Special case for the genesis block, skipping connection of its
%%   // transactions (its coinbase is unspendable)
%%   if (block_hash == params.GetConsensus().hashGenesisBlock) {
%%       if (!fJustCheck) view.SetBestBlock(pindex->GetBlockHash());
%%       return true;
%%   }
%%
%% This both keeps Core-byte-identical UTXO snapshots (the genesis
%% coinbase output never enters the chainstate) and avoids running
%% header/coinbase/script checks against the bootstrap genesis block,
%% which has no parent and is treated as axiomatic by the network.
connect_block(_Block, 0, _PrevIndex, _Params) ->
    ok;
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
        %% Skip for known exception blocks (91842, 91880).
        %% Also skip after BIP34 activation — unique coinbase heights make
        %% duplicate txids impossible after height 227931. Bitcoin Core skips
        %% the check between BIP34 activation and height 1,983,702.
        Bip30Exceptions = maps:get(bip30_exceptions, Params, []),
        Bip34Height = maps:get(bip34_height, Params, 0),
        SkipBip30 = lists:member(Height, Bip30Exceptions)
                    orelse (Height > Bip34Height andalso Height < 1983702),
        case SkipBip30 of
            false ->
                lists:foreach(fun(Tx) ->
                    Txid = beamchain_serialize:tx_hash(Tx),
                    NumOutputs = length(Tx#transaction.outputs),
                    check_no_existing_outputs(Txid, NumOutputs)
                end, Txs);
            true ->
                ok
        end,

        %% get script flags for this height
        Network = maps:get(network, Params, mainnet),
        Flags = beamchain_script:flags_for_height(Height, Network),

        BlockHash = beamchain_serialize:block_hash(Header),

        %% 3b. Checkpoint enforcement: verify block hash matches checkpoint
        case check_against_checkpoint(Height, BlockHash, Network) of
            ok -> ok;
            {error, checkpoint_mismatch} -> throw(checkpoint_mismatch)
        end,

        %% Determine whether to skip script verification.
        %% Uses the real Bitcoin Core v28.0 assumevalid ancestor-check semantic:
        %% skip scripts iff the block is an ancestor of the configured
        %% assumed-valid block AND all six safety conditions hold.
        %% Non-script validation (PoW, merkle root, BIP30, coinbase) always runs.
        SkipScripts = skip_scripts(Height, BlockHash, Params),

        %% 4. validate each transaction (sequential: UTXO checks)
        %% Script verification is deferred and run in parallel below.
        %%
        %% IMPORTANT: We track processed transactions incrementally in the
        %% process dictionary so that if any transaction throws mid-fold,
        %% the catch block can roll back UTXO changes from the transactions
        %% that were already applied. Without this, a mid-fold throw would
        %% leave spent UTXOs unrestored, corrupting the UTXO set and causing
        %% permanent "missing_inputs" failures on retry.
        [CoinbaseTx | _RegularTxs] = Txs,
        put(connect_block_undo, {[], []}),
        %% UndoAcc is a reversed list of SpentCoins chunks (list of lists).
        %% ProcessedTxsAcc is a reversed list of processed txs.
        %% We flatten/reverse at the end to avoid O(n^2) ++ accumulation.
        {TotalFees, UndoChunksRev, TotalSigopCost, ScriptJobs, _ProcessedTxsRev} = lists:foldl(
            fun(Tx, {FeesAcc, UndoAcc, SigopsAcc, JobsAcc, TxsAcc}) ->
                IsCoinbase = is_coinbase_tx(Tx),
                case IsCoinbase of
                    true ->
                        %% coinbase: no inputs to validate
                        {FeesAcc, UndoAcc, SigopsAcc, JobsAcc, TxsAcc};
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
                        check_sequence_locks(Tx, InputCoins, Height, PrevIndex),

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
                        %% Create outputs (use add_utxo_fresh since BIP30
                        %% uniqueness was already checked above — no need
                        %% for the expensive RocksDB existence check)
                        Txid2 = beamchain_serialize:tx_hash(Tx),
                        lists:foldl(fun(#tx_out{value = V2, script_pubkey = SPK2}, Idx) ->
                            Utxo = #utxo{
                                value = V2,
                                script_pubkey = SPK2,
                                is_coinbase = false,
                                height = Height
                            },
                            beamchain_chainstate:add_utxo_fresh(Txid2, Idx, Utxo),
                            Idx + 1
                        end, 0, Tx#transaction.outputs),

                        %% Update incremental undo data so rollback works
                        %% even if a later transaction in this block throws.
                        %% Accumulate in reverse order (O(1) prepend) and
                        %% flatten at the end to avoid O(n^2) list append.
                        NewUndoAcc = [SpentCoins | UndoAcc],
                        NewTxsAcc = [Tx | TxsAcc],
                        %% Flatten for process dict (needed for mid-fold rollback)
                        put(connect_block_undo,
                            {lists:reverse(NewTxsAcc),
                             lists:append(lists:reverse(NewUndoAcc))}),

                        {FeesAcc + Fee, NewUndoAcc, NewSigops,
                         NewJobs, NewTxsAcc}
                end
            end,
            {0, [], 0, [], []},
            Txs),
        %% Flatten the reversed undo chunks into a single list
        AllUndoData = lists:append(lists:reverse(UndoChunksRev)),

        %% 4b. verify scripts in parallel (one process per tx)
        %% Update undo info with full transaction list for script-phase rollback.
        %% AllUndoData has the spent coins; Txs has the added outputs.
        put(connect_block_undo, {Txs, AllUndoData}),

        case ScriptJobs of
            [] -> ok;
            _ -> verify_scripts_parallel(ScriptJobs, Flags)
        end,

        %% Also count coinbase legacy sigops in the total
        CbSigops = count_legacy_sigops_tx(CoinbaseTx) * ?WITNESS_SCALE_FACTOR,
        (TotalSigopCost + CbSigops) =< ?MAX_BLOCK_SIGOPS_COST
            orelse throw(bad_blk_sigops),

        %% 5. verify block subsidy
        Subsidy = beamchain_chain_params:block_subsidy(Height, Network),
        CbValue = lists:foldl(fun(#tx_out{value = V}, A) -> A + V end,
                              0, CoinbaseTx#transaction.outputs),
        CbValue =< Subsidy + TotalFees orelse throw(bad_cb_amount),

        %% 6. add coinbase outputs to UTXO set (use add_utxo_fresh —
        %%    BIP30 uniqueness was already checked in step 3 above)
        CbTxid = beamchain_serialize:tx_hash(CoinbaseTx),
        lists:foldl(fun(#tx_out{value = V, script_pubkey = SPK}, Idx) ->
            Utxo = #utxo{
                value = V,
                script_pubkey = SPK,
                is_coinbase = true,
                height = Height
            },
            beamchain_chainstate:add_utxo_fresh(CbTxid, Idx, Utxo),
            Idx + 1
        end, 0, CoinbaseTx#transaction.outputs),

        %% 7. store undo data (direct write bypasses gen_server)
        UndoBin = encode_undo_data(AllUndoData),
        beamchain_db:direct_store_undo(BlockHash, UndoBin),

        %% Chain tip is updated in ETS by chainstate:do_connect_block.
        %% The RocksDB chain_tip is written during flush (atomically with
        %% UTXO changes) to avoid tip/UTXO mismatch on crash.

        %% NOTE: We intentionally do NOT erase connect_block_undo here.
        %% The caller (do_connect_block_inner) still has post-validation
        %% work to do (atomic_connect_writes, state update).  If any of
        %% those steps fail with an exit/crash, the terminate/2 handler
        %% needs the undo data to roll back the UTXO changes before
        %% flushing.  The caller erases it after all work is done.

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
            {error, {internal_error, Reason2}};
        exit:Reason3 ->
            %% Catch exit signals (e.g. gen_server:call timeout to
            %% beamchain_db during store_undo). Without this clause,
            %% the exit propagates up and crashes the chainstate
            %% gen_server, whose terminate/2 flushes the partially-
            %% modified UTXO cache to RocksDB — corrupting the UTXO
            %% set (inputs spent but chain_tip not advanced).
            case erase(connect_block_undo) of
                {UndoTxs3, UndoCoins3} ->
                    rollback_block_utxos(UndoTxs3, UndoCoins3);
                _ -> ok
            end,
            {error, {exit_during_connect, Reason3}}
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
%% When reconnecting blocks after a chainstate reset (tip rolled back but
%% UTXOs not fully cleaned), duplicate outputs are expected. In that case
%% we overwrite the existing UTXO rather than reject the block, matching
%% Bitcoin Core's behaviour for the two historical BIP30 exception blocks
%% and the general reconnection path.
check_no_existing_outputs(Txid, NumOutputs) ->
    lists:foreach(fun(Idx) ->
        case beamchain_chainstate:has_utxo(Txid, Idx) of
            true ->
                %% Check if we are reconnecting (chainstate tip is behind
                %% the block that originally created this UTXO). Log a
                %% warning but allow reconnection by spending the stale
                %% entry so the new output can take its place.
                logger:warning("BIP30 duplicate_txid (overwriting for reconnection): "
                               "txid=~s vout=~B (of ~B outputs)",
                               [binary:encode_hex(beamchain_serialize:reverse_bytes(Txid)),
                                Idx, NumOutputs]),
                beamchain_chainstate:spend_utxo(Txid, Idx);
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

%% @doc Calculate the minimum block height and time at which a transaction
%% can be included, based on BIP 68 relative lock-time constraints.
%% Returns {MinHeight, MinTime} where:
%%   - MinHeight is the minimum block height (or -1 if no height constraint)
%%   - MinTime is the minimum MTP of the previous block (or -1 if no time constraint)
%% Following Bitcoin Core semantics: these are "last invalid" values.
-spec calculate_sequence_lock_pair(#transaction{}, [#utxo{}], map()) ->
    {integer(), integer()}.
calculate_sequence_lock_pair(#transaction{version = Version},
                             _InputCoins, _PrevIndex) when Version < 2 ->
    %% BIP 68 only applies to tx version >= 2
    {-1, -1};
calculate_sequence_lock_pair(#transaction{inputs = Inputs}, InputCoins, _PrevIndex) ->
    lists:foldl(fun({Input, Coin}, {MinH, MinT}) ->
        Seq = Input#tx_in.sequence,
        %% if disable flag is set, skip this input
        case (Seq band ?SEQUENCE_LOCKTIME_DISABLE_FLAG) =/= 0 of
            true ->
                {MinH, MinT};
            false ->
                Masked = Seq band ?SEQUENCE_LOCKTIME_MASK,
                case (Seq band ?SEQUENCE_LOCKTIME_TYPE_FLAG) =/= 0 of
                    false ->
                        %% height-based lock
                        %% Bitcoin Core: nMinHeight = max(nMinHeight, coinHeight + value - 1)
                        CoinHeight = Coin#utxo.height,
                        NewMinH = CoinHeight + Masked - 1,
                        {max(MinH, NewMinH), MinT};
                    true ->
                        %% time-based lock
                        %% Bitcoin Core: get MTP of block prior to coin's block
                        CoinMTP = case Coin#utxo.height of
                            0 -> 0;
                            H ->
                                CoinMTPIndex = case beamchain_db:get_block_index(H - 1) of
                                    {ok, CI} -> CI;
                                    not_found -> error({missing_block_index, H - 1})
                                end,
                                median_time_past(CoinMTPIndex)
                        end,
                        %% Bitcoin Core: nMinTime = max(nMinTime, coinMTP + (value << 9) - 1)
                        LockSeconds = Masked bsl ?SEQUENCE_LOCKTIME_GRANULARITY,
                        NewMinT = CoinMTP + LockSeconds - 1,
                        {MinH, max(MinT, NewMinT)}
                end
        end
    end, {-1, -1}, lists:zip(Inputs, InputCoins)).

%% @doc Check BIP 68 sequence locks.
%% For tx version >= 2, verify relative timelocks are satisfied.
check_sequence_locks(#transaction{version = Version}, _InputCoins,
                     _Height, _PrevIndex) when Version < 2 ->
    %% BIP 68 only applies to tx version >= 2
    ok;
check_sequence_locks(Tx, InputCoins, Height, PrevIndex) ->
    {MinHeight, MinTime} = calculate_sequence_lock_pair(Tx, InputCoins, PrevIndex),
    MTP = median_time_past(PrevIndex),
    %% Bitcoin Core EvaluateSequenceLocks:
    %% Lock is satisfied when MinHeight < Height AND MinTime < MTP
    case MinHeight >= Height of
        true -> throw(sequence_lock_not_met);
        false -> ok
    end,
    case MinTime >= MTP of
        true -> throw(sequence_lock_not_met);
        false -> ok
    end.

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
    {ok, BlockHash :: binary()} | {error, atom()}.
%% Disconnect a block from the active chain.
%%
%% This is the *ETS-only* phase: it mutates the in-memory UTXO cache to
%% reverse the block's spend/create effects. It deliberately does NOT
%% commit the new chain tip or delete the on-disk undo data — those are
%% the caller's responsibility (chainstate's `do_disconnect_block` /
%% `do_reorganize`) so that:
%%
%%  - single-block disconnects can flush UTXO + tip + undo-delete in one
%%    RocksDB WriteBatch (single-block atomicity), and
%%  - multi-block reorgs can accumulate the disk side-effects of all
%%    disconnects + all connects into ONE final atomic batch
%%    (multi-block atomicity — Pattern D).
%%
%% Pre-fix, this function called `set_chain_tip` and `delete_undo`
%% inline as separate `rocksdb:put` / `rocksdb:delete` operations. A
%% crash between those writes and the chainstate flush left the disk
%% with: chain_tip pointing at PrevHash but UTXO set still reflecting
%% TipHash, and/or undo data already deleted from disk so the caller
%% couldn't replay. See
%% CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md
%% Pattern D.
%%
%% Returns {ok, BlockHash} so the caller can stage `delete_undo(Hash)`
%% into the same batch as the chainstate flush.
disconnect_block(#block{header = Header, transactions = Txs},
                 _Height, _Params) ->
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

        %% 3. NB: chain_tip update and undo-data delete are deliberately
        %% NOT performed here — see function docstring above. Caller
        %% (chainstate) batches them with the next UTXO flush so the
        %% disconnect is atomic across UTXO + tip + undo-delete.

        {ok, BlockHash}
    catch
        throw:Reason -> {error, Reason}
    end.

%%% -------------------------------------------------------------------
%%% Assumevalid ancestor check — Bitcoin Core v28.0 semantics
%%% -------------------------------------------------------------------

%% @doc Decide whether to skip script verification for the block at Height
%% with BlockHash, given chain consensus Params.
%%
%% Returns true (skip scripts) iff ALL six conditions hold:
%%   1. assume_valid hash is configured (non-zero).
%%   2. The assumed-valid block is present in the local block index.
%%   3. The block being connected is at or below the assumed-valid height
%%      (linear-chain equivalent of the ancestor check).
%%   4. The best known header extends at or above this block's height.
%%   5. The best-known-header's chainwork >= minimum chainwork.
%%   6. The best-known-header is at least 2 weeks of equivalent-work
%%      (POW_TARGET_TIMESPAN) past the block being connected.
%%
%% If any condition fails, scripts are verified normally.
%% Regtest: assume_valid is always <<0:256>>, so condition 1 fails → scripts run.
-spec skip_scripts(non_neg_integer(), binary(), map()) -> boolean().
skip_scripts(Height, BlockHash, Params) ->
    %% Condition 1: assume_valid must be configured (non-zero)
    AssumeValidDisplay = maps:get(assume_valid, Params, <<0:256>>),
    case AssumeValidDisplay of
        <<0:256>> ->
            %% Regtest and networks with no assume_valid: always verify scripts.
            false;
        _ ->
            %% assume_valid is stored in display byte order (big-endian hex).
            %% The block index stores hashes in internal byte order (reversed).
            AssumeValid = beamchain_serialize:reverse_bytes(AssumeValidDisplay),
            %% Condition 2: assumed-valid block must be in our block index.
            AVLookup = beamchain_db:get_block_index_by_hash(AssumeValid),
            %% Conditions 4-6: look up best known header tip.
            HdrTip = beamchain_db:get_header_tip(),
            %% For condition 6: look up block's own index entry for its timestamp.
            BlockEntry = beamchain_db:get_block_index(Height),
            skip_scripts_eval(Height, BlockHash, Params, AVLookup, HdrTip, BlockEntry)
    end.

%% @doc Pure evaluator for the 6-condition skip_scripts check.
%% All DB lookups are passed in as arguments so this function is unit-testable
%% without a running database.
%%
%% Arguments:
%%   Height     — height of the block being connected
%%   _BlockHash — hash of the block being connected (reserved for future use)
%%   Params     — chain consensus params map
%%   AVLookup   — result of beamchain_db:get_block_index_by_hash(AVHash)
%%   HdrTip     — result of beamchain_db:get_header_tip()
%%   BlockEntry — result of beamchain_db:get_block_index(Height)
-spec skip_scripts_eval(
    non_neg_integer(), binary(), map(),
    {ok, map()} | not_found,
    {ok, map()} | not_found,
    {ok, map()} | not_found
) -> boolean().
skip_scripts_eval(Height, _BlockHash, Params, AVLookup, HdrTip, BlockEntry) ->
    case AVLookup of
        not_found ->
            %% Condition 2 fails: assumed-valid block header not yet received.
            false;
        {ok, #{height := AVHeight}} ->
            %% Condition 3: block must be at or below assumed-valid height.
            %% In beamchain's linear canonical chain, any block being connected
            %% via connect_block IS on the canonical chain (prev_hash enforced
            %% in do_connect_block). Therefore height =< AVHeight is a correct
            %% linear-chain equivalent of Bitcoin Core's GetAncestor check.
            case Height > AVHeight of
                true ->
                    %% Block is above the assumed-valid block → verify scripts.
                    false;
                false ->
                    %% Conditions 4-6 require the best-known-header tip.
                    case HdrTip of
                        not_found ->
                            false;
                        {ok, #{hash := HdrHash, height := HdrHeight}} ->
                            %% Condition 4: best known header must be at or
                            %% above this block's height (block is in the
                            %% best header chain).
                            case HdrHeight < Height of
                                true ->
                                    false;
                                false ->
                                    %% Conditions 5 and 6 need the header tip's
                                    %% block index entry (chainwork + timestamp).
                                    HdrEntry = case beamchain_db:get_block_index_by_hash(HdrHash) of
                                        not_found -> not_found;
                                        {ok, E} -> E
                                    end,
                                    check_chainwork_and_time(
                                        Height, HdrEntry, BlockEntry, Params)
                            end
                    end
            end
    end.

%% Check conditions 5 and 6 given the header tip's index entry.
%% HdrEntry is a map (from block_index) or 'not_found'.
%% BlockEntry is {ok, map()} | not_found for the block being connected.
check_chainwork_and_time(_BlockHeight, not_found, _BlockEntry, _Params) ->
    false;
check_chainwork_and_time(_BlockHeight, HdrEntry, BlockEntry, Params) ->
    %% Condition 5: best-header chainwork >= minimum chainwork.
    MinChainwork = maps:get(min_chainwork, Params, <<0:256>>),
    HdrChainwork = maps:get(chainwork, HdrEntry, <<0:256>>),
    MinCWInt = binary:decode_unsigned(MinChainwork, big),
    HdrCWInt = binary:decode_unsigned(HdrChainwork, big),
    case HdrCWInt < MinCWInt of
        true ->
            false;
        false ->
            %% Condition 6: best header must be at least POW_TARGET_TIMESPAN
            %% (1 209 600 seconds = 2 weeks) past the block being connected.
            %% We use header timestamps as a proxy for block-proof-equivalent
            %% time, matching Bitcoin Core's GetBlockProofEquivalentTime intent.
            HdrTimestamp = case maps:get(header, HdrEntry, undefined) of
                undefined -> 0;
                H -> H#block_header.timestamp
            end,
            %% Get the block being connected's timestamp from its index entry.
            BlockTimestamp = case BlockEntry of
                {ok, #{header := BH}} -> BH#block_header.timestamp;
                not_found ->
                    %% Block not yet in index (fresh IBD connecting a new block).
                    %% Use 0 so the time-delta check passes when the header tip
                    %% is well ahead — the only case that matters for IBD speed.
                    0
            end,
            TimeDelta = HdrTimestamp - BlockTimestamp,
            TimeDelta > ?POW_TARGET_TIMESPAN
    end.

%% Split a list, taking the last N elements.
%% Returns {LastN, Rest} where Rest ++ LastN = List.
%% If N >= length(List), returns {List, []}.
split_last_n(List, N) ->
    Len = length(List),
    case Len =< N of
        true -> {List, []};
        false -> {lists:sublist(List, Len - N), lists:nthtail(Len - N, List)}
    end.
