-module(beamchain_serialize).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Varint
-export([encode_varint/1, decode_varint/1, decode_varint_no_range/1]).

%% Little-endian helpers
-export([encode_le32/1, decode_le32/1,
         encode_le64/1, decode_le64/1]).

%% Variable-length string/bytes
-export([encode_varstr/1, decode_varstr/1]).

%% Block header
-export([encode_block_header/1, decode_block_header/1]).

%% Transaction
-export([encode_transaction/1, encode_transaction/2,
         decode_transaction/1]).

%% Tx inputs/outputs
-export([encode_tx_in/1, decode_tx_in/1,
         encode_tx_out/1, decode_tx_out/1]).

%% Full block
-export([encode_block/1, decode_block/1]).

%% Hashing
-export([block_hash/1, tx_hash/1, wtx_hash/1,
         hash256/1, hash160/1]).

%% Merkle
-export([compute_merkle_root/1, compute_witness_commitment/2]).

%% Weight/vsize/size
-export([tx_weight/1, tx_vsize/1, tx_sigop_vsize/2, tx_size/1]).
%% Block weight (includes header + varint tx count + transactions)
-export([block_weight/1]).

%% Utility
-export([reverse_bytes/1, hex_encode/1, hex_decode/1]).

%%% -------------------------------------------------------------------
%%% Varint (CompactSize) encoding
%%% -------------------------------------------------------------------

-spec encode_varint(non_neg_integer()) -> binary().
encode_varint(N) when N >= 0, N =< 16#FC ->
    <<N:8>>;
encode_varint(N) when N =< 16#FFFF ->
    <<16#FD:8, N:16/little>>;
encode_varint(N) when N =< 16#FFFFFFFF ->
    <<16#FE:8, N:32/little>>;
encode_varint(N) when N =< 16#FFFFFFFFFFFFFFFF ->
    <<16#FF:8, N:64/little>>.

%% MAX_SIZE mirrors bitcoin-core/src/serialize.h line 34:
%%   MAX_SIZE = 0x02000000 (= 33,554,432 bytes)
%% ReadCompactSize throws "ReadCompactSize(): size too large" when the
%% decoded value exceeds MAX_SIZE (range_check=true, the default).
-define(MAX_COMPACT_SIZE, 16#02000000).

-spec decode_varint(binary()) -> {non_neg_integer(), binary()} | {error, atom()}.
decode_varint(<<16#FD:8, N:16/little, _Rest/binary>>) when N < 253 ->
    {error, non_canonical_compact_size};
decode_varint(<<16#FD:8, N:16/little, _Rest/binary>>) when N > ?MAX_COMPACT_SIZE ->
    {error, oversized_compact_size};
decode_varint(<<16#FD:8, N:16/little, Rest/binary>>) ->
    {N, Rest};
decode_varint(<<16#FE:8, N:32/little, _Rest/binary>>) when N < 16#10000 ->
    {error, non_canonical_compact_size};
decode_varint(<<16#FE:8, N:32/little, _Rest/binary>>) when N > ?MAX_COMPACT_SIZE ->
    {error, oversized_compact_size};
decode_varint(<<16#FE:8, N:32/little, Rest/binary>>) ->
    {N, Rest};
decode_varint(<<16#FF:8, N:64/little, _Rest/binary>>) when N < 16#100000000 ->
    {error, non_canonical_compact_size};
decode_varint(<<16#FF:8, N:64/little, _Rest/binary>>) when N > ?MAX_COMPACT_SIZE ->
    {error, oversized_compact_size};
decode_varint(<<16#FF:8, N:64/little, Rest/binary>>) ->
    {N, Rest};
decode_varint(<<N:8, Rest/binary>>) ->
    {N, Rest}.

%% @doc Decode CompactSize without the MAX_SIZE range check.
%% Mirrors bitcoin-core's ReadCompactSize(stream, range_check=false).
%% Use for fields that are bitmasks / arbitrary uint64 values rather than
%% allocation sizes — e.g. the services field in addrv2 (BIP-155).
-spec decode_varint_no_range(binary()) -> {non_neg_integer(), binary()} | {error, atom()}.
decode_varint_no_range(<<16#FD:8, N:16/little, _Rest/binary>>) when N < 253 ->
    {error, non_canonical_compact_size};
decode_varint_no_range(<<16#FD:8, N:16/little, Rest/binary>>) ->
    {N, Rest};
decode_varint_no_range(<<16#FE:8, N:32/little, _Rest/binary>>) when N < 16#10000 ->
    {error, non_canonical_compact_size};
decode_varint_no_range(<<16#FE:8, N:32/little, Rest/binary>>) ->
    {N, Rest};
decode_varint_no_range(<<16#FF:8, N:64/little, _Rest/binary>>) when N < 16#100000000 ->
    {error, non_canonical_compact_size};
decode_varint_no_range(<<16#FF:8, N:64/little, Rest/binary>>) ->
    {N, Rest};
decode_varint_no_range(<<N:8, Rest/binary>>) ->
    {N, Rest}.

%%% -------------------------------------------------------------------
%%% Little-endian integer helpers
%%% -------------------------------------------------------------------

-spec encode_le32(non_neg_integer()) -> binary().
encode_le32(N) -> <<N:32/little>>.

-spec decode_le32(binary()) -> {non_neg_integer(), binary()}.
decode_le32(<<N:32/little, Rest/binary>>) -> {N, Rest}.

-spec encode_le64(non_neg_integer()) -> binary().
encode_le64(N) -> <<N:64/little>>.

-spec decode_le64(binary()) -> {non_neg_integer(), binary()}.
decode_le64(<<N:64/little, Rest/binary>>) -> {N, Rest}.

%%% -------------------------------------------------------------------
%%% Variable-length string (varint length prefix + bytes)
%%% -------------------------------------------------------------------

-spec encode_varstr(binary()) -> binary().
encode_varstr(Bin) ->
    <<(encode_varint(byte_size(Bin)))/binary, Bin/binary>>.

-spec decode_varstr(binary()) -> {binary(), binary()}.
decode_varstr(Bin) ->
    {Len, Rest} = decode_varint(Bin),
    <<Str:Len/binary, Rest2/binary>> = Rest,
    {Str, Rest2}.

%%% -------------------------------------------------------------------
%%% Block header (80 bytes)
%%% -------------------------------------------------------------------

-spec encode_block_header(#block_header{}) -> binary().
encode_block_header(#block_header{version = Version,
                                  prev_hash = PrevHash,
                                  merkle_root = MerkleRoot,
                                  timestamp = Timestamp,
                                  bits = Bits,
                                  nonce = Nonce}) ->
    <<Version:32/little,
      PrevHash:32/binary,
      MerkleRoot:32/binary,
      Timestamp:32/little,
      Bits:32/little,
      Nonce:32/little>>.

-spec decode_block_header(binary()) -> {#block_header{}, binary()}.
decode_block_header(<<Version:32/little,
                      PrevHash:32/binary,
                      MerkleRoot:32/binary,
                      Timestamp:32/little,
                      Bits:32/little,
                      Nonce:32/little,
                      Rest/binary>>) ->
    Header = #block_header{
        version = Version,
        prev_hash = PrevHash,
        merkle_root = MerkleRoot,
        timestamp = Timestamp,
        bits = Bits,
        nonce = Nonce
    },
    {Header, Rest}.

%%% -------------------------------------------------------------------
%%% Hashing
%%% -------------------------------------------------------------------

-spec hash256(binary()) -> binary().
hash256(Data) ->
    beamchain_crypto:hash256(Data).

-spec hash160(binary()) -> binary().
hash160(Data) ->
    beamchain_crypto:hash160(Data).

-spec block_hash(#block_header{} | #block{}) -> binary().
block_hash(#block{header = Header}) ->
    block_hash(Header);
block_hash(#block_header{} = Header) ->
    hash256(encode_block_header(Header)).

-spec tx_hash(#transaction{}) -> binary().
tx_hash(Tx) ->
    hash256(encode_transaction(Tx, no_witness)).

-spec wtx_hash(#transaction{}) -> binary().
wtx_hash(Tx) ->
    case has_witness(Tx) of
        true  -> hash256(encode_transaction(Tx, witness));
        false -> tx_hash(Tx)
    end.

%%% -------------------------------------------------------------------
%%% Merkle tree
%%% -------------------------------------------------------------------

-spec compute_merkle_root([binary()]) -> binary().
compute_merkle_root([]) ->
    <<0:256>>;
compute_merkle_root([Root]) ->
    Root;
compute_merkle_root(Hashes) ->
    NextLevel = merkle_pairs(Hashes),
    compute_merkle_root(NextLevel).

merkle_pairs([]) ->
    [];
merkle_pairs([A]) ->
    %% odd element: duplicate it
    [hash256(<<A/binary, A/binary>>)];
merkle_pairs([A, B | Rest]) ->
    [hash256(<<A/binary, B/binary>>) | merkle_pairs(Rest)].

-spec compute_witness_commitment([binary()], binary()) -> binary().
compute_witness_commitment(Wtxids, WitnessNonce) ->
    %% coinbase wtxid is 32 zero bytes (first element should already be set)
    WitnessRoot = compute_merkle_root(Wtxids),
    hash256(<<WitnessRoot/binary, WitnessNonce/binary>>).

%%% -------------------------------------------------------------------
%%% Transaction input
%%% -------------------------------------------------------------------

-spec encode_tx_in(#tx_in{}) -> binary().
encode_tx_in(#tx_in{prev_out = #outpoint{hash = Hash, index = Index},
                    script_sig = ScriptSig,
                    sequence = Sequence}) ->
    <<Hash:32/binary,
      Index:32/little,
      (encode_varstr(ScriptSig))/binary,
      Sequence:32/little>>.

-spec decode_tx_in(binary()) -> {#tx_in{}, binary()}.
decode_tx_in(<<Hash:32/binary, Index:32/little, Rest/binary>>) ->
    {ScriptSig, Rest2} = decode_varstr(Rest),
    <<Sequence:32/little, Rest3/binary>> = Rest2,
    TxIn = #tx_in{
        prev_out = #outpoint{hash = Hash, index = Index},
        script_sig = ScriptSig,
        sequence = Sequence,
        witness = []
    },
    {TxIn, Rest3}.

%%% -------------------------------------------------------------------
%%% Transaction output
%%% -------------------------------------------------------------------

-spec encode_tx_out(#tx_out{}) -> binary().
encode_tx_out(#tx_out{value = Value, script_pubkey = ScriptPubKey}) ->
    <<Value:64/little, (encode_varstr(ScriptPubKey))/binary>>.

-spec decode_tx_out(binary()) -> {#tx_out{}, binary()}.
decode_tx_out(<<Value:64/signed-little, Rest/binary>>) ->
    %% Bitcoin wire format for output value is int64 (signed).  Using
    %% signed-little ensures negative wire values (e.g. -1 = 0xffffffffffffffff)
    %% arrive as negative integers so check_transaction's `V >= 0` guard fires
    %% the negative_output atom rather than output_too_large.
    %% Reference: consensus/tx_check.cpp::CheckTransaction (Core parity).
    {ScriptPubKey, Rest2} = decode_varstr(Rest),
    {#tx_out{value = Value, script_pubkey = ScriptPubKey}, Rest2}.

%%% -------------------------------------------------------------------
%%% Transaction serialization
%%% -------------------------------------------------------------------

-spec encode_transaction(#transaction{}) -> binary().
encode_transaction(Tx) ->
    %% default: use witness format if any input has witness data
    case has_witness(Tx) of
        true  -> encode_transaction(Tx, witness);
        false -> encode_transaction(Tx, no_witness)
    end.

-spec encode_transaction(#transaction{}, witness | no_witness) -> binary().
encode_transaction(#transaction{version = Version, inputs = Inputs,
                                outputs = Outputs, locktime = Locktime},
                   no_witness) ->
    InputsBin = encode_list(Inputs, fun encode_tx_in/1),
    OutputsBin = encode_list(Outputs, fun encode_tx_out/1),
    <<Version:32/little,
      InputsBin/binary,
      OutputsBin/binary,
      Locktime:32/little>>;
encode_transaction(#transaction{version = Version, inputs = Inputs,
                                outputs = Outputs, locktime = Locktime},
                   witness) ->
    InputsBin = encode_list(Inputs, fun encode_tx_in/1),
    OutputsBin = encode_list(Outputs, fun encode_tx_out/1),
    WitnessBin = encode_witness(Inputs),
    <<Version:32/little,
      16#00:8, 16#01:8,   %% segwit marker + flag
      InputsBin/binary,
      OutputsBin/binary,
      WitnessBin/binary,
      Locktime:32/little>>.

-spec decode_transaction(binary()) -> {#transaction{}, binary()}.
decode_transaction(<<Version:32/little, Rest/binary>>) ->
    case Rest of
        <<16#00:8, 16#01:8, Rest2/binary>> ->
            %% witness format
            decode_transaction_witness(Version, Rest2);
        _ ->
            %% legacy format
            decode_transaction_legacy(Version, Rest)
    end.

decode_transaction_legacy(Version, Bin) ->
    {Inputs, Rest} = decode_list(Bin, fun decode_tx_in/1),
    {Outputs, Rest2} = decode_list(Rest, fun decode_tx_out/1),
    <<Locktime:32/little, Rest3/binary>> = Rest2,
    Tx = #transaction{
        version = Version,
        inputs = Inputs,
        outputs = Outputs,
        locktime = Locktime
    },
    {Tx, Rest3}.

decode_transaction_witness(Version, Bin) ->
    {Inputs, Rest} = decode_list(Bin, fun decode_tx_in/1),
    {Outputs, Rest2} = decode_list(Rest, fun decode_tx_out/1),
    {InputsWithWitness, Rest3} = decode_witness_data(Inputs, Rest2),
    <<Locktime:32/little, Rest4/binary>> = Rest3,
    Tx = #transaction{
        version = Version,
        inputs = InputsWithWitness,
        outputs = Outputs,
        locktime = Locktime
    },
    {Tx, Rest4}.

%%% -------------------------------------------------------------------
%%% Full block
%%% -------------------------------------------------------------------

-spec encode_block(#block{}) -> binary().
encode_block(#block{header = Header, transactions = Txs}) ->
    HeaderBin = encode_block_header(Header),
    TxsBin = encode_list(Txs, fun encode_transaction/1),
    <<HeaderBin/binary, TxsBin/binary>>.

-spec decode_block(binary()) -> {#block{}, binary()}.
decode_block(Bin) ->
    {Header, Rest} = decode_block_header(Bin),
    {Txs, Rest2} = decode_list(Rest, fun decode_transaction/1),
    Block = #block{
        header = Header,
        transactions = Txs
    },
    {Block, Rest2}.

%%% -------------------------------------------------------------------
%%% Weight / vsize
%%% -------------------------------------------------------------------

-spec tx_weight(#transaction{}) -> non_neg_integer().
tx_weight(Tx) ->
    BaseSize = byte_size(encode_transaction(Tx, no_witness)),
    case has_witness(Tx) of
        true ->
            TotalSize = byte_size(encode_transaction(Tx, witness)),
            (BaseSize * (?WITNESS_SCALE_FACTOR - 1)) + TotalSize;
        false ->
            BaseSize * ?WITNESS_SCALE_FACTOR
    end.

-spec tx_vsize(#transaction{}) -> non_neg_integer().
tx_vsize(Tx) ->
    Weight = tx_weight(Tx),
    (Weight + ?WITNESS_SCALE_FACTOR - 1) div ?WITNESS_SCALE_FACTOR.

%% @doc Compute sigop-adjusted virtual transaction size.
%% Mirrors Bitcoin Core policy/policy.cpp GetVirtualTransactionSize:
%%   vsize = ceil(max(weight, sigop_cost * bytes_per_sigop) / WITNESS_SCALE_FACTOR)
%% The bytes_per_sigop parameter corresponds to Core's DEFAULT_BYTES_PER_SIGOP (20).
-spec tx_sigop_vsize(#transaction{}, non_neg_integer()) -> non_neg_integer().
tx_sigop_vsize(Tx, SigopCost) ->
    Weight = tx_weight(Tx),
    AdjustedWeight = max(Weight, SigopCost * 20),
    (AdjustedWeight + ?WITNESS_SCALE_FACTOR - 1) div ?WITNESS_SCALE_FACTOR.

%% @doc Compute total block weight.
%% Mirrors Bitcoin Core consensus/validation.h GetBlockWeight:
%%   weight = stripped_size * (WITNESS_SCALE_FACTOR - 1) + total_size
%% which equals: header(80) * 4 + varint(tx_count) * 4 + sum(tx_weight).
%% The varint encoding of the transaction count contributes
%% varint_size * WITNESS_SCALE_FACTOR weight units (it has no witness discount).
-spec block_weight([#transaction{}]) -> non_neg_integer().
block_weight(Txs) ->
    %% 80-byte header: contributes 80 * 4 = 320 weight units
    HeaderWeight = 80 * ?WITNESS_SCALE_FACTOR,
    %% varint-encoded transaction count: no witness discount → * 4
    TxCountVarintSize = byte_size(encode_varint(length(Txs))),
    TxCountWeight = TxCountVarintSize * ?WITNESS_SCALE_FACTOR,
    %% sum of individual transaction weights
    TxWeight = lists:foldl(fun(Tx, Acc) ->
        Acc + tx_weight(Tx)
    end, 0, Txs),
    HeaderWeight + TxCountWeight + TxWeight.

%% @doc Get the serialized size of a transaction in bytes
-spec tx_size(#transaction{}) -> non_neg_integer().
tx_size(Tx) ->
    byte_size(encode_transaction(Tx)).

%%% -------------------------------------------------------------------
%%% Utility functions
%%% -------------------------------------------------------------------

-spec reverse_bytes(binary()) -> binary().
reverse_bytes(Bin) ->
    S = byte_size(Bin) * 8,
    <<V:S/integer-little>> = Bin,
    <<V:S/integer-big>>.


-spec hex_encode(binary()) -> binary().
hex_encode(Bin) ->
    binary:encode_hex(Bin, lowercase).

-spec hex_decode(binary() | string()) -> binary().
hex_decode(Hex) when is_binary(Hex) ->
    binary:decode_hex(Hex);
hex_decode(Hex) when is_list(Hex) ->
    binary:decode_hex(list_to_binary(Hex)).

%%% -------------------------------------------------------------------
%%% Internal helpers
%%% -------------------------------------------------------------------

has_witness(#transaction{inputs = Inputs}) ->
    lists:any(fun(#tx_in{witness = W}) ->
        W =/= [] andalso W =/= undefined
    end, Inputs).

encode_list(Items, EncodeFun) ->
    CountBin = encode_varint(length(Items)),
    DataBin = list_to_binary([EncodeFun(Item) || Item <- Items]),
    <<CountBin/binary, DataBin/binary>>.

decode_list(Bin, DecodeFun) ->
    {Count, Rest} = decode_varint(Bin),
    decode_n(Count, Rest, DecodeFun, []).

decode_n(0, Rest, _DecodeFun, Acc) ->
    {lists:reverse(Acc), Rest};
decode_n(N, Bin, DecodeFun, Acc) ->
    {Item, Rest} = DecodeFun(Bin),
    decode_n(N - 1, Rest, DecodeFun, [Item | Acc]).

encode_witness(Inputs) ->
    list_to_binary([encode_witness_stack(In) || In <- Inputs]).

encode_witness_stack(#tx_in{witness = undefined}) ->
    encode_varint(0);
encode_witness_stack(#tx_in{witness = []}) ->
    encode_varint(0);
encode_witness_stack(#tx_in{witness = Items}) ->
    CountBin = encode_varint(length(Items)),
    DataBin = list_to_binary([encode_varstr(Item) || Item <- Items]),
    <<CountBin/binary, DataBin/binary>>.

decode_witness_data(Inputs, Bin) ->
    decode_witness_items(Inputs, Bin, []).

decode_witness_items([], Bin, Acc) ->
    {lists:reverse(Acc), Bin};
decode_witness_items([Input | Rest], Bin, Acc) ->
    {StackItems, Bin2} = decode_witness_stack(Bin),
    Input2 = Input#tx_in{witness = StackItems},
    decode_witness_items(Rest, Bin2, [Input2 | Acc]).

decode_witness_stack(Bin) ->
    {Count, Rest} = decode_varint(Bin),
    decode_n(Count, Rest, fun decode_varstr/1, []).
