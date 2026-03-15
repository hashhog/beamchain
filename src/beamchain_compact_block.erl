-module(beamchain_compact_block).

%% BIP152 Compact Block Relay
%%
%% Compact blocks reduce block propagation bandwidth by sending:
%% - Block header (80 bytes)
%% - 8-byte nonce for SipHash key derivation
%% - 6-byte short txids instead of full 32-byte txids
%% - Prefilled transactions (at least the coinbase)
%%
%% Receivers reconstruct blocks using their mempool.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([init_compact_block/1,
         try_reconstruct/2,
         fill_block/2,
         get_missing_indices/1,
         compute_short_id/3,
         derive_siphash_key/2]).

%% Short txid length (6 bytes = 48 bits)
-define(SHORT_TXID_LENGTH, 6).

%% Maximum transactions per compact block
-define(MAX_COMPACT_BLOCK_TXS, 65535).

%%% -------------------------------------------------------------------
%%% Compact block state (partially downloaded block)
%%% -------------------------------------------------------------------

-record(compact_state, {
    header       :: #block_header{},
    block_hash   :: binary(),
    nonce        :: non_neg_integer(),
    k0           :: non_neg_integer(),
    k1           :: non_neg_integer(),
    short_ids    :: [binary()],       %% list of 6-byte short ids
    prefilled    :: [{non_neg_integer(), #transaction{}}],
    txn_count    :: non_neg_integer(),
    txn_available :: array:array(),   %% array of tx | undefined
    missing_count :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Initialize compact block state from a cmpctblock message.
%% Returns {ok, State} or {error, Reason}.
-spec init_compact_block(map()) -> {ok, #compact_state{}} | {error, term()}.
init_compact_block(#{header := Header, nonce := Nonce,
                     short_ids := ShortIds, prefilled_txns := Prefilled}) ->
    try
        %% Validate counts
        TxnCount = length(ShortIds) + length(Prefilled),
        TxnCount =< ?MAX_COMPACT_BLOCK_TXS orelse throw(too_many_txns),

        %% Compute block hash and SipHash key
        BlockHash = beamchain_serialize:block_hash(Header),
        {K0, K1} = derive_siphash_key(Header, Nonce),

        %% Initialize txn_available array with undefined
        TxnAvailable0 = array:new(TxnCount, {default, undefined}),

        %% Process prefilled transactions (indexes are differential)
        %% Each index is relative to the previous prefilled tx + 1
        {TxnAvailable1, _LastIdx} = lists:foldl(
            fun(#{index := DiffIdx, tx := Tx}, {Arr, PrevIdx}) ->
                AbsIdx = PrevIdx + DiffIdx + 1,
                AbsIdx < TxnCount orelse throw(invalid_prefilled_index),
                Arr2 = array:set(AbsIdx, Tx, Arr),
                {Arr2, AbsIdx}
            end,
            {TxnAvailable0, -1},
            Prefilled),

        %% Convert prefilled to absolute indexes for storage
        {PrefilledAbs, _} = lists:mapfoldl(
            fun(#{index := DiffIdx, tx := Tx}, PrevIdx) ->
                AbsIdx = PrevIdx + DiffIdx + 1,
                {{AbsIdx, Tx}, AbsIdx}
            end,
            -1,
            Prefilled),

        %% Count how many we still need
        PrefilledCount = length(Prefilled),
        MissingCount = TxnCount - PrefilledCount,

        State = #compact_state{
            header = Header,
            block_hash = BlockHash,
            nonce = Nonce,
            k0 = K0,
            k1 = K1,
            short_ids = ShortIds,
            prefilled = PrefilledAbs,
            txn_count = TxnCount,
            txn_available = TxnAvailable1,
            missing_count = MissingCount
        },
        {ok, State}
    catch
        throw:Reason -> {error, Reason}
    end.

%% @doc Try to reconstruct the full block using mempool transactions.
%% Returns {ok, Block} if successful, {partial, State} if some txns missing,
%% or {error, Reason} if reconstruction failed.
-spec try_reconstruct(#compact_state{}, [#transaction{}]) ->
    {ok, #block{}} | {partial, #compact_state{}} | {error, term()}.
try_reconstruct(#compact_state{short_ids = ShortIds, k0 = K0, k1 = K1,
                                txn_available = TxnAvailable0,
                                prefilled = Prefilled} = State,
                ExtraTxns) ->
    %% Build map of short_id -> index for all short ids
    %% Skip indices that are already filled (prefilled)
    PrefilledIdxs = sets:from_list([Idx || {Idx, _} <- Prefilled]),
    {ShortIdMap, _} = lists:foldl(
        fun(ShortId, {Map, Idx}) ->
            %% Skip if this index has a prefilled txn
            Idx2 = skip_prefilled(Idx, PrefilledIdxs),
            {maps:put(ShortId, Idx2, Map), Idx2 + 1}
        end,
        {#{}, 0},
        ShortIds),

    %% Try to match mempool transactions
    {TxnAvailable1, MatchCount1} = match_mempool_txns(
        ShortIdMap, K0, K1, TxnAvailable0),

    %% Try to match extra transactions (recently received)
    {TxnAvailable2, MatchCount2} = match_extra_txns(
        ExtraTxns, ShortIdMap, K0, K1, TxnAvailable1),

    TotalMatched = MatchCount1 + MatchCount2,
    MissingCount = State#compact_state.missing_count - TotalMatched,

    case MissingCount of
        0 ->
            %% All transactions found, build the block
            build_block(State#compact_state{txn_available = TxnAvailable2});
        _ ->
            %% Still missing some transactions
            State2 = State#compact_state{
                txn_available = TxnAvailable2,
                missing_count = MissingCount
            },
            {partial, State2}
    end.

%% @doc Fill in missing transactions from a blocktxn response.
-spec fill_block(#compact_state{}, [#transaction{}]) ->
    {ok, #block{}} | {error, term()}.
fill_block(#compact_state{txn_available = TxnAvailable} = State,
           MissingTxns) ->
    %% Fill in the missing slots in order
    {TxnAvailable2, Remaining} = lists:foldl(
        fun(Tx, {Arr, [Idx | RestIdx]}) ->
            {array:set(Idx, Tx, Arr), RestIdx};
           (_Tx, {Arr, []}) ->
            %% More txns than needed
            {Arr, []}
        end,
        {TxnAvailable, get_missing_indices(State)},
        MissingTxns),

    case Remaining of
        [] ->
            build_block(State#compact_state{txn_available = TxnAvailable2});
        _ ->
            %% Not enough txns provided
            {error, insufficient_txns}
    end.

%% @doc Get list of indices for missing transactions.
-spec get_missing_indices(#compact_state{}) -> [non_neg_integer()].
get_missing_indices(#compact_state{txn_available = TxnAvailable,
                                    txn_count = TxnCount}) ->
    lists:filtermap(
        fun(Idx) ->
            case array:get(Idx, TxnAvailable) of
                undefined -> {true, Idx};
                _ -> false
            end
        end,
        lists:seq(0, TxnCount - 1)).

%% @doc Compute short txid for a transaction.
%% Short ID = first 6 bytes of SipHash(K0, K1, wtxid).
-spec compute_short_id(non_neg_integer(), non_neg_integer(),
                       binary()) -> binary().
compute_short_id(K0, K1, Wtxid) when byte_size(Wtxid) =:= 32 ->
    Hash = beamchain_crypto:siphash_uint256(K0, K1, Wtxid),
    <<(Hash band 16#ffffffffffff):48/little>>.

%% @doc Derive SipHash key from block header and nonce.
%% Key = SHA256(header || nonce), take first 16 bytes as K0, K1.
-spec derive_siphash_key(#block_header{}, non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer()}.
derive_siphash_key(Header, Nonce) ->
    HeaderBin = beamchain_serialize:encode_block_header(Header),
    KeyData = crypto:hash(sha256, <<HeaderBin/binary, Nonce:64/little>>),
    <<K0:64/little, K1:64/little, _/binary>> = KeyData,
    {K0, K1}.

%%% ===================================================================
%%% Internal functions
%%% ===================================================================

%% Skip over indices that have prefilled transactions
skip_prefilled(Idx, PrefilledIdxs) ->
    case sets:is_element(Idx, PrefilledIdxs) of
        true -> skip_prefilled(Idx + 1, PrefilledIdxs);
        false -> Idx
    end.

%% Match mempool transactions against short ids
match_mempool_txns(ShortIdMap, K0, K1, TxnAvailable) ->
    %% Get all mempool entries
    Txids = beamchain_mempool:get_all_txids(),
    lists:foldl(
        fun(Txid, {Arr, Count}) ->
            case beamchain_mempool:get_tx(Txid) of
                {ok, Tx} ->
                    Wtxid = beamchain_serialize:wtx_hash(Tx),
                    ShortId = compute_short_id(K0, K1, Wtxid),
                    case maps:find(ShortId, ShortIdMap) of
                        {ok, Idx} ->
                            %% Check if slot is still empty
                            case array:get(Idx, Arr) of
                                undefined ->
                                    {array:set(Idx, Tx, Arr), Count + 1};
                                _Existing ->
                                    %% Collision! Two txns match same short id
                                    %% Clear the slot to force a fetch
                                    {array:set(Idx, undefined, Arr), Count}
                            end;
                        error ->
                            {Arr, Count}
                    end;
                not_found ->
                    {Arr, Count}
            end
        end,
        {TxnAvailable, 0},
        Txids).

%% Match extra transactions against short ids
match_extra_txns(ExtraTxns, ShortIdMap, K0, K1, TxnAvailable) ->
    lists:foldl(
        fun(Tx, {Arr, Count}) ->
            Wtxid = beamchain_serialize:wtx_hash(Tx),
            ShortId = compute_short_id(K0, K1, Wtxid),
            case maps:find(ShortId, ShortIdMap) of
                {ok, Idx} ->
                    case array:get(Idx, Arr) of
                        undefined ->
                            {array:set(Idx, Tx, Arr), Count + 1};
                        Existing ->
                            %% Check for collision with different tx
                            ExistingWtxid = beamchain_serialize:wtx_hash(Existing),
                            case ExistingWtxid =:= Wtxid of
                                true ->
                                    %% Same tx, no collision
                                    {Arr, Count};
                                false ->
                                    %% Collision, clear slot
                                    {array:set(Idx, undefined, Arr), Count}
                            end
                    end;
                error ->
                    {Arr, Count}
            end
        end,
        {TxnAvailable, 0},
        ExtraTxns).

%% Build the final block from fully reconstructed txn_available
build_block(#compact_state{header = Header, block_hash = BlockHash,
                            txn_available = TxnAvailable,
                            txn_count = TxnCount}) ->
    %% Extract all transactions in order
    Txs = [array:get(I, TxnAvailable) || I <- lists:seq(0, TxnCount - 1)],

    %% Verify no undefined entries
    case lists:any(fun(T) -> T =:= undefined end, Txs) of
        true ->
            {error, missing_transactions};
        false ->
            Block = #block{
                header = Header,
                transactions = Txs,
                hash = BlockHash
            },
            %% Verify merkle root matches
            case verify_merkle_root(Block) of
                true -> {ok, Block};
                false -> {error, merkle_mismatch}
            end
    end.

%% Verify the reconstructed block's merkle root
verify_merkle_root(#block{header = Header, transactions = Txs}) ->
    ExpectedRoot = Header#block_header.merkle_root,
    TxHashes = [beamchain_serialize:tx_hash(Tx) || Tx <- Txs],
    ComputedRoot = beamchain_serialize:compute_merkle_root(TxHashes),
    ExpectedRoot =:= ComputedRoot.
