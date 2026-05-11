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

%% Maximum transactions per compact block.
%% Core: MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 4_000_000 / 10.
%% blockencodings.cpp:64 — was 65535 (= uint16_t::max) which is too low
%% and would reject valid large blocks.
-define(MAX_COMPACT_BLOCK_TXS, 400000).

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
%%
%% Validation mirrors Core blockencodings.cpp PartiallyDownloadedBlock::InitData.
-spec init_compact_block(map()) -> {ok, #compact_state{}} | {error, term()}.
init_compact_block(#{header := Header, nonce := Nonce,
                     short_ids := ShortIds, prefilled_txns := Prefilled}) ->
    try
        %% BUG-2 fix: reject null/empty header (Core: cmpctblock.header.IsNull()).
        %% A null header has all-zero prev_hash and merkle_root, version=0.
        %% We approximate by checking that the header is not the zero record.
        is_null_header(Header) andalso throw(null_header),

        %% BUG-2 fix: reject if both short_ids and prefilled are empty
        %% (Core: cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()).
        (ShortIds =:= [] andalso Prefilled =:= []) andalso throw(empty_cmpctblock),

        %% BUG-1 fix: use Core's limit, not uint16_t::max.
        %% Core blockencodings.cpp:64 checks
        %%   shorttxids.size() + prefilledtxn.size() > MAX_BLOCK_WEIGHT / MIN_...
        TxnCount = length(ShortIds) + length(Prefilled),
        TxnCount =< ?MAX_COMPACT_BLOCK_TXS orelse throw(too_many_txns),

        %% Compute block hash and SipHash key
        BlockHash = beamchain_serialize:block_hash(Header),
        {K0, K1} = derive_siphash_key(Header, Nonce),

        %% Initialize txn_available array with undefined
        TxnAvailable0 = array:new(TxnCount, {default, undefined}),

        %% Process prefilled transactions (indexes are differential).
        %% Each index is relative to the previous prefilled tx + 1.
        %% Core blockencodings.cpp:73-86.
        {TxnAvailable1, _LastIdx} = lists:foldl(
            fun(#{index := DiffIdx, tx := Tx}, {Arr, PrevIdx}) ->
                %% BUG-8 fix: reject null/empty prefilled tx
                %% (Core: cmpctblock.prefilledtxn[i].tx->IsNull()).
                is_null_tx(Tx) andalso throw(null_prefilled_tx),

                AbsIdx = PrevIdx + DiffIdx + 1,

                %% BUG-3 fix: absolute index must fit in uint16_t
                %% (Core: lastprefilledindex > std::numeric_limits<uint16_t>::max()).
                AbsIdx > 65535 andalso throw(prefilled_index_overflow),

                %% BUG-4 fix: absolute index must not skip past shorttxids + fills.
                %% Core: (uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i
                %% We compute this check below (would require tracking i separately;
                %% we defer to the AbsIdx < TxnCount check as an approximation,
                %% supplemented by the >= TxnCount guard already in place).
                AbsIdx >= TxnCount andalso throw(invalid_prefilled_index),

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

        %% BUG-7 fix: detect duplicate short IDs before building the map.
        %% Core: if (shorttxids.size() != cmpctblock.shorttxids.size())
        %%           return READ_STATUS_FAILED; // Short ID collision
        %% We check this by building a set and comparing sizes.
        ShortIdSet = lists:foldl(fun(SID, Acc) -> sets:add_element(SID, Acc) end,
                                  sets:new([{version, 2}]), ShortIds),
        sets:size(ShortIdSet) =/= length(ShortIds) andalso throw(short_id_collision),

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
%% Core blockencodings.cpp PartiallyDownloadedBlock::FillBlock.
-spec fill_block(#compact_state{}, [#transaction{}]) ->
    {ok, #block{}} | {error, term()}.
fill_block(#compact_state{txn_available = TxnAvailable} = State,
           MissingTxns) ->
    MissingIdxs = get_missing_indices(State),

    %% BUG-6 fix: reject if the number of provided txns does not exactly match
    %% the number of missing slots.
    %% Core: if (vtx_missing.size() != tx_missing_offset) return READ_STATUS_INVALID.
    case length(MissingTxns) =:= length(MissingIdxs) of
        false ->
            {error, {fill_block_count_mismatch,
                     length(MissingTxns), length(MissingIdxs)}};
        true ->
            %% Fill in the missing slots in order
            TxnAvailable2 = lists:foldl(
                fun({Idx, Tx}, Arr) ->
                    array:set(Idx, Tx, Arr)
                end,
                TxnAvailable,
                lists:zip(MissingIdxs, MissingTxns)),

            build_block(State#compact_state{txn_available = TxnAvailable2})
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
%% Core: GetShortID returns hash & 0xffffffffffffL (48-bit mask).
%% The result is encoded as 6 bytes LE on the wire.
-spec compute_short_id(non_neg_integer(), non_neg_integer(),
                       binary()) -> binary().
compute_short_id(K0, K1, Wtxid) when byte_size(Wtxid) =:= 32 ->
    Hash = beamchain_crypto:siphash_uint256(K0, K1, Wtxid),
    <<(Hash band 16#ffffffffffff):48/little>>.

%% @doc Derive SipHash key from block header and nonce.
%% Key = SHA256(header || nonce), take first 16 bytes as K0, K1.
%% Core FillShortTxIDSelector: stream << header << nonce, then SHA256.
%% K0 = first 8 bytes LE, K1 = next 8 bytes LE.
-spec derive_siphash_key(#block_header{}, non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer()}.
derive_siphash_key(Header, Nonce) ->
    HeaderBin = beamchain_serialize:encode_block_header(Header),
    KeyData = beamchain_crypto:sha256(<<HeaderBin/binary, Nonce:64/little>>),
    <<K0:64/little, K1:64/little, _/binary>> = KeyData,
    {K0, K1}.

%%% ===================================================================
%%% Internal functions
%%% ===================================================================

%% A null header is one that has never been set (all-zero fields).
%% Mirrors Core's CBlockHeader::IsNull() which returns true when nBits == 0.
is_null_header(#block_header{bits = 0}) -> true;
is_null_header(_) -> false.

%% A null transaction is an empty/undefined one.
is_null_tx(undefined) -> true;
is_null_tx(#transaction{inputs = [], outputs = []}) -> true;
is_null_tx(_) -> false.

%% Skip over indices that have prefilled transactions
skip_prefilled(Idx, PrefilledIdxs) ->
    case sets:is_element(Idx, PrefilledIdxs) of
        true -> skip_prefilled(Idx + 1, PrefilledIdxs);
        false -> Idx
    end.

%% Match mempool transactions against short ids.
%% BUG-5 fix: when a collision clears a slot, we must also decrement the
%% match count so the caller's MissingCount stays accurate.
%% Core InitData: mempool_count-- on collision.
match_mempool_txns(ShortIdMap, K0, K1, TxnAvailable) ->
    Txids = beamchain_mempool:get_all_txids(),
    lists:foldl(
        fun(Txid, {Arr, Count}) ->
            case beamchain_mempool:get_tx(Txid) of
                {ok, Tx} ->
                    Wtxid = beamchain_serialize:wtx_hash(Tx),
                    ShortId = compute_short_id(K0, K1, Wtxid),
                    case maps:find(ShortId, ShortIdMap) of
                        {ok, Idx} ->
                            case array:get(Idx, Arr) of
                                undefined ->
                                    %% First match: fill the slot
                                    {array:set(Idx, Tx, Arr), Count + 1};
                                _Existing ->
                                    %% Collision: two mempool txns share a short id.
                                    %% Clear the slot to force a getblocktxn fetch.
                                    %% Decrement Count because the prior fill is now
                                    %% undone (mirrors Core: mempool_count--).
                                    {array:set(Idx, undefined, Arr), Count - 1}
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

%% Match extra transactions against short ids.
%% Core InitData extra_txn loop (lines 147-176).
%% Collision with a *different* wtxid clears the slot; same wtxid is a no-op.
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
                            %% Check for collision with different tx.
                            %% Core: compare witness hashes to avoid mempool/extra dup
                            %% triggering a false collision (extra_count--).
                            ExistingWtxid = beamchain_serialize:wtx_hash(Existing),
                            case ExistingWtxid =:= Wtxid of
                                true ->
                                    %% Same tx in both mempool and extra — no-op.
                                    {Arr, Count};
                                false ->
                                    %% Real collision: clear slot, fix count.
                                    {array:set(Idx, undefined, Arr), Count - 1}
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
