-module(beamchain_miner).
-behaviour(gen_server).

%% Block template construction and mining support.
%% Implements getblocktemplate (BIP 22/23) and submitblock.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Dialyzer suppressions for false positives:
%% build_coinbase/5, build_coinbase_for_txs/6: Height=0 is a defensive
%%   base case; dialyzer infers Height::pos_integer() from call sites.
%% encode_coinbase_height/1: same reasoning for the Height=0 clause.
-dialyzer({nowarn_function, [build_coinbase/5, build_coinbase_for_txs/5,
                              encode_coinbase_height/1]}).

%% API
-export([start_link/0]).
-export([create_block_template/1, create_block_template/2]).
-export([submit_block/1]).
-export([generate_blocks/3, generate_block_with_txs/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% BUG1 FIX: Core policy/policy.h DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 WU.
%% Reserved for block header (80 B * 4 = 320 WU), tx-count varint, and
%% coinbase tx.  The old value of 4000 allowed ~4000 extra WU of transactions,
%% potentially producing overweight blocks.
%% Core: node/miner.cpp resetBlock() — nBlockWeight = *block_reserved_weight.
-define(DEFAULT_BLOCK_RESERVED_WEIGHT, 8000).

%% BUG6 FIX: Core policy/policy.h DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS = 400.
%% This sigop budget is pre-reserved (subtracted from MAX_BLOCK_SIGOPS_COST before
%% greedy selection) to account for coinbase output scriptPubKeys.
%% Core: node/miner.cpp resetBlock() — nBlockSigOpsCost = coinbase_output_max_additional_sigops.
-define(DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS, 400).

%% BUG3 FIX: Core node/miner.cpp addChunks() early-exit constants.
%% After MAX_CONSECUTIVE_FAILURES consecutive rejections AND the block is within
%% BLOCK_FULL_ENOUGH_WEIGHT_DELTA WU of the limit, give up (block is essentially full).
-define(MAX_CONSECUTIVE_FAILURES, 1000).
-define(BLOCK_FULL_ENOUGH_WEIGHT_DELTA, 4000).

%% BUG4 FIX: Core policy/policy.h DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB.
%% Transactions below this fee rate are skipped during block assembly.
%% Exposed as -blockmintxfee option in Core; we use the same default.
-define(DEFAULT_BLOCK_MIN_TX_FEE_SAT_KVBYTE, 1).

%% BUG8 FIX: BIP94 timewarp rule — at difficulty-adjustment boundaries the
%% block timestamp must be >= prev_block_time - MAX_TIMEWARP (600 seconds).
%% Core: consensus/consensus.h MAX_TIMEWARP = 600.
-define(MAX_TIMEWARP, 600).

%% Re-define mempool_entry record (internal to beamchain_mempool)
-record(mempool_entry, {
    txid, wtxid, tx, fee, size, vsize, weight, fee_rate,
    time_added, height_added,
    ancestor_count, ancestor_size, ancestor_fee,
    descendant_count, descendant_size, descendant_fee,
    spends_coinbase, rbf_signaling
}).

-record(state, {
    params    :: map(),
    network   :: atom(),
    template  :: map() | undefined,
    tip_hash  :: binary() | undefined
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Create a block template for mining.
%% CoinbaseScriptPubKey is the scriptPubKey for the coinbase payout.
-spec create_block_template(binary()) -> {ok, map()} | {error, term()}.
create_block_template(CoinbaseScriptPubKey) ->
    create_block_template(CoinbaseScriptPubKey, #{}).

-spec create_block_template(binary(), map()) -> {ok, map()} | {error, term()}.
create_block_template(CoinbaseScriptPubKey, Opts) ->
    gen_server:call(?SERVER, {create_template, CoinbaseScriptPubKey, Opts}, 30000).

%% @doc Submit a mined block (hex-encoded serialized block).
-spec submit_block(binary()) -> ok | {error, term()}.
submit_block(HexBlock) ->
    gen_server:call(?SERVER, {submit_block, HexBlock}, 60000).

%% @doc Generate N blocks with coinbase paying to given scriptPubKey.
%% Only works on regtest. Returns list of block hashes (hex strings).
-spec generate_blocks(binary(), non_neg_integer(), non_neg_integer()) ->
    {ok, [binary()]} | {error, term()}.
generate_blocks(CoinbaseScript, NumBlocks, MaxTries) ->
    gen_server:call(?SERVER, {generate_blocks, CoinbaseScript, NumBlocks, MaxTries},
                    NumBlocks * 60000 + 30000).

%% @doc Generate a single block with specific transactions.
%% Only works on regtest. Returns {hash, hex} if submit=false, else just {hash}.
-spec generate_block_with_txs(binary(), [#transaction{}], boolean()) ->
    {ok, map()} | {error, term()}.
generate_block_with_txs(CoinbaseScript, Txs, Submit) ->
    gen_server:call(?SERVER, {generate_block_with_txs, CoinbaseScript, Txs, Submit}, 60000).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    Network = beamchain_config:network(),
    Params = beamchain_chain_params:params(Network),
    logger:info("miner: initialized for ~s", [Network]),
    {ok, #state{
        params = Params,
        network = Network,
        template = undefined,
        tip_hash = undefined
    }}.

handle_call({create_template, CoinbaseScriptPubKey, Opts}, _From, State) ->
    case do_create_template(CoinbaseScriptPubKey, Opts, State) of
        {ok, Template, State2} ->
            {reply, {ok, Template}, State2};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({submit_block, HexBlock}, _From, State) ->
    Result = do_submit_block(HexBlock),
    %% Invalidate cached template on success
    State2 = case Result of
        ok -> State#state{template = undefined};
        _ -> State
    end,
    {reply, Result, State2};

handle_call({generate_blocks, CoinbaseScript, NumBlocks, MaxTries}, _From, State) ->
    %% Only allowed on regtest
    case State#state.network of
        regtest ->
            Result = do_generate_blocks(CoinbaseScript, NumBlocks, MaxTries, State),
            State2 = State#state{template = undefined},
            {reply, Result, State2};
        _ ->
            {reply, {error, not_regtest}, State}
    end;

handle_call({generate_block_with_txs, CoinbaseScript, Txs, Submit}, _From, State) ->
    %% Only allowed on regtest
    case State#state.network of
        regtest ->
            Result = do_generate_block_with_txs(CoinbaseScript, Txs, Submit, State),
            State2 = State#state{template = undefined},
            {reply, Result, State2};
        _ ->
            {reply, {error, not_regtest}, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%% ===================================================================
%%% Internal: create block template
%%% ===================================================================

do_create_template(CoinbaseScriptPubKey, _Opts,
                   #state{params = Params, network = Network} = State) ->
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            Height = TipHeight + 1,
            MTP = beamchain_chainstate:get_mtp(),

            %% Compute required difficulty for the next block
            PrevIndex = get_prev_index(TipHeight),
            Now = erlang:system_time(second),

            %% BUG8 FIX: apply BIP94 timewarp rule at difficulty-adjustment
            %% boundaries.  At height H where H mod 2016 == 0, the timestamp
            %% must be >= prev_block_time - 600 seconds.
            %% Core: node/miner.cpp GetMinimumTime() + UpdateTime().
            PrevBlockTime = case PrevIndex of
                #{header := #block_header{timestamp = T}} -> T;
                _ -> MTP  %% fallback: no worse than MTP
            end,
            MinTime = compute_minimum_time(MTP, PrevBlockTime, Height),

            DummyHeader = #block_header{
                version = 16#20000000,
                prev_hash = TipHash,
                merkle_root = <<0:256>>,
                timestamp = max(MinTime, Now),
                bits = 0,
                nonce = 0
            },
            Bits = beamchain_pow:get_next_work_required(
                PrevIndex, DummyHeader, Params),

            %% BUG8 FIX: on testnet (fPowAllowMinDifficultyBlocks), nBits may
            %% be recalculated when timestamp advances — already done above via
            %% DummyHeader.  For testnet the difficulty can drop to min if time
            %% gap > 20 min, so use the updated nBits from get_next_work_required.

            %% BUG5 FIX: use compute_block_version to signal BIP9 deployments.
            %% Core: node/miner.cpp CreateNewBlock() line 140.
            Version = beamchain_versionbits:compute_block_version(
                TipHeight, Params),

            %% Select transactions from mempool (BUG2 fix: pass lock_time_cutoff=MTP)
            {SelectedEntries, TotalFees, TotalWeight, TotalSigops} =
                select_transactions(MTP, Height),

            %% Block subsidy + fees
            Subsidy = beamchain_chain_params:block_subsidy(Height, Network),
            CoinbaseValue = Subsidy + TotalFees,

            %% Check if any selected tx has witness data
            HasWitnessTx = lists:any(fun(E) ->
                has_witness(E#mempool_entry.tx)
            end, SelectedEntries),

            %% Build coinbase
            CoinbaseTx = build_coinbase(Height, CoinbaseScriptPubKey,
                                         CoinbaseValue, HasWitnessTx,
                                         SelectedEntries),

            %% Assemble full transaction list
            AllTxs = [CoinbaseTx |
                      [E#mempool_entry.tx || E <- SelectedEntries]],

            %% Compute merkle root
            TxHashes = [beamchain_serialize:tx_hash(Tx) || Tx <- AllTxs],
            MerkleRoot = beamchain_serialize:compute_merkle_root(TxHashes),

            %% BUG8 FIX: timestamp is max(GetMinimumTime(), now).
            %% GetMinimumTime = max(MTP+1, BIP94 boundary check).
            Timestamp = max(MinTime, Now),

            %% Assemble block header
            Header = #block_header{
                version = Version,
                prev_hash = TipHash,
                merkle_root = MerkleRoot,
                timestamp = Timestamp,
                bits = Bits,
                nonce = 0
            },

            %% BIP 22 response
            Target = beamchain_pow:bits_to_target(Bits),
            TxEntries = format_tx_entries(SelectedEntries),

            Template = #{
                <<"version">> => Version,
                <<"previousblockhash">> => hash_to_hex(TipHash),
                <<"transactions">> => TxEntries,
                <<"coinbaseaux">> => #{<<"flags">> => <<>>},
                <<"coinbasevalue">> => CoinbaseValue,
                <<"target">> => target_to_hex(Target),
                <<"mintime">> => MTP + 1,
                <<"mutable">> => [<<"time">>, <<"transactions">>,
                                  <<"prevblock">>],
                <<"noncerange">> => <<"00000000ffffffff">>,
                <<"sigoplimit">> => ?MAX_BLOCK_SIGOPS_COST,
                <<"sizelimit">> => ?MAX_BLOCK_SERIALIZED_SIZE,
                <<"weightlimit">> => ?MAX_BLOCK_WEIGHT,
                <<"curtime">> => Timestamp,
                <<"bits">> => bits_to_hex(Bits),
                <<"height">> => Height,
                %% internal fields for our own use
                <<"_header">> => Header,
                <<"_coinbase_tx">> => CoinbaseTx,
                <<"_all_txs">> => AllTxs,
                <<"_total_weight">> => TotalWeight,
                <<"_total_sigops">> => TotalSigops
            },

            State2 = State#state{template = Template, tip_hash = TipHash},
            {ok, Template, State2};

        not_found ->
            {error, no_chain_tip}
    end.

get_prev_index(TipHeight) ->
    case beamchain_db:get_block_index(TipHeight) of
        {ok, PI} -> PI;
        not_found -> error({missing_block_index, TipHeight})
    end.

%% BUG8 FIX: compute_minimum_time/3 — equivalent of Core's GetMinimumTime().
%%
%% The minimum timestamp for the next block is:
%%   max(MTP + 1,
%%       [at difficulty-adjustment boundary] prev_block_time - MAX_TIMEWARP)
%%
%% BIP94 (timewarp fix, active on all networks since Core 28.x):
%% At every difficulty-adjustment boundary (height mod 2016 == 0) the
%% timestamp must be >= pindexPrev->GetBlockTime() - MAX_TIMEWARP (600s).
%% This prevents the time-warp attack by bounding how far back a miner
%% can retroactively set the timestamp.
%%
%% Core: node/miner.cpp GetMinimumTime()
-spec compute_minimum_time(non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    non_neg_integer().
compute_minimum_time(MTP, PrevBlockTime, Height) ->
    MinFromMTP = MTP + 1,
    case Height rem ?DIFFICULTY_ADJUSTMENT_INTERVAL of
        0 ->
            %% At a difficulty-adjustment boundary: apply BIP94 timewarp check.
            MinFromTimewarp = PrevBlockTime - ?MAX_TIMEWARP,
            max(MinFromMTP, MinFromTimewarp);
        _ ->
            MinFromMTP
    end.

has_witness(#transaction{inputs = Inputs}) ->
    lists:any(fun(#tx_in{witness = W}) ->
        W =/= [] andalso W =/= undefined
    end, Inputs).

%%% ===================================================================
%%% Internal: BIP 22 transaction entry formatting
%%% ===================================================================

format_tx_entries(Entries) ->
    format_tx_entries(Entries, 1, #{}, []).

format_tx_entries([], _Idx, _IdxMap, Acc) ->
    lists:reverse(Acc);
format_tx_entries([Entry | Rest], Idx, IdxMap, Acc) ->
    Tx = Entry#mempool_entry.tx,
    Txid = Entry#mempool_entry.txid,
    Wtxid = Entry#mempool_entry.wtxid,

    %% Serialize the transaction
    TxHex = beamchain_serialize:hex_encode(
        beamchain_serialize:encode_transaction(Tx)),

    %% Find in-template parent indices
    Depends = lists:filtermap(
        fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
            case maps:find(H, IdxMap) of
                {ok, ParentIdx} -> {true, ParentIdx};
                error -> false
            end
        end, Tx#transaction.inputs),

    TxEntry = #{
        <<"data">> => TxHex,
        <<"txid">> => hash_to_hex(Txid),
        <<"hash">> => hash_to_hex(Wtxid),
        <<"fee">> => Entry#mempool_entry.fee,
        <<"sigops">> => estimate_sigops(Tx),
        <<"weight">> => Entry#mempool_entry.weight,
        <<"depends">> => lists:usort(Depends)
    },

    IdxMap2 = maps:put(Txid, Idx, IdxMap),
    format_tx_entries(Rest, Idx + 1, IdxMap2, [TxEntry | Acc]).

%%% ===================================================================
%%% Internal: hex/hash helpers
%%% ===================================================================

%% Display-order hex: reversed bytes then hex-encoded.
hash_to_hex(Hash) when byte_size(Hash) =:= 32 ->
    beamchain_serialize:hex_encode(
        beamchain_serialize:reverse_bytes(Hash)).

bits_to_hex(Bits) ->
    beamchain_serialize:hex_encode(<<Bits:32/big>>).

target_to_hex(Target) ->
    beamchain_serialize:hex_encode(<<Target:256/big>>).

short_hex(<<H:4/binary, _/binary>>) ->
    beamchain_serialize:hex_encode(H);
short_hex(Other) ->
    beamchain_serialize:hex_encode(Other).

%%% ===================================================================
%%% Internal: submit block
%%% ===================================================================

do_submit_block(HexBlock) ->
    try
        %% 1. decode hex to binary
        BlockBin = beamchain_serialize:hex_decode(HexBlock),

        %% 2. deserialize block
        {Block, _Rest} = beamchain_serialize:decode_block(BlockBin),

        %% 3. context-free block checks (PoW, merkle root, sigops, weight).
        %% Mirrors Bitcoin Core CheckBlock() in validation.cpp — in particular
        %% the BlockMerkleRoot() recomputation that catches bad-txnmrklroot.
        %% This step was previously missing from the submitblock path (unlike
        %% the block-sync path which always called check_block/2 first).
        Params = beamchain_chain_params:params(beamchain_config:network()),
        case beamchain_validation:check_block(Block, Params) of
            ok ->
                %% 4. submit_block decouples acceptance (block_index +
                %% storage) from best-chain selection (UTXO connect +
                %% tip flip).  Side-branch blocks are persisted and
                %% become reorg candidates rather than being silently
                %% dropped.  See chainstate:submit_block/1 docstring +
                %% CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md.
                case beamchain_chainstate:submit_block(Block) of
                    {ok, Outcome} when Outcome =:= active;
                                       Outcome =:= reorg ->
                        %% Active-chain advance (either direct extension
                        %% or a reorg flip).  Mempool + announce as
                        %% before.
                        Txids = [beamchain_serialize:tx_hash(Tx)
                                 || Tx <- Block#block.transactions],
                        beamchain_mempool:remove_for_block(Txids),

                        BlockHash = beamchain_serialize:block_hash(
                            Block#block.header),
                        broadcast_new_block(Block#block.header, BlockHash),

                        logger:info("miner: accepted block ~s (~p)",
                                    [short_hex(BlockHash), Outcome]),
                        ok;
                    {ok, side_branch} ->
                        %% Block stored as side-branch — no tip flip,
                        %% no mempool churn, no broadcast.  Surface as
                        %% BIP-22 "inconclusive" via the rpc_submitblock
                        %% layer.  Mirrors Bitcoin Core
                        %% rpc/mining.cpp::submitblock returning
                        %% "inconclusive" for stored-but-not-active
                        %% blocks.
                        BlockHash = beamchain_serialize:block_hash(
                            Block#block.header),
                        logger:info("miner: stored block ~s "
                                    "as side-branch (inconclusive)",
                                    [short_hex(BlockHash)]),
                        {error, inconclusive};
                    {error, Reason} ->
                        logger:warning("miner: rejected block: ~p", [Reason]),
                        {error, Reason}
                end;
            {error, CheckErr} ->
                logger:warning("miner: rejected block (check_block): ~p",
                               [CheckErr]),
                {error, CheckErr}
        end
    catch
        error:Reason2 ->
            logger:warning("miner: submit_block error: ~p", [Reason2]),
            {error, Reason2}
    end.

%% Broadcast a newly mined block to all connected peers, branching on
%% BIP-130 sendheaders. Peers that opted into header announces receive a
%% `headers` push; others fall back to `inv`. See
%% beamchain_peer_manager:announce_block/2.
broadcast_new_block(Header, BlockHash) ->
    try
        beamchain_peer_manager:announce_block(Header, BlockHash)
    catch
        _:_ -> ok   %% peer manager may not be running
    end.

%%% ===================================================================
%%% Internal: transaction selection
%%% ===================================================================

%% Select transactions from the mempool for inclusion in a block.
%% Sorts by ancestor fee rate (CPFP-aware), then greedily fills the
%% block respecting weight and sigop limits. Returns a topologically
%% ordered list of entries (parents before children).
%%
%% LockTimeCutoff = MTP of tip (for IsFinalTx), Height = next block height.
select_transactions(LockTimeCutoff, Height) ->
    %% Get all mempool entries sorted by fee rate (highest first)
    Entries = beamchain_mempool:get_sorted_by_fee(),

    %% Re-sort by ancestor fee rate for CPFP
    %% ancestor_fee_rate = (tx fee + ancestor fees) / (tx weight + ancestor weight)
    %% We use weight directly for more accurate fee rate comparison
    Sorted = lists:sort(fun(A, B) ->
        ancestor_fee_rate(A) >= ancestor_fee_rate(B)
    end, Entries),

    %% BUG1 FIX: nBlockWeight starts at DEFAULT_BLOCK_RESERVED_WEIGHT (8000),
    %% not zero.  The available budget for tx data is thus MAX - 8000.
    %% Core: node/miner.cpp resetBlock() + addChunks() TestChunkBlockLimits.
    MaxWeight = ?MAX_BLOCK_WEIGHT - ?DEFAULT_BLOCK_RESERVED_WEIGHT,

    %% BUG6 FIX: pre-reserve sigop budget for coinbase outputs.
    %% Core: resetBlock() nBlockSigOpsCost = coinbase_output_max_additional_sigops (400).
    MaxSigops = ?MAX_BLOCK_SIGOPS_COST - ?DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS,

    {Selected, Fees, Weight, Sigops} =
        greedy_select(Sorted, MaxWeight, MaxSigops,
                      LockTimeCutoff, Height,
                      sets:new([{version, 2}]), [], 0, 0, 0, 0),

    %% Topological sort so parents appear before children
    Ordered = topological_sort(Selected),
    {Ordered, Fees, Weight, Sigops}.

%% Calculate ancestor fee rate in sat/WU for accurate comparison.
%% Uses weight (not vsize) for proper SegWit fee rate comparison.
%% ancestor_fee_rate = (tx fee + ancestor fees) / (tx weight + ancestor weight)
ancestor_fee_rate(Entry) ->
    %% ancestor_fee and weight already include the tx's own values
    %% (set in beamchain_mempool:compute_ancestors)
    AncFee = Entry#mempool_entry.ancestor_fee,
    %% Convert ancestor_size (vsize) to weight approximation
    %% This is a simplification - for truly accurate results we'd track
    %% ancestor_weight separately, but vsize*4 is a reasonable upper bound
    AncWeight = Entry#mempool_entry.ancestor_size * ?WITNESS_SCALE_FACTOR,
    case AncWeight of
        0 -> Entry#mempool_entry.fee / max(1, Entry#mempool_entry.weight);
        _ -> AncFee / AncWeight
    end.

%%% ===================================================================
%%% Internal: greedy block filling
%%% ===================================================================

%% greedy_select/11: BUG3 FIX — MAX_CONSECUTIVE_FAILURES early-exit added.
%% After 1000 consecutive skips while the block is within 4000 WU of the
%% limit, give up (block is essentially full, further iteration is wasteful).
%% Core: node/miner.cpp addChunks() — nConsecutiveFailed + BLOCK_FULL_ENOUGH.
%%
%% BUG2 FIX — IsFinalTx check per entry.  m_lock_time_cutoff = MTP of tip.
%% Core: node/miner.cpp TestChunkTransactions() — IsFinalTx(tx, nHeight, cutoff).
%%
%% BUG4 FIX — blockMinFeeRate check: entries below DEFAULT_BLOCK_MIN_TX_FEE
%% (1 sat/kvB) are skipped; the sorted order means once we hit one below the
%% threshold the rest will also be below (unless ancestor pulls them up), but
%% we still check per-entry for correctness.
%% Core: node/miner.cpp addChunks() — chunk_feerate_vsize << blockMinFeeRate.
%%
%% BUG7 FIX — weight limit is >= (not >).
%% Core: TestChunkBlockLimits() — nBlockWeight + size >= nBlockMaxWeight.
greedy_select([], _MaxW, _MaxS, _LTC, _H, _Seen, Acc, Fees, Weight, Sigops, _ConsecFail) ->
    {lists:reverse(Acc), Fees, Weight, Sigops};
greedy_select(_Entries, _MaxW, _MaxS, _LTC, _H, _Seen, Acc, Fees, Weight, Sigops, ConsecFail)
  when ConsecFail > ?MAX_CONSECUTIVE_FAILURES,
       Weight + ?BLOCK_FULL_ENOUGH_WEIGHT_DELTA > ?MAX_BLOCK_WEIGHT - ?DEFAULT_BLOCK_RESERVED_WEIGHT ->
    %% BUG3 FIX: block is full enough and we've had many failures in a row.
    {lists:reverse(Acc), Fees, Weight, Sigops};
greedy_select([Entry | Rest], MaxW, MaxS, LockTimeCutoff, Height, Seen, Acc,
              Fees, Weight, Sigops, ConsecFail) ->
    Txid = Entry#mempool_entry.txid,

    %% Skip if already selected (pulled in as a dependency)
    case sets:is_element(Txid, Seen) of
        true ->
            greedy_select(Rest, MaxW, MaxS, LockTimeCutoff, Height, Seen, Acc,
                          Fees, Weight, Sigops, ConsecFail);
        false ->
            %% BUG4 FIX: blockMinFeeRate gate — skip below-minimum-fee entries.
            %% fee_rate in sat/kvB = fee * 1000 / vsize.
            FeeRateSatKvb = case Entry#mempool_entry.vsize of
                0 -> 0;
                VS -> Entry#mempool_entry.fee * 1000 div VS
            end,
            case FeeRateSatKvb < ?DEFAULT_BLOCK_MIN_TX_FEE_SAT_KVBYTE of
                true ->
                    %% Below minimum fee rate, skip (sorted list: subsequent may differ
                    %% in ancestor fee rate, so we skip rather than early-exit).
                    greedy_select(Rest, MaxW, MaxS, LockTimeCutoff, Height, Seen, Acc,
                                  Fees, Weight, Sigops, ConsecFail + 1);
                false ->
                    %% BUG2 FIX: IsFinalTx check — non-final txs must not enter template.
                    %% Core: TestChunkTransactions() IsFinalTx(tx, nHeight, m_lock_time_cutoff).
                    TxFinal = beamchain_validation:is_final_tx(
                        Entry#mempool_entry.tx, Height, LockTimeCutoff),

                    case TxFinal of
                        false ->
                            %% Non-final: skip but do not count as a block-filling failure
                            greedy_select(Rest, MaxW, MaxS, LockTimeCutoff, Height, Seen, Acc,
                                          Fees, Weight, Sigops, ConsecFail + 1);
                        true ->
                            TxWeight = Entry#mempool_entry.weight,
                            TxSigops = estimate_sigops(Entry#mempool_entry.tx),

                            %% Resolve parent txs that are still in mempool
                            {Parents, Seen2} = resolve_parents(
                                Entry#mempool_entry.tx, Seen),
                            ParentWeight = lists:foldl(fun(PE, W) ->
                                W + PE#mempool_entry.weight
                            end, 0, Parents),
                            ParentFees = lists:foldl(fun(PE, F) ->
                                F + PE#mempool_entry.fee
                            end, 0, Parents),
                            ParentSigops = lists:foldl(fun(PE, S) ->
                                S + estimate_sigops(PE#mempool_entry.tx)
                            end, 0, Parents),

                            TotalNewWeight = TxWeight + ParentWeight,
                            NewWeight = Weight + TotalNewWeight,
                            %% BUG7 FIX: use >= not > (Core TestChunkBlockLimits).
                            NewSigops = Sigops + TxSigops + ParentSigops,

                            case NewWeight >= MaxW orelse NewSigops >= MaxS of
                                true ->
                                    %% Doesn't fit, try next — count as a failure
                                    greedy_select(Rest, MaxW, MaxS, LockTimeCutoff, Height, Seen, Acc,
                                                  Fees, Weight, Sigops, ConsecFail + 1);
                                false ->
                                    AllNew = Parents ++ [Entry],
                                    Seen3 = lists:foldl(fun(E, S) ->
                                        sets:add_element(E#mempool_entry.txid, S)
                                    end, Seen2, AllNew),
                                    greedy_select(
                                        Rest, MaxW, MaxS, LockTimeCutoff, Height, Seen3,
                                        AllNew ++ Acc,
                                        Fees + Entry#mempool_entry.fee + ParentFees,
                                        NewWeight, NewSigops, 0)
                            end
                    end
            end
    end.

%% Recursively resolve unselected mempool parents.
resolve_parents(#transaction{inputs = Inputs}, AlreadySelected) ->
    ParentTxids = lists:usort(lists:filtermap(
        fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
            case beamchain_mempool:has_tx(H) of
                true ->
                    case sets:is_element(H, AlreadySelected) of
                        true -> false;
                        false -> {true, H}
                    end;
                false -> false
            end
        end, Inputs)),

    lists:foldl(fun(PTxid, {Ents, Sel}) ->
        case beamchain_mempool:get_entry(PTxid) of
            {ok, PE} ->
                %% Resolve grandparents first
                {GrandParents, Sel2} =
                    resolve_parents(PE#mempool_entry.tx, Sel),
                Sel3 = sets:add_element(PTxid, Sel2),
                {Ents ++ GrandParents ++ [PE], Sel3};
            not_found ->
                {Ents, Sel}
        end
    end, {[], AlreadySelected}, ParentTxids).

%% Estimate sigops for a tx (legacy count * witness scale factor).
%% This is a conservative estimate used for block filling, not consensus.
estimate_sigops(#transaction{inputs = Inputs, outputs = Outputs}) ->
    InSigops = lists:foldl(fun(#tx_in{script_sig = S}, Acc) ->
        Acc + beamchain_validation:count_legacy_sigops(S)
    end, 0, Inputs),
    OutSigops = lists:foldl(fun(#tx_out{script_pubkey = S}, Acc) ->
        Acc + beamchain_validation:count_legacy_sigops(S)
    end, 0, Outputs),
    (InSigops + OutSigops) * ?WITNESS_SCALE_FACTOR.

%%% ===================================================================
%%% Internal: topological sort (Kahn's algorithm)
%%% ===================================================================

%% Sort entries so that parent transactions appear before children.
topological_sort(Entries) ->
    TxMap = maps:from_list(
        [{E#mempool_entry.txid, E} || E <- Entries]),
    TxidSet = sets:from_list(maps:keys(TxMap), [{version, 2}]),

    %% Build in-degree map and children adjacency
    {InDegree, Children} = lists:foldl(fun(E, {InD, Ch}) ->
        Txid = E#mempool_entry.txid,
        Parents = in_block_parents(E#mempool_entry.tx, TxidSet),
        InD2 = maps:put(Txid, length(Parents), InD),
        Ch2 = lists:foldl(fun(P, C) ->
            maps:update_with(P,
                fun(Existing) -> [Txid | Existing] end,
                [Txid], C)
        end, Ch, Parents),
        {InD2, Ch2}
    end, {#{}, #{}}, Entries),

    %% Start with zero in-degree nodes
    Queue = [Txid || Txid <- maps:keys(TxMap),
                     maps:get(Txid, InDegree, 0) =:= 0],
    topo_loop(Queue, InDegree, Children, TxMap, []).

topo_loop([], _InDegree, _Children, _TxMap, Acc) ->
    lists:reverse(Acc);
topo_loop([Txid | Rest], InDegree, Children, TxMap, Acc) ->
    Entry = maps:get(Txid, TxMap),
    ChildList = maps:get(Txid, Children, []),
    {NewQueue, InDegree2} = lists:foldl(fun(Child, {Q, ID}) ->
        NewDeg = maps:get(Child, ID, 1) - 1,
        ID2 = maps:put(Child, NewDeg, ID),
        case NewDeg of
            0 -> {Q ++ [Child], ID2};
            _ -> {Q, ID2}
        end
    end, {Rest, InDegree}, ChildList),
    topo_loop(NewQueue, InDegree2, Children, TxMap, [Entry | Acc]).

%% Get parent txids of a tx that are in the selected set.
in_block_parents(#transaction{inputs = Inputs}, TxidSet) ->
    lists:usort(lists:filtermap(
        fun(#tx_in{prev_out = #outpoint{hash = H}}) ->
            case sets:is_element(H, TxidSet) of
                true -> {true, H};
                false -> false
            end
        end, Inputs)).

%%% ===================================================================
%%% Internal: coinbase transaction
%%% ===================================================================

%% Build the coinbase transaction for a block template.
%% Includes BIP 34 height encoding and (if needed) witness commitment.
build_coinbase(Height, CoinbaseScriptPubKey, CoinbaseValue,
               HasWitnessTx, SelectedEntries) ->
    %% BIP 34: encode block height in scriptSig
    HeightScript = encode_coinbase_height(Height),
    %% Extra nonce space (8 bytes for miner to vary)
    ExtraNonce = <<0, 0, 0, 0, 0, 0, 0, 0>>,
    ScriptSig = <<HeightScript/binary, ExtraNonce/binary>>,

    %% Coinbase input:
    %% - sequence = 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL) to ensure locktime is enforced
    %% - witness = [32 zero bytes] if block has witness txs
    CbInput = #tx_in{
        prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
        script_sig = ScriptSig,
        sequence = 16#fffffffe,  %% CTxIn::MAX_SEQUENCE_NONFINAL (anti-fee-sniping)
        witness = case HasWitnessTx of
            true -> [<<0:256>>];   %% witness nonce: 32 zero bytes
            false -> []
        end
    },

    %% Main payout output
    PayoutOutput = #tx_out{
        value = CoinbaseValue,
        script_pubkey = CoinbaseScriptPubKey
    },

    %% Optionally add witness commitment output
    Outputs = case HasWitnessTx of
        true ->
            CommitOutput = witness_commitment_output(
                SelectedEntries, CbInput),
            [PayoutOutput, CommitOutput];
        false ->
            [PayoutOutput]
    end,

    %% Anti-fee-sniping: set locktime to Height - 1
    %% This makes the coinbase invalid for reorgs to earlier blocks
    Locktime = case Height of
        0 -> 0;
        _ -> Height - 1
    end,

    #transaction{
        version = 2,
        inputs = [CbInput],
        outputs = Outputs,
        locktime = Locktime
    }.

%% Build the OP_RETURN witness commitment output (BIP 141).
%% commitment = SHA256d(witness_root || witness_nonce)
witness_commitment_output(SelectedEntries, CbInput) ->
    %% Coinbase wtxid is always 32 zero bytes
    Wtxids = [<<0:256>> |
              [beamchain_serialize:wtx_hash(E#mempool_entry.tx)
               || E <- SelectedEntries]],

    %% Witness nonce from the coinbase input
    [WitnessNonce | _] = CbInput#tx_in.witness,

    %% Compute commitment hash
    Commitment = beamchain_serialize:compute_witness_commitment(
        Wtxids, WitnessNonce),

    %% OP_RETURN <36 bytes> 0xaa21a9ed <32-byte commitment>
    Script = <<16#6a, 16#24, 16#aa, 16#21, 16#a9, 16#ed,
               Commitment/binary>>,
    #tx_out{value = 0, script_pubkey = Script}.

%% Encode block height for BIP 34 coinbase scriptSig.
%% Heights are pushed as minimal little-endian byte arrays.
encode_coinbase_height(0) ->
    <<0>>;
encode_coinbase_height(Height) when Height >= 1, Height =< 16 ->
    <<1, Height:8>>;
encode_coinbase_height(Height) ->
    Bytes = le_minimal(Height),
    Len = byte_size(Bytes),
    <<Len:8, Bytes/binary>>.

le_minimal(N) ->
    le_minimal_acc(N, <<>>).

le_minimal_acc(0, Acc) -> Acc;
le_minimal_acc(N, Acc) ->
    Byte = N band 16#ff,
    le_minimal_acc(N bsr 8, <<Acc/binary, Byte:8>>).

%%% ===================================================================
%%% Internal: regtest block generation
%%% ===================================================================

%% Generate multiple blocks sequentially.
do_generate_blocks(CoinbaseScript, NumBlocks, MaxTries, State) ->
    do_generate_blocks_loop(CoinbaseScript, NumBlocks, MaxTries, State, []).

do_generate_blocks_loop(_CoinbaseScript, 0, _MaxTries, _State, Acc) ->
    {ok, lists:reverse(Acc)};
do_generate_blocks_loop(CoinbaseScript, N, MaxTries, State, Acc) ->
    case do_generate_one_block(CoinbaseScript, MaxTries, State) of
        {ok, BlockHashHex} ->
            do_generate_blocks_loop(CoinbaseScript, N - 1, MaxTries, State,
                                    [BlockHashHex | Acc]);
        {error, Reason} ->
            {error, Reason}
    end.

%% Generate a single block using the current chain state.
do_generate_one_block(CoinbaseScript, MaxTries, #state{params = Params} = State) ->
    case do_create_template(CoinbaseScript, #{}, State) of
        {ok, Template, _State2} ->
            Header = maps:get(<<"_header">>, Template),
            AllTxs = maps:get(<<"_all_txs">>, Template),
            PowLimit = maps:get(pow_limit, Params),

            case mine_block(Header, AllTxs, MaxTries, PowLimit) of
                {ok, MinedBlock, BlockHash} ->
                    %% Submit the mined block
                    HexBlock = beamchain_serialize:hex_encode(
                        beamchain_serialize:encode_block(MinedBlock)),
                    case do_submit_block(HexBlock) of
                        ok ->
                            BlockHashHex = beamchain_serialize:hex_encode(
                                beamchain_serialize:reverse_bytes(BlockHash)),
                            {ok, BlockHashHex};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Generate a block with specific transactions.
do_generate_block_with_txs(CoinbaseScript, Txs, Submit,
                           #state{params = Params, network = Network}) ->
    case beamchain_chainstate:get_tip() of
        {ok, {TipHash, TipHeight}} ->
            Height = TipHeight + 1,
            MTP = beamchain_chainstate:get_mtp(),

            %% Get difficulty for regtest (use pow_limit)
            PowLimit = maps:get(pow_limit, Params),
            PowLimitInt = binary:decode_unsigned(PowLimit, big),
            Bits = beamchain_pow:target_to_bits(PowLimitInt),

            %% Check if any tx has witness data
            HasWitnessTx = lists:any(fun(Tx) -> has_witness(Tx) end, Txs),

            %% Block subsidy (no fees from provided txs for simplicity)
            Subsidy = beamchain_chain_params:block_subsidy(Height, Network),
            TotalFees = lists:foldl(fun(_Tx, Sum) ->
                %% In a real impl, would compute fee from inputs-outputs
                %% For generateblock, caller is responsible for valid txs
                Sum
            end, 0, Txs),
            CoinbaseValue = Subsidy + TotalFees,

            %% Build coinbase with empty selected entries (no mempool deps)
            CoinbaseTx = build_coinbase_for_txs(Height, CoinbaseScript,
                                                 CoinbaseValue, HasWitnessTx, Txs),

            %% All transactions
            AllTxs = [CoinbaseTx | Txs],

            %% Compute merkle root
            TxHashes = [beamchain_serialize:tx_hash(Tx) || Tx <- AllTxs],
            MerkleRoot = beamchain_serialize:compute_merkle_root(TxHashes),

            %% BUG8 FIX: apply BIP94 timewarp rule at difficulty boundaries.
            PrevIndex = get_prev_index(TipHeight),
            PrevBlockTime = case PrevIndex of
                #{header := #block_header{timestamp = T}} -> T;
                _ -> MTP
            end,
            Now = erlang:system_time(second),
            MinTime = compute_minimum_time(MTP, PrevBlockTime, Height),
            Timestamp = max(MinTime, Now),

            %% BUG5 FIX: use compute_block_version (versionbits signaling).
            Version = beamchain_versionbits:compute_block_version(TipHeight, Params),

            %% Header
            Header = #block_header{
                version = Version,
                prev_hash = TipHash,
                merkle_root = MerkleRoot,
                timestamp = Timestamp,
                bits = Bits,
                nonce = 0
            },

            case mine_block(Header, AllTxs, 1000000, PowLimit) of
                {ok, MinedBlock, BlockHash} ->
                    BlockHashHex = beamchain_serialize:hex_encode(
                        beamchain_serialize:reverse_bytes(BlockHash)),
                    HexBlock = beamchain_serialize:hex_encode(
                        beamchain_serialize:encode_block(MinedBlock)),

                    case Submit of
                        true ->
                            case do_submit_block(HexBlock) of
                                ok ->
                                    {ok, #{<<"hash">> => BlockHashHex}};
                                {error, Reason} ->
                                    {error, Reason}
                            end;
                        false ->
                            {ok, #{<<"hash">> => BlockHashHex,
                                   <<"hex">> => HexBlock}}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        not_found ->
            {error, no_chain_tip}
    end.

%% Build coinbase for generateblock (without mempool entry tracking).
build_coinbase_for_txs(Height, CoinbaseScriptPubKey, CoinbaseValue,
                       HasWitnessTx, Txs) ->
    HeightScript = encode_coinbase_height(Height),
    ExtraNonce = <<0, 0, 0, 0, 0, 0, 0, 0>>,
    ScriptSig = <<HeightScript/binary, ExtraNonce/binary>>,

    CbInput = #tx_in{
        prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
        script_sig = ScriptSig,
        sequence = 16#fffffffe,
        witness = case HasWitnessTx of
            true -> [<<0:256>>];
            false -> []
        end
    },

    PayoutOutput = #tx_out{
        value = CoinbaseValue,
        script_pubkey = CoinbaseScriptPubKey
    },

    Outputs = case HasWitnessTx of
        true ->
            CommitOutput = witness_commitment_for_txs(Txs, CbInput),
            [PayoutOutput, CommitOutput];
        false ->
            [PayoutOutput]
    end,

    Locktime = case Height of
        0 -> 0;
        _ -> Height - 1
    end,

    #transaction{
        version = 2,
        inputs = [CbInput],
        outputs = Outputs,
        locktime = Locktime
    }.

%% Witness commitment for generateblock (with explicit tx list).
witness_commitment_for_txs(Txs, CbInput) ->
    Wtxids = [<<0:256>> | [beamchain_serialize:wtx_hash(Tx) || Tx <- Txs]],
    [WitnessNonce | _] = CbInput#tx_in.witness,
    Commitment = beamchain_serialize:compute_witness_commitment(
        Wtxids, WitnessNonce),
    Script = <<16#6a, 16#24, 16#aa, 16#21, 16#a9, 16#ed, Commitment/binary>>,
    #tx_out{value = 0, script_pubkey = Script}.

%% Mine a block by iterating the nonce until PoW is valid.
%% For regtest, this typically succeeds on the first try since
%% pow_limit is nearly the maximum value (all hashes are valid).
mine_block(Header, Txs, MaxTries, PowLimit) ->
    mine_block_loop(Header, Txs, MaxTries, PowLimit, 0).

mine_block_loop(_Header, _Txs, 0, _PowLimit, _Nonce) ->
    {error, max_tries_exceeded};
mine_block_loop(_Header, _Txs, _TriesLeft, _PowLimit, Nonce) when Nonce > 16#ffffffff ->
    %% Nonce exhausted, would need to modify timestamp or extra nonce
    {error, nonce_exhausted};
mine_block_loop(Header, Txs, TriesLeft, PowLimit, Nonce) ->
    Header2 = Header#block_header{nonce = Nonce},
    BlockHash = beamchain_serialize:block_hash(Header2),
    Bits = Header#block_header.bits,

    case beamchain_pow:check_pow(BlockHash, Bits, PowLimit) of
        true ->
            Block = #block{header = Header2, transactions = Txs},
            {ok, Block, BlockHash};
        false ->
            mine_block_loop(Header, Txs, TriesLeft - 1, PowLimit, Nonce + 1)
    end.
