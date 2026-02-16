-module(beamchain_miner).
-behaviour(gen_server).

%% Block template construction and mining support.
%% Implements getblocktemplate (BIP 22/23) and submitblock.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0]).
-export([create_block_template/1, create_block_template/2]).
-export([submit_block/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% Reserve some weight for the coinbase transaction
-define(COINBASE_WEIGHT_RESERVE, 4000).

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
            DummyHeader = #block_header{
                version = 16#20000000,
                prev_hash = TipHash,
                merkle_root = <<0:256>>,
                timestamp = Now,
                bits = 0,
                nonce = 0
            },
            Bits = beamchain_pow:get_next_work_required(
                PrevIndex, DummyHeader, Params),

            %% Select transactions from mempool
            {SelectedEntries, TotalFees, TotalWeight, TotalSigops} =
                select_transactions(),

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

            %% Timestamp: must be > MTP, use current time if ahead
            Timestamp = max(MTP + 1, Now),

            %% Assemble block header
            Header = #block_header{
                version = 16#20000000,
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
                <<"version">> => 16#20000000,
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
        {ok, PI} -> PI#{height => TipHeight};
        not_found -> error({missing_block_index, TipHeight})
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

        %% 3. validate and connect to chain
        case beamchain_chainstate:connect_block(Block) of
            ok ->
                %% 4. remove confirmed txs from mempool
                Txids = [beamchain_serialize:tx_hash(Tx)
                         || Tx <- Block#block.transactions],
                beamchain_mempool:remove_for_block(Txids),

                %% 5. announce new block to peers
                BlockHash = beamchain_serialize:block_hash(
                    Block#block.header),
                broadcast_new_block(BlockHash),

                logger:info("miner: accepted block ~s",
                            [short_hex(BlockHash)]),
                ok;
            {error, Reason} ->
                logger:warning("miner: rejected block: ~p", [Reason]),
                {error, Reason}
        end
    catch
        error:Reason2 ->
            logger:warning("miner: submit_block error: ~p", [Reason2]),
            {error, Reason2}
    end.

%% Broadcast a newly mined block hash via inv to all connected peers.
broadcast_new_block(BlockHash) ->
    try
        beamchain_peer_manager:broadcast(inv, #{
            items => [#{type => ?MSG_BLOCK, hash => BlockHash}]
        })
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
select_transactions() ->
    %% Get all mempool entries sorted by fee rate (highest first)
    Entries = beamchain_mempool:get_sorted_by_fee(),

    %% Re-sort by ancestor fee rate for CPFP
    Sorted = lists:sort(fun(A, B) ->
        ancestor_fee_rate(A) >= ancestor_fee_rate(B)
    end, Entries),

    %% Available weight: max block weight minus header and coinbase reserve
    MaxWeight = ?MAX_BLOCK_WEIGHT - ?COINBASE_WEIGHT_RESERVE
                - (80 * ?WITNESS_SCALE_FACTOR),
    MaxSigops = ?MAX_BLOCK_SIGOPS_COST,

    {Selected, Fees, Weight, Sigops} =
        greedy_select(Sorted, MaxWeight, MaxSigops,
                      sets:new([{version, 2}]), [], 0, 0, 0),

    %% Topological sort so parents appear before children
    Ordered = topological_sort(Selected),
    {Ordered, Fees, Weight, Sigops}.

ancestor_fee_rate(Entry) ->
    case Entry#mempool_entry.ancestor_size of
        0 -> Entry#mempool_entry.fee_rate;
        AncSize -> Entry#mempool_entry.ancestor_fee / AncSize
    end.

%%% ===================================================================
%%% Internal: greedy block filling
%%% ===================================================================

greedy_select([], _MaxW, _MaxS, _Seen, Acc, Fees, Weight, Sigops) ->
    {lists:reverse(Acc), Fees, Weight, Sigops};
greedy_select([Entry | Rest], MaxW, MaxS, Seen, Acc,
              Fees, Weight, Sigops) ->
    Txid = Entry#mempool_entry.txid,

    %% Skip if already selected (pulled in as a dependency)
    case sets:is_element(Txid, Seen) of
        true ->
            greedy_select(Rest, MaxW, MaxS, Seen, Acc,
                          Fees, Weight, Sigops);
        false ->
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

            TotalNewWeight = TxWeight + ParentWeight,
            NewWeight = Weight + TotalNewWeight,
            NewSigops = Sigops + TxSigops,

            case NewWeight > MaxW orelse NewSigops > MaxS of
                true ->
                    %% Doesn't fit, try next
                    greedy_select(Rest, MaxW, MaxS, Seen, Acc,
                                  Fees, Weight, Sigops);
                false ->
                    AllNew = Parents ++ [Entry],
                    Seen3 = lists:foldl(fun(E, S) ->
                        sets:add_element(E#mempool_entry.txid, S)
                    end, Seen2, AllNew),
                    greedy_select(
                        Rest, MaxW, MaxS, Seen3,
                        AllNew ++ Acc,
                        Fees + Entry#mempool_entry.fee + ParentFees,
                        NewWeight, NewSigops)
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

    %% Coinbase input
    CbInput = #tx_in{
        prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
        script_sig = ScriptSig,
        sequence = 16#ffffffff,
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

    #transaction{
        version = 2,
        inputs = [CbInput],
        outputs = Outputs,
        locktime = 0
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
