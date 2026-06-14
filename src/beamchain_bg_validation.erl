-module(beamchain_bg_validation).

%%% ===================================================================
%%% AssumeUTXO REAL background-validation chainstate (Core v31.99 parity)
%%%
%%% This module implements Bitcoin Core's *background* (a.k.a.
%%% "validated") chainstate for AssumeUTXO. When `loadtxoutset` activates
%%% a snapshot, the active chainstate jumps to the snapshot base height
%%% and starts validating forward immediately. In parallel, a SECOND
%%% chainstate re-derives the UTXO set from GENESIS up to the snapshot
%%% base height and, at the base, recomputes the HASH_SERIALIZED
%%% commitment and compares it to the hard-coded `au_data.hash_serialized`
%%% from chainparams. This is what *authenticates* the snapshot beyond the
%%% load-time file hash (which only proves the file matches its own
%%% claimed commitment — circular if the file was tampered).
%%%
%%% Core references:
%%%   validation.cpp:5588  ActivateSnapshot       (load gate: G1..G9)
%%%   validation.cpp:5754  PopulateAndValidateSnapshot
%%%   validation.cpp:6170  AddChainstate          (background cs OWN coins db)
%%%   validation.cpp:5967  MaybeCompleteSnapshotValidation
%%%   validation.cpp:6036  ComputeUTXOStats(HASH_SERIALIZED, &validated_coins_db)
%%%   validation.cpp:6061  hashSerialized != au_data.hash_serialized -> INVALID
%%%   validation.cpp:6072  -> VALIDATED on match
%%%
%%% THE TWO INVARIANTS that make this non-circular (cf. rustoshi 5cfa601,
%%% clearbit 9de6087, haskoin c02803b):
%%%
%%%   1. SEPARATE STORE. The background coins live in a PRIVATE ETS table
%%%      created and owned by THIS process — never the active chainstate's
%%%      `?UTXO_CACHE`/CF. Seeded EMPTY at genesis. So the recomputed hash
%%%      is a hash of independently-rederived coins, not a hash-of-self.
%%%
%%%   2. ALIASING GUARD. `assert_separate_store/1` refuses to run if the
%%%      background table id collides with any of the active named UTXO
%%%      tables. A misconfiguration that pointed the background store at
%%%      the active set would trivially "validate" any snapshot (it would
%%%      hash the very set it just loaded). We hard-error instead.
%%%
%%% The replay itself is a real connect: for each block genesis..base we
%%% spend the inputs (remove from the bg store) and add the outputs
%%% (skipping provably-unspendable / OP_RETURN coins, and the genesis
%%% coinbase which Core never adds to the UTXO set). It is NOT a counter
%%% and NOT a re-hash of the active set.
%%% ===================================================================

-behaviour(gen_server).

-include("beamchain.hrl").

%% Public API
-export([start_link/2, start_link/3]).
-export([run/2, run/3]).
-export([status/1, await/2, stop/1]).
-export([assert_separate_store/1]).

%% Pure replay core (separate-store; testable without a gen_server)
-export([replay_genesis_to_base/3, replay_block_into_store/3,
         materialize_store/1, recompute_hash_serialized/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% The set of named ETS tables owned by the *active* chainstate. The
%% background store must never be any of these (aliasing guard). Kept in
%% sync with beamchain_chainstate:init_chainstate/2.
-define(ACTIVE_UTXO_TABLES,
        [beamchain_utxo_cache, beamchain_utxo_dirty,
         beamchain_utxo_fresh, beamchain_utxo_spent]).

-record(bgstate, {
    store        :: ets:tid(),       %% PRIVATE bg coins table (separate)
    network      :: atom(),
    base_height  :: non_neg_integer(),
    base_hash    :: binary(),
    expected_hash:: binary(),        %% au_data.hash_serialized
    block_fun    :: fun((non_neg_integer()) -> {ok, #block{}} | not_found),
    %% result: pending | {validated, Hash} | {invalid, Computed, Expected}
    %%         | {error, term()}
    result       :: pending | tuple(),
    waiters      :: [gen_server:from()]
}).

%%% ===================================================================
%%% Public API
%%% ===================================================================

%% @doc Start a background-validation process for a loaded snapshot.
%% Network + BaseHeight select the chainparams au_data. The block source
%% defaults to beamchain_db:get_block_by_height/1.
-spec start_link(atom(), non_neg_integer()) -> {ok, pid()} | {error, term()}.
start_link(Network, BaseHeight) ->
    start_link(Network, BaseHeight, default_block_fun()).

-spec start_link(atom(), non_neg_integer(),
                 fun((non_neg_integer()) -> {ok, #block{}} | not_found)) ->
    {ok, pid()} | {error, term()}.
start_link(Network, BaseHeight, BlockFun) ->
    gen_server:start_link(?MODULE, [Network, BaseHeight, BlockFun], []).

%% @doc Synchronous run (used by tests / inline callers): build the
%% separate store, replay genesis..base, recompute the commitment, and
%% return the verdict. Does NOT spawn a process.
-spec run(atom(), non_neg_integer()) ->
    {validated, binary()} | {invalid, binary(), binary()} | {error, term()}.
run(Network, BaseHeight) ->
    run(Network, BaseHeight, default_block_fun()).

-spec run(atom(), non_neg_integer(),
          fun((non_neg_integer()) -> {ok, #block{}} | not_found)) ->
    {validated, binary()} | {invalid, binary(), binary()} | {error, term()}.
run(Network, BaseHeight, BlockFun) ->
    %% Resolve the expected commitment + base hash from chainparams.
    case beamchain_chain_params:get_assumeutxo(BaseHeight, Network) of
        {ok, #{utxo_hash := ExpectedHash, block_hash := BaseHash}} ->
            Store = new_separate_store(),
            try
                ok = assert_separate_store(Store),
                do_run(Store, Network, BaseHeight, BaseHash, ExpectedHash,
                       BlockFun)
            after
                ets:delete(Store)
            end;
        not_found ->
            {error, {no_assumeutxo_for_height, BaseHeight}}
    end.

%% @doc Current verdict of a running bg-validation process.
-spec status(pid()) -> pending | tuple().
status(Pid) ->
    gen_server:call(Pid, status, 60000).

%% @doc Block until the verdict is reached (or timeout).
-spec await(pid(), timeout()) -> tuple().
await(Pid, Timeout) ->
    gen_server:call(Pid, await, Timeout).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%%% ===================================================================
%%% Aliasing guard — invariant #2.
%%% ===================================================================

%% @doc Refuse to proceed unless `Store` is a distinct table from every
%% active chainstate UTXO table. This prevents a hash-of-self: if the
%% background store WERE the active coins set, the recomputed
%% HASH_SERIALIZED would tautologically equal the loaded snapshot's hash
%% and any tampered snapshot would "validate".
%%
%% Mirrors the spirit of Core's CChainState owning its OWN CCoinsViewDB
%% (validation.cpp:6170 AddChainstate / 6020 validated_cs.CoinsDB()).
-spec assert_separate_store(ets:tid()) -> ok | no_return().
assert_separate_store(Store) ->
    %% Resolve the live numeric ids of the active named tables (if any
    %% exist in this VM) and compare against the bg store's id. A private
    %% unnamed table can never share an id with a named one, but we check
    %% by-name AND by-id so the guard holds even if a future refactor
    %% makes the bg store named.
    ActiveIds =
        lists:foldl(
          fun(Name, Acc) ->
                  case ets:whereis(Name) of
                      undefined -> Acc;
                      Tid -> [Tid, Name | Acc]
                  end
          end, [], ?ACTIVE_UTXO_TABLES),
    StoreName =
        case ets:info(Store, name) of
            undefined -> Store;
            N -> N
        end,
    case lists:member(Store, ActiveIds)
         orelse lists:member(StoreName, ActiveIds)
         orelse lists:member(Store, ?ACTIVE_UTXO_TABLES) of
        true ->
            erlang:error({bg_validation_aliases_active_store, Store});
        false ->
            ok
    end.

%%% ===================================================================
%%% Pure replay core (separate-store). Exported for direct unit testing.
%%% ===================================================================

%% @doc Allocate a fresh, EMPTY, PRIVATE coins store. Unnamed + private so
%% it can never collide with (or be read by) the active chainstate.
-spec new_separate_store() -> ets:tid().
new_separate_store() ->
    ets:new(beamchain_bg_utxo, [set, private]).

%% @doc Replay every block from genesis (height 0) up to and including
%% BaseHeight into the SEPARATE store. BlockFun fetches a block by height.
%% Returns ok or {error, {missing_block, Height}}.
-spec replay_genesis_to_base(ets:tid(), non_neg_integer(),
                             fun((non_neg_integer()) ->
                                     {ok, #block{}} | not_found)) ->
    ok | {error, term()}.
replay_genesis_to_base(Store, BaseHeight, BlockFun) ->
    replay_loop(Store, 0, BaseHeight, BlockFun).

replay_loop(_Store, H, BaseHeight, _BlockFun) when H > BaseHeight ->
    ok;
replay_loop(Store, H, BaseHeight, BlockFun) ->
    case BlockFun(H) of
        {ok, Block} ->
            ok = replay_block_into_store(Store, H, Block),
            replay_loop(Store, H + 1, BaseHeight, BlockFun);
        not_found ->
            {error, {missing_block, H}}
    end.

%% @doc Connect a single block into the separate store: spend inputs,
%% then add outputs. Mirrors Core's ConnectBlock UTXO mutation
%% (coins.cpp SpendCoin / AddCoin), including:
%%   * genesis coinbase (height 0) is NEVER added — Core skips it
%%     (the genesis coinbase output is unspendable by consensus).
%%   * coinbase inputs are not "spent" (they reference the null prevout).
%%   * provably-unspendable outputs (OP_RETURN / oversize) are dropped at
%%     AddCoin time, exactly like the active chainstate's add_utxo/3.
-spec replay_block_into_store(ets:tid(), non_neg_integer(), #block{}) -> ok.
replay_block_into_store(Store, Height, #block{transactions = Txs}) ->
    lists:foreach(
      fun(Tx) -> connect_tx(Store, Height, Tx) end,
      index_txs(Txs)),
    ok.

%% Tag each tx with whether it is the coinbase (first tx in the block).
index_txs([]) -> [];
index_txs([Coinbase | Rest]) ->
    [{coinbase, Coinbase} | [{normal, T} || T <- Rest]].

connect_tx(Store, Height, {Kind, #transaction{inputs = Ins, outputs = Outs} = Tx}) ->
    Txid = txid_of(Tx),
    %% 1. Spend inputs (skip the coinbase null-prevout input).
    case Kind of
        coinbase -> ok;
        normal   -> lists:foreach(fun(In) -> spend_input(Store, In) end, Ins)
    end,
    %% 2. Add outputs. The genesis (height 0) coinbase is never added.
    case {Kind, Height} of
        {coinbase, 0} ->
            ok;
        _ ->
            IsCoinbase = (Kind =:= coinbase),
            add_outputs(Store, Txid, Height, IsCoinbase, Outs)
    end.

spend_input(Store, #tx_in{prev_out = #outpoint{hash = PrevTxid, index = Vout}}) ->
    ets:delete(Store, {PrevTxid, Vout}),
    ok.

add_outputs(Store, Txid, Height, IsCoinbase, Outs) ->
    add_outputs(Store, Txid, Height, IsCoinbase, Outs, 0).

add_outputs(_Store, _Txid, _Height, _IsCoinbase, [], _Idx) ->
    ok;
add_outputs(Store, Txid, Height, IsCoinbase,
            [#tx_out{value = Value, script_pubkey = SPK} | Rest], Idx) ->
    %% Core coins.cpp:91 — drop provably-unspendable outputs at AddCoin.
    %% Reuse the active chainstate's predicate so the two paths agree
    %% byte-for-byte on what enters the set.
    case beamchain_chainstate:is_unspendable_script(SPK) of
        true ->
            ok;
        false ->
            Utxo = #utxo{value = Value, script_pubkey = SPK,
                         is_coinbase = IsCoinbase, height = Height},
            ets:insert(Store, {{Txid, Idx}, Utxo})
    end,
    add_outputs(Store, Txid, Height, IsCoinbase, Rest, Idx + 1).

%% @doc Materialize the separate store as the standard
%% {Txid, Vout, #utxo{}} coin tuples the hasher consumes.
-spec materialize_store(ets:tid()) -> [{binary(), non_neg_integer(), #utxo{}}].
materialize_store(Store) ->
    ets:foldl(fun({{Txid, Vout}, Utxo}, Acc) ->
                      [{Txid, Vout, Utxo} | Acc]
              end, [], Store).

%% @doc Recompute the HASH_SERIALIZED commitment over the separate store
%% using the SAME kernel the active path uses (beamchain_snapshot:
%% compute_utxo_hash_from_list/1 -> tx_out_ser/3). We do NOT write a new
%% hasher — Core's coinstats.cpp:161 TxOutSer layout lives there.
-spec recompute_hash_serialized(ets:tid()) -> binary().
recompute_hash_serialized(Store) ->
    beamchain_snapshot:compute_utxo_hash_from_list(materialize_store(Store)).

%%% ===================================================================
%%% Internal shared run logic
%%% ===================================================================

do_run(Store, _Network, BaseHeight, BaseHash, ExpectedHash, BlockFun) ->
    case replay_genesis_to_base(Store, BaseHeight, BlockFun) of
        ok ->
            Computed = recompute_hash_serialized(Store),
            case Computed =:= ExpectedHash of
                true ->
                    logger:info(
                      "bg_validation: snapshot at height ~B base ~s "
                      "fully validated (hash_serialized match)",
                      [BaseHeight, short_hex(BaseHash)]),
                    {validated, Computed};
                false ->
                    %% Core validation.cpp:6061-6066 — never silent; the
                    %% snapshot chainstate is marked INVALID.
                    logger:error(
                      "bg_validation: snapshot hash mismatch at height ~B: "
                      "computed=~s expected=~s -> INVALID",
                      [BaseHeight, short_hex(Computed), short_hex(ExpectedHash)]),
                    {invalid, Computed, ExpectedHash}
            end;
        {error, Reason} ->
            logger:warning("bg_validation: replay failed: ~p", [Reason]),
            {error, Reason}
    end.

default_block_fun() ->
    fun(H) -> beamchain_db:get_block_by_height(H) end.

%% Compute the txid for a transaction, reusing a precomputed value when
%% present.
txid_of(#transaction{txid = T}) when is_binary(T), byte_size(T) =:= 32 ->
    T;
txid_of(#transaction{} = Tx) ->
    beamchain_serialize:tx_hash(Tx).

short_hex(<<Bin:32/binary>>) ->
    %% Display (big-endian) short hash, like Core's uint256::ToString prefix.
    Rev = beamchain_serialize:reverse_bytes(Bin),
    <<Prefix:8/binary, _/binary>> = beamchain_serialize:hex_encode(Rev),
    Prefix;
short_hex(Other) ->
    iolist_to_binary(io_lib:format("~p", [Other])).

%%% ===================================================================
%%% gen_server callbacks (async background mode)
%%% ===================================================================

init([Network, BaseHeight, BlockFun]) ->
    case beamchain_chain_params:get_assumeutxo(BaseHeight, Network) of
        {ok, #{utxo_hash := ExpectedHash, block_hash := BaseHash}} ->
            Store = new_separate_store(),
            try
                ok = assert_separate_store(Store)
            catch
                error:Alias ->
                    ets:delete(Store),
                    {stop, {aliasing_guard, Alias}}
            end,
            St = #bgstate{
                store = Store,
                network = Network,
                base_height = BaseHeight,
                base_hash = BaseHash,
                expected_hash = ExpectedHash,
                block_fun = BlockFun,
                result = pending,
                waiters = []
            },
            %% Kick off the replay asynchronously so init returns promptly.
            self() ! start_replay,
            {ok, St};
        not_found ->
            {stop, {no_assumeutxo_for_height, BaseHeight}}
    end.

handle_info(start_replay, #bgstate{store = Store,
                                   base_height = BaseHeight,
                                   base_hash = BaseHash,
                                   expected_hash = ExpectedHash,
                                   block_fun = BlockFun} = St) ->
    %% Re-assert the separate-store invariant immediately before mutating.
    ok = assert_separate_store(Store),
    Result = case replay_genesis_to_base(Store, BaseHeight, BlockFun) of
        ok ->
            Computed = recompute_hash_serialized(Store),
            case Computed =:= ExpectedHash of
                true  -> {validated, Computed};
                false -> {invalid, Computed, ExpectedHash}
            end;
        {error, Reason} ->
            {error, Reason}
    end,
    notify_waiters(St#bgstate.waiters, Result),
    log_result(Result, BaseHeight, BaseHash, ExpectedHash),
    {noreply, St#bgstate{result = Result, waiters = []}};
handle_info(_Msg, St) ->
    {noreply, St}.

handle_call(status, _From, #bgstate{result = R} = St) ->
    {reply, R, St};
handle_call(await, From, #bgstate{result = pending, waiters = Ws} = St) ->
    {noreply, St#bgstate{waiters = [From | Ws]}};
handle_call(await, _From, #bgstate{result = R} = St) ->
    {reply, R, St};
handle_call(_Req, _From, St) ->
    {reply, {error, unknown_request}, St}.

handle_cast(_Msg, St) ->
    {noreply, St}.

terminate(_Reason, #bgstate{store = Store}) ->
    catch ets:delete(Store),
    ok.

code_change(_Old, St, _Extra) ->
    {ok, St}.

notify_waiters(Waiters, Result) ->
    lists:foreach(fun(From) -> gen_server:reply(From, Result) end, Waiters).

log_result({validated, _}, H, BaseHash, _) ->
    logger:info("bg_validation: snapshot at height ~B base ~s VALIDATED",
                [H, short_hex(BaseHash)]);
log_result({invalid, C, E}, H, _BaseHash, _) ->
    logger:error("bg_validation: snapshot at height ~B INVALID "
                 "(computed=~s expected=~s)",
                 [H, short_hex(C), short_hex(E)]);
log_result({error, R}, H, _BaseHash, _) ->
    logger:warning("bg_validation: snapshot at height ~B replay error: ~p",
                   [H, R]).
