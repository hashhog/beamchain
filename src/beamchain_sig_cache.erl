-module(beamchain_sig_cache).

%% Signature verification cache — avoids re-verifying the same
%% signatures during reorgs or when a tx is in both mempool and block.
%%
%% Uses an ETS table with LRU-style eviction (oldest entries removed
%% when the cache exceeds max size). Key is {SigHash, PubKey, Signature}.

-export([start_link/0, init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2]).
-export([lookup/3, insert/3]).

-behaviour(gen_server).

-define(SERVER, ?MODULE).
-define(SIG_CACHE, beamchain_sig_cache_tab).
-define(SIG_CACHE_ORDER, beamchain_sig_cache_order).
-define(MAX_ENTRIES, 50000).
-define(EVICT_BATCH, 5000).

-record(state, {
    count = 0 :: non_neg_integer(),
    seq = 0   :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Check if a signature verification result is cached.
%% Returns true if the {SigHash, PubKey, Sig} triple was previously
%% verified successfully. Direct ETS read — no gen_server call.
-spec lookup(binary(), binary(), binary()) -> boolean().
lookup(SigHash, PubKey, Sig) ->
    Key = make_key(SigHash, PubKey, Sig),
    ets:member(?SIG_CACHE, Key).

%% @doc Cache a successful signature verification.
%% Only caches successful verifications (true). Async cast to avoid
%% blocking the caller.
-spec insert(binary(), binary(), binary()) -> ok.
insert(SigHash, PubKey, Sig) ->
    Key = make_key(SigHash, PubKey, Sig),
    gen_server:cast(?SERVER, {insert, Key}).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    ets:new(?SIG_CACHE, [set, public, named_table,
                          {read_concurrency, true}]),
    ets:new(?SIG_CACHE_ORDER, [ordered_set, public, named_table]),
    logger:info("sig_cache: initialized (max ~B entries)", [?MAX_ENTRIES]),
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast({insert, Key}, #state{count = Count, seq = Seq} = State) ->
    case ets:member(?SIG_CACHE, Key) of
        true ->
            %% Already cached
            {noreply, State};
        false ->
            ets:insert(?SIG_CACHE, {Key, Seq}),
            ets:insert(?SIG_CACHE_ORDER, {Seq, Key}),
            NewCount = Count + 1,
            State2 = State#state{count = NewCount, seq = Seq + 1},
            State3 = maybe_evict(State2),
            {noreply, State3}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%% ===================================================================
%%% Internal
%%% ===================================================================

make_key(SigHash, PubKey, Sig) ->
    %% Use a hash of the concatenation for a compact fixed-size key
    beamchain_crypto:sha256(<<SigHash/binary, PubKey/binary, Sig/binary>>).

maybe_evict(#state{count = Count} = State) when Count =< ?MAX_ENTRIES ->
    State;
maybe_evict(#state{count = Count} = State) ->
    %% Evict oldest EVICT_BATCH entries
    evict_oldest(?EVICT_BATCH),
    State#state{count = Count - ?EVICT_BATCH}.

evict_oldest(0) -> ok;
evict_oldest(N) ->
    case ets:first(?SIG_CACHE_ORDER) of
        '$end_of_table' -> ok;
        Seq ->
            case ets:lookup(?SIG_CACHE_ORDER, Seq) of
                [{Seq, Key}] ->
                    ets:delete(?SIG_CACHE, Key),
                    ets:delete(?SIG_CACHE_ORDER, Seq),
                    evict_oldest(N - 1);
                [] ->
                    ok
            end
    end.
