-module(beamchain_addrman).
-behaviour(gen_server).

%% Address manager — maintains a database of known peer addresses
%% organized into "new" (heard about, never connected) and "tried"
%% (successfully connected) tables.
%%
%% Selection algorithm: 70% from tried, 30% from new.
%% Skip addresses attempted in the last 60 seconds.
%% Persist to disk periodically using DETS.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0,
         add_address/3,
         add_addresses/2,
         mark_tried/1,
         mark_failed/1,
         select_address/0,
         get_addresses/1,
         count/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% How often to persist to disk (5 minutes)
-define(PERSIST_INTERVAL, 300000).

%% Don't retry an address within this window (60s)
-define(MIN_RETRY_INTERVAL, 60).

%% Max addresses per table
-define(MAX_NEW_ADDRS, 16384).
-define(MAX_TRIED_ADDRS, 4096).

-record(addr_info, {
    address     :: {inet:ip_address(), inet:port_number()},
    services = 0 :: non_neg_integer(),
    timestamp   :: non_neg_integer(),    %% last time we heard about it
    source      :: term(),               %% where we learned this addr
    attempts = 0 :: non_neg_integer(),   %% connection attempts
    last_try = 0 :: non_neg_integer(),   %% unix timestamp of last attempt
    last_success = 0 :: non_neg_integer() %% unix timestamp of last success
}).

-record(state, {
    %% ETS tables
    new_table     :: ets:tid(),
    tried_table   :: ets:tid(),
    %% DETS table for persistence
    dets_table    :: reference() | undefined,
    datadir       :: string()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Add a single address with its services and source.
-spec add_address({inet:ip_address(), inet:port_number()},
                  non_neg_integer(), term()) -> ok.
add_address(Address, Services, Source) ->
    gen_server:cast(?SERVER, {add_address, Address, Services, Source}).

%% @doc Add a batch of addr entries (from an addr message).
%% Each entry is #{ip => IP, port => Port, services => Svc, timestamp => T}.
-spec add_addresses([map()], term()) -> ok.
add_addresses(Entries, Source) ->
    gen_server:cast(?SERVER, {add_addresses, Entries, Source}).

%% @doc Mark an address as successfully connected (move to tried).
-spec mark_tried({inet:ip_address(), inet:port_number()}) -> ok.
mark_tried(Address) ->
    gen_server:cast(?SERVER, {mark_tried, Address}).

%% @doc Mark an address as failed (increment attempt counter).
-spec mark_failed({inet:ip_address(), inet:port_number()}) -> ok.
mark_failed(Address) ->
    gen_server:cast(?SERVER, {mark_failed, Address}).

%% @doc Select a random address to connect to.
%% Returns {ok, {IP, Port}} or empty if none available.
-spec select_address() -> {ok, {inet:ip_address(), inet:port_number()}} | empty.
select_address() ->
    gen_server:call(?SERVER, select_address).

%% @doc Get N random addresses (for responding to getaddr).
-spec get_addresses(non_neg_integer()) -> [{inet:ip_address(), inet:port_number()}].
get_addresses(N) ->
    gen_server:call(?SERVER, {get_addresses, N}).

%% @doc Return count of new and tried addresses.
-spec count() -> {non_neg_integer(), non_neg_integer()}.
count() ->
    gen_server:call(?SERVER, count).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    NewTab = ets:new(addrman_new, [set, private, {keypos, #addr_info.address}]),
    TriedTab = ets:new(addrman_tried, [set, private, {keypos, #addr_info.address}]),
    DataDir = beamchain_config:datadir(),

    %% Try to load persisted addresses from DETS
    DetsFile = filename:join(DataDir, "peers.dets"),
    DetsTab = case dets:open_file(addrman_dets,
                                   [{file, DetsFile}, {type, set},
                                    {keypos, #addr_info.address}]) of
        {ok, Tab} ->
            load_from_dets(Tab, NewTab, TriedTab),
            Tab;
        {error, Reason} ->
            logger:warning("addrman: could not open ~s: ~p",
                           [DetsFile, Reason]),
            undefined
    end,

    %% Schedule periodic persistence
    erlang:send_after(?PERSIST_INTERVAL, self(), persist),

    {ok, #state{
        new_table = NewTab,
        tried_table = TriedTab,
        dets_table = DetsTab,
        datadir = DataDir
    }}.

handle_call(select_address, _From, State) ->
    Result = do_select_address(State),
    {reply, Result, State};

handle_call({get_addresses, N}, _From, State) ->
    Result = do_get_addresses(N, State),
    {reply, Result, State};

handle_call(count, _From, State) ->
    NewCount = ets:info(State#state.new_table, size),
    TriedCount = ets:info(State#state.tried_table, size),
    {reply, {NewCount, TriedCount}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({add_address, Address, Services, Source}, State) ->
    do_add_address(Address, Services, Source, State),
    {noreply, State};

handle_cast({add_addresses, Entries, Source}, State) ->
    lists:foreach(fun(#{ip := IP, port := Port} = Entry) ->
        Svc = maps:get(services, Entry, 0),
        do_add_address({IP, Port}, Svc, Source)
    end, Entries),
    {noreply, State};

handle_cast({mark_tried, Address}, State) ->
    do_mark_tried(Address, State),
    {noreply, State};

handle_cast({mark_failed, Address}, State) ->
    do_mark_failed(Address, State),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(persist, State) ->
    persist_to_dets(State),
    erlang:send_after(?PERSIST_INTERVAL, self(), persist),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    persist_to_dets(State),
    case State#state.dets_table of
        undefined -> ok;
        Tab -> dets:close(Tab)
    end,
    ok.

%%% ===================================================================
%%% Internal: address management
%%% ===================================================================

do_add_address(Address, Services, Source, #state{new_table = NewTab,
                                                  tried_table = TriedTab}) ->
    Now = erlang:system_time(second),
    case ets:lookup(TriedTab, Address) of
        [_] ->
            %% Already in tried, just update timestamp
            ets:update_element(TriedTab, Address,
                               {#addr_info.timestamp, Now});
        [] ->
            case ets:lookup(NewTab, Address) of
                [_] ->
                    %% Already in new, update timestamp
                    ets:update_element(NewTab, Address,
                                       {#addr_info.timestamp, Now});
                [] ->
                    %% New address, add to new table
                    maybe_evict(NewTab, ?MAX_NEW_ADDRS),
                    Entry = #addr_info{
                        address = Address,
                        services = Services,
                        timestamp = Now,
                        source = Source
                    },
                    ets:insert(NewTab, Entry)
            end
    end.

%% overload without State for batch add
do_add_address(Address, Services, Source) ->
    gen_server:cast(?SERVER, {add_address, Address, Services, Source}).

do_mark_tried(Address, #state{new_table = NewTab,
                               tried_table = TriedTab}) ->
    Now = erlang:system_time(second),
    %% Remove from new if present, add/update in tried
    ets:delete(NewTab, Address),
    case ets:lookup(TriedTab, Address) of
        [Existing] ->
            ets:insert(TriedTab, Existing#addr_info{
                last_success = Now,
                timestamp = Now
            });
        [] ->
            maybe_evict(TriedTab, ?MAX_TRIED_ADDRS),
            Entry = #addr_info{
                address = Address,
                timestamp = Now,
                last_success = Now
            },
            ets:insert(TriedTab, Entry)
    end.

do_mark_failed(Address, #state{new_table = NewTab,
                                tried_table = TriedTab}) ->
    Now = erlang:system_time(second),
    %% Update attempt count in whichever table has it
    case ets:lookup(TriedTab, Address) of
        [Entry] ->
            ets:insert(TriedTab, Entry#addr_info{
                attempts = Entry#addr_info.attempts + 1,
                last_try = Now
            });
        [] ->
            case ets:lookup(NewTab, Address) of
                [Entry] ->
                    ets:insert(NewTab, Entry#addr_info{
                        attempts = Entry#addr_info.attempts + 1,
                        last_try = Now
                    });
                [] ->
                    ok
            end
    end.

%%% ===================================================================
%%% Internal: address selection
%%% ===================================================================

do_select_address(#state{new_table = NewTab, tried_table = TriedTab}) ->
    Now = erlang:system_time(second),
    TriedSize = ets:info(TriedTab, size),
    NewSize = ets:info(NewTab, size),
    case TriedSize + NewSize of
        0 -> empty;
        _ ->
            %% 70% chance of selecting from tried, 30% from new
            UseTried = (TriedSize > 0) andalso
                       ((NewSize =:= 0) orelse (rand:uniform(10) =< 7)),
            Table = case UseTried of
                true  -> TriedTab;
                false -> NewTab
            end,
            select_random_from(Table, Now)
    end.

select_random_from(Table, Now) ->
    Size = ets:info(Table, size),
    case Size of
        0 -> empty;
        _ ->
            %% Try up to 50 times to find an eligible address
            select_random_from(Table, Now, 50)
    end.

select_random_from(_Table, _Now, 0) ->
    empty;
select_random_from(Table, Now, Attempts) ->
    %% Pick a random key from the table
    case random_ets_entry(Table) of
        none ->
            empty;
        #addr_info{address = Addr, last_try = LastTry} ->
            %% Skip if attempted too recently
            case Now - LastTry >= ?MIN_RETRY_INTERVAL of
                true ->
                    %% Update last_try timestamp
                    ets:update_element(Table, Addr,
                                       {#addr_info.last_try, Now}),
                    {ok, Addr};
                false ->
                    select_random_from(Table, Now, Attempts - 1)
            end
    end.

random_ets_entry(Table) ->
    Size = ets:info(Table, size),
    case Size of
        0 -> none;
        _ ->
            %% Walk to a random position in the table
            Pos = rand:uniform(Size),
            walk_ets(Table, ets:first(Table), Pos)
    end.

walk_ets(_Table, '$end_of_table', _) -> none;
walk_ets(Table, Key, 1) ->
    case ets:lookup(Table, Key) of
        [Entry] -> Entry;
        [] -> none
    end;
walk_ets(Table, Key, N) ->
    walk_ets(Table, ets:next(Table, Key), N - 1).

do_get_addresses(N, #state{new_table = NewTab, tried_table = TriedTab}) ->
    %% Collect all addresses from both tables, shuffle, take N
    All = ets:foldl(fun(#addr_info{address = A}, Acc) -> [A | Acc] end,
                    [], TriedTab) ++
          ets:foldl(fun(#addr_info{address = A}, Acc) -> [A | Acc] end,
                    [], NewTab),
    Shuffled = shuffle(All),
    lists:sublist(Shuffled, N).

%%% ===================================================================
%%% Internal: persistence (DETS)
%%% ===================================================================

persist_to_dets(#state{dets_table = undefined}) ->
    ok;
persist_to_dets(#state{dets_table = DetsTab,
                        new_table = NewTab,
                        tried_table = TriedTab}) ->
    %% Clear and rewrite — simpler than diffing
    dets:delete_all_objects(DetsTab),
    ets:foldl(fun(Entry, _) ->
        dets:insert(DetsTab, Entry)
    end, ok, TriedTab),
    ets:foldl(fun(Entry, _) ->
        dets:insert(DetsTab, Entry)
    end, ok, NewTab),
    dets:sync(DetsTab),
    ok.

load_from_dets(DetsTab, NewTab, TriedTab) ->
    dets:foldl(fun(#addr_info{last_success = LS} = Entry, _) ->
        case LS > 0 of
            true  -> ets:insert(TriedTab, Entry);
            false -> ets:insert(NewTab, Entry)
        end
    end, ok, DetsTab),
    NewCount = ets:info(NewTab, size),
    TriedCount = ets:info(TriedTab, size),
    logger:info("addrman: loaded ~B new, ~B tried addresses from disk",
                [NewCount, TriedCount]).

%%% ===================================================================
%%% Internal: helpers
%%% ===================================================================

maybe_evict(Table, MaxSize) ->
    case ets:info(Table, size) >= MaxSize of
        true ->
            %% Evict the oldest entry
            Oldest = ets:foldl(fun(#addr_info{address = A, timestamp = T}, {_, BestT} = Best) ->
                case T < BestT of
                    true  -> {A, T};
                    false -> Best
                end
            end, {undefined, erlang:system_time(second)}, Table),
            case Oldest of
                {undefined, _} -> ok;
                {Addr, _}      -> ets:delete(Table, Addr)
            end;
        false ->
            ok
    end.

shuffle(List) ->
    Tagged = [{rand:uniform(), X} || X <- List],
    [X || {_, X} <- lists:sort(Tagged)].
