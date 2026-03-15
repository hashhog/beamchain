-module(beamchain_addrman).
-behaviour(gen_server).

%% Address manager — maintains a database of known peer addresses
%% organized into "new" (heard about, never connected) and "tried"
%% (successfully connected) tables with bucket-based storage for
%% eclipse attack resistance.
%%
%% Bitcoin Core parity:
%% - New table: 1024 buckets, 64 entries each
%% - Tried table: 256 buckets, 64 entries each
%% - Deterministic bucket assignment with keyed hash
%% - Netgroup-based limits to prevent Sybil attacks
%%
%% Reference: Bitcoin Core addrman.cpp

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0,
         add_address/3,
         add_addresses/2,
         mark_tried/1,
         mark_failed/1,
         select_address/0,
         select_address/1,
         get_addresses/1,
         count/0,
         netgroup/1,
         get_secret/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% Table dimensions (Bitcoin Core parity)
-define(NEW_BUCKET_COUNT, 1024).
-define(TRIED_BUCKET_COUNT, 256).
-define(BUCKET_SIZE, 64).

%% Limits per netgroup
-define(NEW_BUCKETS_PER_SOURCE_GROUP, 64).
-define(NEW_BUCKETS_PER_ADDRESS, 8).
-define(TRIED_BUCKETS_PER_GROUP, 8).

%% Time constants
-define(PERSIST_INTERVAL, 300000).    %% 5 minutes
-define(MIN_RETRY_INTERVAL, 60).      %% Don't retry within 60s
-define(HORIZON_DAYS, 30).            %% Max age for addresses
-define(REPLACEMENT_HOURS, 4).        %% Good() replaces if older
-define(HORIZON_SECS, (?HORIZON_DAYS * 24 * 3600)).

%% Max addresses per table (total capacity)
-define(MAX_NEW_ADDRS, (?NEW_BUCKET_COUNT * ?BUCKET_SIZE)).
-define(MAX_TRIED_ADDRS, (?TRIED_BUCKET_COUNT * ?BUCKET_SIZE)).

-record(addr_info, {
    address     :: {inet:ip_address(), inet:port_number()},
    services = 0 :: non_neg_integer(),
    timestamp   :: non_neg_integer(),    %% last time we heard about it
    source      :: term(),               %% where we learned this addr
    source_netgroup :: term(),           %% netgroup of source
    attempts = 0 :: non_neg_integer(),   %% connection attempts
    last_try = 0 :: non_neg_integer(),   %% unix timestamp of last attempt
    last_success = 0 :: non_neg_integer(), %% unix timestamp of last success
    in_tried = false :: boolean(),       %% true if in tried table
    ref_count = 0 :: non_neg_integer()   %% number of new table buckets containing this
}).

-record(state, {
    %% ETS tables for address info (keyed by address)
    addr_table    :: ets:tid(),
    %% ETS tables for bucket structure: {Bucket, Slot} -> Address
    new_buckets   :: ets:tid(),
    tried_buckets :: ets:tid(),
    %% 256-bit secret key for deterministic bucket assignment
    secret        :: binary(),
    %% DETS table for persistence
    dets_table    :: reference() | undefined,
    datadir       :: string(),
    %% Counts for quick access
    new_count = 0 :: non_neg_integer(),
    tried_count = 0 :: non_neg_integer()
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
    select_address(#{}).

%% @doc Select address with options.
%% Options: new_only => true to only select from new table
-spec select_address(map()) -> {ok, {inet:ip_address(), inet:port_number()}} | empty.
select_address(Opts) ->
    gen_server:call(?SERVER, {select_address, Opts}).

%% @doc Get N random addresses (for responding to getaddr).
-spec get_addresses(non_neg_integer()) -> [{inet:ip_address(), inet:port_number()}].
get_addresses(N) ->
    gen_server:call(?SERVER, {get_addresses, N}).

%% @doc Return count of new and tried addresses.
-spec count() -> {non_neg_integer(), non_neg_integer()}.
count() ->
    gen_server:call(?SERVER, count).

%% @doc Get the netgroup for an address (exported for peer_manager).
%% IPv4: /16 prefix; IPv6: /32 prefix; Tor: identity
-spec netgroup({inet:ip_address(), inet:port_number()} | inet:ip_address()) -> term().
netgroup({{A, B, _C, _D}, _Port}) -> {ipv4, A, B};
netgroup({A, B, _C, _D}) -> {ipv4, A, B};
netgroup({{A, B, C, D, _E, _F, _G, _H}, _Port}) -> {ipv6, A, B, C, D};
netgroup({A, B, C, D, _E, _F, _G, _H}) -> {ipv6, A, B, C, D};
netgroup(_) -> other.

%% @doc Get the secret key (for testing).
-spec get_secret() -> binary().
get_secret() ->
    gen_server:call(?SERVER, get_secret).

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% ETS tables
    AddrTab = ets:new(addrman_addrs, [set, private, {keypos, #addr_info.address}]),
    NewBuckets = ets:new(addrman_new_buckets, [set, private]),
    TriedBuckets = ets:new(addrman_tried_buckets, [set, private]),

    DataDir = beamchain_config:datadir(),

    %% Load or generate secret key
    Secret = load_or_generate_secret(DataDir),

    %% Try to load persisted addresses from DETS
    DetsFile = filename:join(DataDir, "peers.dets"),
    DetsTab = case dets:open_file(addrman_dets,
                                   [{file, DetsFile}, {type, set},
                                    {keypos, #addr_info.address}]) of
        {ok, Tab} -> Tab;
        {error, Reason} ->
            logger:warning("addrman: could not open ~s: ~p",
                           [DetsFile, Reason]),
            undefined
    end,

    State0 = #state{
        addr_table = AddrTab,
        new_buckets = NewBuckets,
        tried_buckets = TriedBuckets,
        secret = Secret,
        dets_table = DetsTab,
        datadir = DataDir
    },

    %% Load persisted addresses
    State1 = case DetsTab of
        undefined -> State0;
        _ -> load_from_dets(DetsTab, State0)
    end,

    %% Schedule periodic persistence
    erlang:send_after(?PERSIST_INTERVAL, self(), persist),

    {ok, State1}.

handle_call({select_address, Opts}, _From, State) ->
    Result = do_select_address(Opts, State),
    {reply, Result, State};

handle_call({get_addresses, N}, _From, State) ->
    Result = do_get_addresses(N, State),
    {reply, Result, State};

handle_call(count, _From, #state{new_count = New, tried_count = Tried} = State) ->
    {reply, {New, Tried}, State};

handle_call(get_secret, _From, #state{secret = Secret} = State) ->
    {reply, Secret, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({add_address, Address, Services, Source}, State) ->
    State2 = do_add_address(Address, Services, Source, State),
    {noreply, State2};

handle_cast({add_addresses, Entries, Source}, State) ->
    State2 = lists:foldl(fun(#{ip := IP, port := Port} = Entry, S) ->
        Svc = maps:get(services, Entry, 0),
        do_add_address({IP, Port}, Svc, Source, S)
    end, State, Entries),
    {noreply, State2};

handle_cast({mark_tried, Address}, State) ->
    State2 = do_mark_tried(Address, State),
    {noreply, State2};

handle_cast({mark_failed, Address}, State) ->
    State2 = do_mark_failed(Address, State),
    {noreply, State2};

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
%%% Internal: bucket assignment (Bitcoin Core parity)
%%% ===================================================================

%% @doc Compute bucket for new table entry.
%% Uses address netgroup and source netgroup to determine bucket.
%% Formula: hash2(key, source_group, hash1(key, group) % BUCKETS_PER_SOURCE_GROUP)
get_new_bucket(Address, SourceNetgroup, Secret) ->
    AddrGroup = netgroup(Address),
    Hash1 = erlang:phash2({Secret, AddrGroup, SourceNetgroup}),
    Slot1 = Hash1 rem ?NEW_BUCKETS_PER_SOURCE_GROUP,
    Hash2 = erlang:phash2({Secret, SourceNetgroup, Slot1}),
    Hash2 rem ?NEW_BUCKET_COUNT.

%% @doc Compute bucket for tried table entry.
%% Uses address itself and netgroup.
%% Formula: hash2(key, group, hash1(key, addr) % BUCKETS_PER_GROUP)
get_tried_bucket(Address, Secret) ->
    AddrGroup = netgroup(Address),
    Hash1 = erlang:phash2({Secret, Address}),
    Slot1 = Hash1 rem ?TRIED_BUCKETS_PER_GROUP,
    Hash2 = erlang:phash2({Secret, AddrGroup, Slot1}),
    Hash2 rem ?TRIED_BUCKET_COUNT.

%% @doc Compute position within a bucket.
get_bucket_position(Address, IsNew, Bucket, Secret) ->
    Type = case IsNew of true -> new; false -> tried end,
    Hash = erlang:phash2({Secret, Type, Bucket, Address}),
    Hash rem ?BUCKET_SIZE.

%%% ===================================================================
%%% Internal: address management
%%% ===================================================================

do_add_address(Address, Services, Source, #state{addr_table = AddrTab,
                                                   secret = Secret} = State) ->
    Now = erlang:system_time(second),
    SourceNG = source_netgroup(Source),

    case ets:lookup(AddrTab, Address) of
        [#addr_info{in_tried = true} = Existing] ->
            %% Already in tried, just update timestamp
            ets:insert(AddrTab, Existing#addr_info{timestamp = Now}),
            State;
        [#addr_info{in_tried = false} = Existing] ->
            %% Already in new, update timestamp and maybe add to more buckets
            ets:insert(AddrTab, Existing#addr_info{timestamp = Now}),
            State;
        [] ->
            %% New address - add to new table
            add_to_new(Address, Services, Now, Source, SourceNG, Secret, State)
    end.

add_to_new(Address, Services, Now, Source, SourceNG, Secret,
           #state{addr_table = AddrTab, new_buckets = NewBuckets,
                  new_count = NewCount} = State) ->
    %% Calculate bucket for this address+source
    Bucket = get_new_bucket(Address, SourceNG, Secret),
    Slot = get_bucket_position(Address, true, Bucket, Secret),

    %% Check if slot is occupied
    case ets:lookup(NewBuckets, {Bucket, Slot}) of
        [{_, ExistingAddr}] ->
            %% Slot occupied - evict if older, else skip
            case ets:lookup(AddrTab, ExistingAddr) of
                [#addr_info{timestamp = OldTime}] when (Now - OldTime) > ?HORIZON_SECS ->
                    %% Old entry, evict
                    remove_from_new(ExistingAddr, AddrTab, NewBuckets),
                    insert_new_entry(Address, Services, Now, Source, SourceNG,
                                      Bucket, Slot, AddrTab, NewBuckets),
                    State#state{new_count = NewCount};  %% count stays same
                _ ->
                    %% Too new to evict, skip
                    State
            end;
        [] ->
            %% Slot empty, insert
            insert_new_entry(Address, Services, Now, Source, SourceNG,
                              Bucket, Slot, AddrTab, NewBuckets),
            State#state{new_count = NewCount + 1}
    end.

insert_new_entry(Address, Services, Now, Source, SourceNG, Bucket, Slot,
                 AddrTab, NewBuckets) ->
    Entry = #addr_info{
        address = Address,
        services = Services,
        timestamp = Now,
        source = Source,
        source_netgroup = SourceNG,
        in_tried = false,
        ref_count = 1
    },
    ets:insert(AddrTab, Entry),
    ets:insert(NewBuckets, {{Bucket, Slot}, Address}).

remove_from_new(Address, AddrTab, _NewBuckets) ->
    case ets:lookup(AddrTab, Address) of
        [#addr_info{ref_count = RefCount} = Entry] ->
            NewRef = RefCount - 1,
            case NewRef =< 0 of
                true ->
                    ets:delete(AddrTab, Address);
                false ->
                    ets:insert(AddrTab, Entry#addr_info{ref_count = NewRef})
            end;
        [] ->
            ok
    end,
    %% Note: we don't know which bucket/slot to clear, caller handles that
    ok.

do_mark_tried(Address, #state{addr_table = AddrTab, new_buckets = NewBuckets,
                               tried_buckets = TriedBuckets, secret = Secret,
                               new_count = NewCount, tried_count = TriedCount} = State) ->
    Now = erlang:system_time(second),
    case ets:lookup(AddrTab, Address) of
        [#addr_info{in_tried = true} = Existing] ->
            %% Already in tried, update success time
            ets:insert(AddrTab, Existing#addr_info{
                last_success = Now,
                timestamp = Now
            }),
            State;
        [#addr_info{in_tried = false, source_netgroup = SourceNG} = Existing] ->
            %% In new table, move to tried
            %% First remove from all new buckets
            clear_from_new_buckets(Address, SourceNG, Secret, NewBuckets),
            %% Add to tried bucket
            Bucket = get_tried_bucket(Address, Secret),
            Slot = get_bucket_position(Address, false, Bucket, Secret),
            %% Handle collision in tried
            State2 = case ets:lookup(TriedBuckets, {Bucket, Slot}) of
                [{_, OldAddr}] when OldAddr =/= Address ->
                    %% Evict old entry back to new table
                    evict_tried_to_new(OldAddr, AddrTab, TriedBuckets, NewBuckets,
                                        Secret, State);
                _ ->
                    State
            end,
            %% Insert into tried
            ets:insert(AddrTab, Existing#addr_info{
                in_tried = true,
                last_success = Now,
                timestamp = Now,
                ref_count = 0
            }),
            ets:insert(TriedBuckets, {{Bucket, Slot}, Address}),
            State2#state{new_count = max(0, NewCount - 1),
                         tried_count = TriedCount + 1};
        [] ->
            %% Unknown address, add directly to tried
            Bucket = get_tried_bucket(Address, Secret),
            Slot = get_bucket_position(Address, false, Bucket, Secret),
            %% Handle collision
            State2 = case ets:lookup(TriedBuckets, {Bucket, Slot}) of
                [{_, OldAddr}] ->
                    evict_tried_to_new(OldAddr, AddrTab, TriedBuckets, NewBuckets,
                                        Secret, State);
                [] ->
                    State
            end,
            Entry = #addr_info{
                address = Address,
                timestamp = Now,
                last_success = Now,
                in_tried = true
            },
            ets:insert(AddrTab, Entry),
            ets:insert(TriedBuckets, {{Bucket, Slot}, Address}),
            State2#state{tried_count = State2#state.tried_count + 1}
    end.

clear_from_new_buckets(Address, SourceNG, Secret, NewBuckets) ->
    %% Clear the specific bucket/slot this address would be in
    Bucket = get_new_bucket(Address, SourceNG, Secret),
    Slot = get_bucket_position(Address, true, Bucket, Secret),
    case ets:lookup(NewBuckets, {Bucket, Slot}) of
        [{_, Address}] -> ets:delete(NewBuckets, {Bucket, Slot});
        _ -> ok
    end.

evict_tried_to_new(Address, AddrTab, TriedBuckets, NewBuckets, Secret,
                   #state{tried_count = TriedCount, new_count = NewCount} = State) ->
    case ets:lookup(AddrTab, Address) of
        [#addr_info{source_netgroup = SourceNG} = Entry] ->
            %% Clear from tried
            Bucket = get_tried_bucket(Address, Secret),
            Slot = get_bucket_position(Address, false, Bucket, Secret),
            ets:delete(TriedBuckets, {Bucket, Slot}),
            %% Add back to new
            NewBucket = get_new_bucket(Address, SourceNG, Secret),
            NewSlot = get_bucket_position(Address, true, NewBucket, Secret),
            ets:insert(NewBuckets, {{NewBucket, NewSlot}, Address}),
            ets:insert(AddrTab, Entry#addr_info{in_tried = false, ref_count = 1}),
            State#state{tried_count = max(0, TriedCount - 1),
                        new_count = NewCount + 1};
        [] ->
            %% Already gone
            State
    end.

do_mark_failed(Address, #state{addr_table = AddrTab} = State) ->
    Now = erlang:system_time(second),
    case ets:lookup(AddrTab, Address) of
        [Entry] ->
            ets:insert(AddrTab, Entry#addr_info{
                attempts = Entry#addr_info.attempts + 1,
                last_try = Now
            }),
            State;
        [] ->
            State
    end.

%%% ===================================================================
%%% Internal: address selection
%%% ===================================================================

do_select_address(Opts, #state{tried_count = TriedCount,
                                new_count = NewCount} = State) ->
    case TriedCount + NewCount of
        0 -> empty;
        _ ->
            NewOnly = maps:get(new_only, Opts, false),
            %% 70% tried, 30% new (unless new_only)
            UseTried = not NewOnly andalso
                       (TriedCount > 0) andalso
                       ((NewCount =:= 0) orelse (rand:uniform(10) =< 7)),
            case UseTried of
                true  -> select_from_tried(State);
                false -> select_from_new(State)
            end
    end.

select_from_tried(#state{tried_buckets = TriedBuckets, addr_table = AddrTab,
                          tried_count = Count}) ->
    Now = erlang:system_time(second),
    %% With sparse tables, we need more attempts
    Attempts = max(100, min(1000, 100 * ?TRIED_BUCKET_COUNT div max(1, Count))),
    select_random_bucket_entry(TriedBuckets, AddrTab, Now, ?TRIED_BUCKET_COUNT, Attempts).

select_from_new(#state{new_buckets = NewBuckets, addr_table = AddrTab,
                        new_count = Count}) ->
    Now = erlang:system_time(second),
    %% With sparse tables, we need more attempts
    %% Scale attempts based on how full the table is
    Attempts = max(100, min(1000, 100 * ?NEW_BUCKET_COUNT div max(1, Count))),
    select_random_bucket_entry(NewBuckets, AddrTab, Now, ?NEW_BUCKET_COUNT, Attempts).

select_random_bucket_entry(_BucketTab, _AddrTab, _Now, _NumBuckets, 0) ->
    empty;
select_random_bucket_entry(BucketTab, AddrTab, Now, NumBuckets, Attempts) ->
    %% Pick random bucket and slot
    Bucket = rand:uniform(NumBuckets) - 1,
    Slot = rand:uniform(?BUCKET_SIZE) - 1,
    case ets:lookup(BucketTab, {Bucket, Slot}) of
        [{_, Address}] ->
            case ets:lookup(AddrTab, Address) of
                [#addr_info{last_try = LastTry} = Entry] ->
                    case Now - LastTry >= ?MIN_RETRY_INTERVAL of
                        true ->
                            %% Update last_try
                            ets:insert(AddrTab, Entry#addr_info{last_try = Now}),
                            {ok, Address};
                        false ->
                            %% Too recently tried, try another
                            select_random_bucket_entry(BucketTab, AddrTab, Now,
                                                        NumBuckets, Attempts - 1)
                    end;
                [] ->
                    %% Stale bucket entry, clean up
                    ets:delete(BucketTab, {Bucket, Slot}),
                    select_random_bucket_entry(BucketTab, AddrTab, Now,
                                                NumBuckets, Attempts - 1)
            end;
        [] ->
            %% Empty slot, try another
            select_random_bucket_entry(BucketTab, AddrTab, Now,
                                        NumBuckets, Attempts - 1)
    end.

do_get_addresses(N, #state{addr_table = AddrTab}) ->
    %% Collect all addresses, shuffle, take N
    All = ets:foldl(fun(#addr_info{address = A}, Acc) -> [A | Acc] end,
                    [], AddrTab),
    Shuffled = shuffle(All),
    lists:sublist(Shuffled, N).

%%% ===================================================================
%%% Internal: persistence (DETS)
%%% ===================================================================

persist_to_dets(#state{dets_table = undefined}) ->
    ok;
persist_to_dets(#state{dets_table = DetsTab, addr_table = AddrTab}) ->
    %% Clear and rewrite
    dets:delete_all_objects(DetsTab),
    ets:foldl(fun(Entry, _) ->
        dets:insert(DetsTab, Entry)
    end, ok, AddrTab),
    dets:sync(DetsTab),
    ok.

load_from_dets(DetsTab, #state{addr_table = AddrTab, new_buckets = NewBuckets,
                                tried_buckets = TriedBuckets, secret = Secret} = State) ->
    {NewCount, TriedCount} = dets:foldl(
        fun(#addr_info{address = Address, in_tried = InTried,
                       source_netgroup = SourceNG} = Entry, {NC, TC}) ->
            ets:insert(AddrTab, Entry),
            case InTried of
                true ->
                    Bucket = get_tried_bucket(Address, Secret),
                    Slot = get_bucket_position(Address, false, Bucket, Secret),
                    ets:insert(TriedBuckets, {{Bucket, Slot}, Address}),
                    {NC, TC + 1};
                false ->
                    SNG = case SourceNG of
                        undefined -> other;
                        _ -> SourceNG
                    end,
                    Bucket = get_new_bucket(Address, SNG, Secret),
                    Slot = get_bucket_position(Address, true, Bucket, Secret),
                    ets:insert(NewBuckets, {{Bucket, Slot}, Address}),
                    {NC + 1, TC}
            end
        end, {0, 0}, DetsTab),
    logger:info("addrman: loaded ~B new, ~B tried addresses from disk",
                [NewCount, TriedCount]),
    State#state{new_count = NewCount, tried_count = TriedCount}.

%%% ===================================================================
%%% Internal: secret key management
%%% ===================================================================

load_or_generate_secret(DataDir) ->
    SecretFile = filename:join(DataDir, "addrman_secret"),
    case file:read_file(SecretFile) of
        {ok, <<Secret:32/binary>>} ->
            Secret;
        _ ->
            %% Generate new 256-bit secret
            Secret = crypto:strong_rand_bytes(32),
            ok = filelib:ensure_dir(SecretFile),
            ok = file:write_file(SecretFile, Secret),
            Secret
    end.

%%% ===================================================================
%%% Internal: helpers
%%% ===================================================================

source_netgroup(Source) when is_pid(Source) ->
    %% Peer pid - we don't have the IP easily, use 'local'
    local;
source_netgroup({IP, _Port}) ->
    netgroup({IP, 0});
source_netgroup(dns) ->
    dns;
source_netgroup(_) ->
    other.

shuffle(List) ->
    Tagged = [{rand:uniform(), X} || X <- List],
    [X || {_, X} <- lists:sort(Tagged)].
