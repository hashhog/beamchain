-module(beamchain_zmq).
-behaviour(gen_server).

%% ZeroMQ notification publisher for real-time blockchain event streaming.
%%
%% Publishes notifications on configurable endpoints:
%% - hashblock: 32-byte block hash when new block connects
%% - hashtx: 32-byte txid when tx enters mempool or block
%% - rawblock: full serialized block
%% - rawtx: full serialized transaction
%% - sequence: block/mempool event with sequence number
%%
%% Message format: ZMQ multipart [topic, body, sequence_le32]
%% Reference: Bitcoin Core zmqpublishnotifier.cpp

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0, start_link/1]).
-export([notify_block/2, notify_transaction/3]).
-export([is_enabled/0, get_endpoints/0]).

%% Test helpers
-export([parse_endpoint_test/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).

%% Default ZMQ endpoints
-define(DEFAULT_ZMQ_PORT, 28332).

%% Topic names (binary for ZMQ)
-define(TOPIC_HASHBLOCK, <<"hashblock">>).
-define(TOPIC_HASHTX, <<"hashtx">>).
-define(TOPIC_RAWBLOCK, <<"rawblock">>).
-define(TOPIC_RAWTX, <<"rawtx">>).
-define(TOPIC_SEQUENCE, <<"sequence">>).

%% Sequence labels (single character)
-define(SEQ_LABEL_CONNECT, $C).       %% Block connect
-define(SEQ_LABEL_DISCONNECT, $D).    %% Block disconnect
-define(SEQ_LABEL_MEMPOOL_ADD, $A).   %% Mempool acceptance
-define(SEQ_LABEL_MEMPOOL_REM, $R).   %% Mempool removal

%%% -------------------------------------------------------------------
%%% State
%%% -------------------------------------------------------------------

-record(state, {
    %% ZMQ PUB sockets by topic -> {Socket, Endpoint}
    sockets = #{} :: #{binary() => {term(), string()}},
    %% Per-topic sequence numbers (32-bit unsigned, wrapping)
    sequences = #{} :: #{binary() => non_neg_integer()},
    %% Internal mempool sequence (for 'sequence' topic)
    mempool_seq = 0 :: non_neg_integer()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    start_link(get_zmq_config()).

start_link(Config) when is_map(Config) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Config, []).

%% @doc Notify that a block has been connected or disconnected.
%% Action is 'connect' or 'disconnect'.
-spec notify_block(#block{}, connect | disconnect) -> ok.
notify_block(Block, Action) ->
    case is_enabled() of
        true -> gen_server:cast(?SERVER, {notify_block, Block, Action});
        false -> ok
    end.

%% @doc Notify that a transaction has been added to or removed from mempool.
%% Source is 'mempool_add', 'mempool_remove', or 'block'.
-spec notify_transaction(#transaction{}, mempool_add | mempool_remove | block,
                         non_neg_integer()) -> ok.
notify_transaction(Tx, Source, MempoolSeq) ->
    case is_enabled() of
        true -> gen_server:cast(?SERVER, {notify_tx, Tx, Source, MempoolSeq});
        false -> ok
    end.

%% @doc Check if any ZMQ topic is enabled.
-spec is_enabled() -> boolean().
is_enabled() ->
    case whereis(?SERVER) of
        undefined -> false;
        _Pid -> true
    end.

%% @doc Get configured endpoints for each topic.
-spec get_endpoints() -> #{binary() => string()}.
get_endpoints() ->
    case is_enabled() of
        true -> gen_server:call(?SERVER, get_endpoints);
        false -> #{}
    end.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init(Config) when is_map(Config) ->
    %% Config is a map of topic -> endpoint
    %% e.g. #{<<"hashblock">> => "tcp://*:28332", ...}
    case maps:size(Config) of
        0 ->
            %% No ZMQ topics configured, don't start
            {stop, no_zmq_topics_configured};
        _ ->
            process_flag(trap_exit, true),
            case setup_sockets(Config) of
                {ok, Sockets} ->
                    %% Initialize sequence counters
                    Seqs = maps:from_list([{T, 0} || T <- maps:keys(Sockets)]),
                    logger:info("zmq: started with topics: ~p",
                               [maps:keys(Sockets)]),
                    {ok, #state{sockets = Sockets, sequences = Seqs}};
                {error, Reason} ->
                    logger:error("zmq: failed to start: ~p", [Reason]),
                    {stop, Reason}
            end
    end.

handle_call(get_endpoints, _From, #state{sockets = Sockets} = State) ->
    Endpoints = maps:fold(fun(Topic, {_Sock, Endpoint}, Acc) ->
        Acc#{Topic => Endpoint}
    end, #{}, Sockets),
    {reply, Endpoints, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({notify_block, Block, Action}, State) ->
    State2 = do_notify_block(Block, Action, State),
    {noreply, State2};

handle_cast({notify_tx, Tx, Source, MempoolSeq}, State) ->
    State2 = do_notify_tx(Tx, Source, MempoolSeq, State),
    {noreply, State2};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{sockets = Sockets}) ->
    %% Close all sockets
    maps:foreach(fun(_Topic, {Sock, _Endpoint}) ->
        catch chumak:stop(Sock)
    end, Sockets),
    logger:info("zmq: shutdown"),
    ok.

%%% ===================================================================
%%% Internal functions
%%% ===================================================================

%% @doc Set up ZMQ PUB sockets for configured topics.
setup_sockets(Config) ->
    setup_sockets(maps:to_list(Config), #{}).

setup_sockets([], Acc) ->
    {ok, Acc};
setup_sockets([{Topic, Endpoint} | Rest], Acc) ->
    case create_pub_socket(Endpoint) of
        {ok, Socket} ->
            setup_sockets(Rest, Acc#{Topic => {Socket, Endpoint}});
        {error, Reason} ->
            %% Clean up already-created sockets
            maps:foreach(fun(_T, {S, _E}) -> catch chumak:stop(S) end, Acc),
            {error, {socket_error, Topic, Reason}}
    end.

%% @doc Create a ZMQ PUB socket and bind to endpoint.
create_pub_socket(Endpoint) ->
    case chumak:socket(pub) of
        {ok, Socket} ->
            case parse_endpoint(Endpoint) of
                {ok, Protocol, Host, Port} ->
                    case chumak:bind(Socket, Protocol, Host, Port) of
                        {ok, _BindPid} ->
                            {ok, Socket};
                        {error, Reason} ->
                            chumak:stop(Socket),
                            {error, {bind_failed, Reason}}
                    end;
                {error, Reason} ->
                    chumak:stop(Socket),
                    {error, {bad_endpoint, Reason}}
            end;
        {error, Reason} ->
            {error, {socket_failed, Reason}}
    end.

%% @doc Parse endpoint string like "tcp://*:28332"
parse_endpoint(Endpoint) when is_list(Endpoint) ->
    case string:split(Endpoint, "://") of
        [ProtoStr, Rest] ->
            Protocol = list_to_atom(ProtoStr),
            case string:split(Rest, ":") of
                [Host, PortStr] ->
                    case catch list_to_integer(PortStr) of
                        Port when is_integer(Port), Port > 0, Port < 65536 ->
                            {ok, Protocol, Host, Port};
                        _ ->
                            {error, invalid_port}
                    end;
                _ ->
                    {error, missing_port}
            end;
        _ ->
            {error, missing_protocol}
    end;
parse_endpoint(Endpoint) when is_binary(Endpoint) ->
    parse_endpoint(binary_to_list(Endpoint)).

%% @doc Notify block connect/disconnect events.
do_notify_block(#block{header = Header, transactions = Txs} = Block,
                Action, State) ->
    BlockHash = beamchain_serialize:block_hash(Header),
    %% Reverse hash to display byte order (like Bitcoin Core)
    HashDisplay = beamchain_serialize:reverse_bytes(BlockHash),

    State2 = case maps:is_key(?TOPIC_HASHBLOCK, State#state.sockets) of
        true -> publish_message(?TOPIC_HASHBLOCK, HashDisplay, State);
        false -> State
    end,

    State3 = case maps:is_key(?TOPIC_RAWBLOCK, State2#state.sockets) of
        true ->
            RawBlock = beamchain_serialize:encode_block(Block),
            publish_message(?TOPIC_RAWBLOCK, RawBlock, State2);
        false -> State2
    end,

    %% Sequence topic: block connect/disconnect
    Label = case Action of
        connect -> ?SEQ_LABEL_CONNECT;
        disconnect -> ?SEQ_LABEL_DISCONNECT
    end,
    State4 = case maps:is_key(?TOPIC_SEQUENCE, State3#state.sockets) of
        true ->
            %% sequence message: [hash:32][label:1]
            SeqBody = <<HashDisplay/binary, Label:8>>,
            publish_message(?TOPIC_SEQUENCE, SeqBody, State3);
        false -> State3
    end,

    %% For block connect, also publish hashtx/rawtx for each transaction
    State5 = case Action of
        connect ->
            lists:foldl(fun(Tx, S) ->
                do_notify_tx_for_block(Tx, S)
            end, State4, Txs);
        disconnect ->
            State4
    end,

    State5.

%% @doc Notify tx when it's included in a block.
do_notify_tx_for_block(Tx, State) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    TxidDisplay = beamchain_serialize:reverse_bytes(Txid),

    State2 = case maps:is_key(?TOPIC_HASHTX, State#state.sockets) of
        true -> publish_message(?TOPIC_HASHTX, TxidDisplay, State);
        false -> State
    end,

    case maps:is_key(?TOPIC_RAWTX, State2#state.sockets) of
        true ->
            RawTx = beamchain_serialize:encode_transaction(Tx),
            publish_message(?TOPIC_RAWTX, RawTx, State2);
        false -> State2
    end.

%% @doc Notify tx for mempool events.
do_notify_tx(Tx, Source, MempoolSeq, State) ->
    Txid = beamchain_serialize:tx_hash(Tx),
    TxidDisplay = beamchain_serialize:reverse_bytes(Txid),

    State2 = case Source of
        mempool_add ->
            %% For mempool adds, publish hashtx/rawtx
            S1 = case maps:is_key(?TOPIC_HASHTX, State#state.sockets) of
                true -> publish_message(?TOPIC_HASHTX, TxidDisplay, State);
                false -> State
            end,
            case maps:is_key(?TOPIC_RAWTX, S1#state.sockets) of
                true ->
                    RawTx = beamchain_serialize:encode_transaction(Tx),
                    publish_message(?TOPIC_RAWTX, RawTx, S1);
                false -> S1
            end;
        _ ->
            %% mempool_remove and block don't publish hashtx/rawtx
            State
    end,

    %% Sequence topic: mempool add/remove
    case maps:is_key(?TOPIC_SEQUENCE, State2#state.sockets) of
        true ->
            Label = case Source of
                mempool_add -> ?SEQ_LABEL_MEMPOOL_ADD;
                mempool_remove -> ?SEQ_LABEL_MEMPOOL_REM;
                block -> undefined  %% Don't send sequence for block txs
            end,
            case Label of
                undefined ->
                    State2;
                _ ->
                    %% sequence message for mempool: [hash:32][label:1][mempool_seq:8/LE]
                    SeqBody = <<TxidDisplay/binary, Label:8, MempoolSeq:64/little>>,
                    publish_message(?TOPIC_SEQUENCE, SeqBody, State2)
            end;
        false -> State2
    end.

%% @doc Publish a multipart ZMQ message: [topic, body, sequence_le32].
publish_message(Topic, Body, #state{sockets = Sockets, sequences = Seqs} = State) ->
    case maps:get(Topic, Sockets, undefined) of
        undefined ->
            State;
        {Socket, _Endpoint} ->
            SeqNum = maps:get(Topic, Seqs, 0),
            SeqLE = <<SeqNum:32/little>>,

            %% ZMQ multipart: send topic with SNDMORE, body with SNDMORE, seq as final
            ok = chumak:send_multipart(Socket, [Topic, Body, SeqLE]),

            %% Increment sequence (wraps at 32 bits)
            NewSeq = (SeqNum + 1) band 16#ffffffff,
            State#state{sequences = Seqs#{Topic => NewSeq}}
    end.

%% @doc Get ZMQ configuration from environment/config.
%% Returns a map of topic -> endpoint.
get_zmq_config() ->
    Topics = [
        {?TOPIC_HASHBLOCK, "BEAMCHAIN_ZMQPUBHASHBLOCK", zmqpubhashblock},
        {?TOPIC_HASHTX, "BEAMCHAIN_ZMQPUBHASHTX", zmqpubhashtx},
        {?TOPIC_RAWBLOCK, "BEAMCHAIN_ZMQPUBRAWBLOCK", zmqpubrawblock},
        {?TOPIC_RAWTX, "BEAMCHAIN_ZMQPUBRAWTX", zmqpubrawtx},
        {?TOPIC_SEQUENCE, "BEAMCHAIN_ZMQPUBSEQUENCE", zmqpubsequence}
    ],
    lists:foldl(fun({Topic, EnvVar, ConfigKey}, Acc) ->
        case get_endpoint_config(EnvVar, ConfigKey) of
            undefined -> Acc;
            Endpoint -> Acc#{Topic => Endpoint}
        end
    end, #{}, Topics).

%% @doc Get endpoint from env var or config file.
get_endpoint_config(EnvVar, ConfigKey) ->
    case os:getenv(EnvVar) of
        false ->
            case beamchain_config:get(ConfigKey) of
                undefined -> undefined;
                Value when is_list(Value) -> Value;
                Value when is_binary(Value) -> binary_to_list(Value)
            end;
        Endpoint ->
            Endpoint
    end.

%%% ===================================================================
%%% Test helpers
%%% ===================================================================

%% @doc Expose parse_endpoint for testing.
-spec parse_endpoint_test(string() | binary()) ->
    {ok, atom(), string(), integer()} | {error, term()}.
parse_endpoint_test(Endpoint) ->
    parse_endpoint(Endpoint).
