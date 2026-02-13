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

handle_call({create_template, _CoinbaseScriptPubKey, _Opts}, _From, State) ->
    %% TODO: build block template
    {reply, {error, not_implemented}, State};

handle_call({submit_block, _HexBlock}, _From, State) ->
    %% TODO: validate and connect block
    {reply, {error, not_implemented}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
