-module(beamchain_config).
-behaviour(gen_server).

-compile({no_auto_import, [get/1]}).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% API
-export([start_link/0,
         get/1,
         get/2,
         network/0,
         network_params/0,
         datadir/0,
         magic/0,
         txindex_enabled/0,
         prune_enabled/0,
         prune_target/0,
         mempool_full_rbf/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).
-define(CONFIG_TABLE, beamchain_config_ets).

-record(state, {
    network     :: atom(),
    datadir     :: string(),
    config_map  :: map()
}).

%%% ===================================================================
%%% API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Get a config value by key
-spec get(atom()) -> term() | undefined.
get(Key) ->
    get(Key, undefined).

%% @doc Get a config value by key with default
-spec get(atom(), term()) -> term().
get(Key, Default) ->
    case ets:lookup(?CONFIG_TABLE, Key) of
        [{Key, Value}] -> Value;
        [] -> Default
    end.

%% @doc Get current network atom
-spec network() -> atom().
network() ->
    get(network, mainnet).

%% @doc Get full network params record
-spec network_params() -> #network_params{}.
network_params() ->
    get(network_params).

%% @doc Get data directory path
-spec datadir() -> string().
datadir() ->
    get(datadir).

%% @doc Get network magic bytes
-spec magic() -> binary().
magic() ->
    (get(network_params))#network_params.magic.

%% @doc Check if transaction index is enabled.
%% Reads from config file (txindex=1) or env var (BEAMCHAIN_TXINDEX=1).
%% Defaults to true (enabled).
-spec txindex_enabled() -> boolean().
txindex_enabled() ->
    case os:getenv("BEAMCHAIN_TXINDEX") of
        "0" -> false;
        "false" -> false;
        _ ->
            case get(txindex, "1") of
                "0" -> false;
                "false" -> false;
                0 -> false;
                false -> false;
                _ -> true  %% Default to enabled
            end
    end.

%% @doc Check if pruning is enabled.
%% Reads from config file (prune=<mb>) or env var (BEAMCHAIN_PRUNE=<mb>).
%% Set to a positive MB value to enable, 0 to disable.
%% Defaults to disabled (0).
-spec prune_enabled() -> boolean().
prune_enabled() ->
    prune_target() > 0.

%% @doc Get prune target in MB.
%% Minimum is 550 MB if enabled (enough for UTXO set + recent blocks).
%% Returns 0 if pruning is disabled.
-spec prune_target() -> non_neg_integer().
prune_target() ->
    Target = case os:getenv("BEAMCHAIN_PRUNE") of
        false ->
            case get(prune, "0") of
                S when is_list(S) ->
                    case catch list_to_integer(S) of
                        N when is_integer(N) -> N;
                        _ -> 0
                    end;
                N when is_integer(N) -> N;
                _ -> 0
            end;
        S ->
            case catch list_to_integer(S) of
                N when is_integer(N) -> N;
                _ -> 0
            end
    end,
    %% Enforce minimum of 550 MB if pruning is enabled
    case Target of
        0 -> 0;
        _ when Target < 550 -> 550;
        _ -> Target
    end.

%% @doc Check if full RBF is enabled.
%% Reads from config file (mempoolfullrbf=1) or env var (BEAMCHAIN_FULLRBF=1).
%% Defaults to true (enabled) since Bitcoin Core 28.0 behavior.
-spec mempool_full_rbf() -> boolean().
mempool_full_rbf() ->
    case os:getenv("BEAMCHAIN_FULLRBF") of
        "0" -> false;
        "false" -> false;
        false ->
            %% No env var, check config
            case get(mempoolfullrbf, "1") of
                "0" -> false;
                "false" -> false;
                0 -> false;
                false -> false;
                _ -> true  %% Default to enabled (Bitcoin Core 28.0+)
            end;
        _ -> true
    end.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Create ETS table for fast config reads from any process
    ets:new(?CONFIG_TABLE, [named_table, set, public, {read_concurrency, true}]),

    Network = determine_network(),
    DataDir = determine_datadir(Network),
    ConfigFile = filename:join(DataDir, "beamchain.conf"),

    %% Ensure data directory exists
    ok = filelib:ensure_dir(filename:join(DataDir, "dummy")),

    %% Load config from file if it exists
    ConfigMap = load_config_file(ConfigFile),

    %% Build network params
    Params = network_params(Network),

    %% Store everything in ETS for fast reads
    ets:insert(?CONFIG_TABLE, {network, Network}),
    ets:insert(?CONFIG_TABLE, {datadir, DataDir}),
    ets:insert(?CONFIG_TABLE, {network_params, Params}),

    %% Store all config file values
    maps:foreach(fun(K, V) ->
        ets:insert(?CONFIG_TABLE, {K, V})
    end, ConfigMap),

    State = #state{
        network = Network,
        datadir = DataDir,
        config_map = ConfigMap
    },
    {ok, State}.

handle_call({get, Key, Default}, _From, State) ->
    Value = case ets:lookup(?CONFIG_TABLE, Key) of
        [{Key, V}] -> V;
        [] -> Default
    end,
    {reply, Value, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%% ===================================================================
%%% Internal functions
%%% ===================================================================

%% @doc Determine which network to use.
%% Priority: env var > application env > default (mainnet)
determine_network() ->
    case os:getenv("BEAMCHAIN_NETWORK") of
        false ->
            case application:get_env(beamchain, network) of
                {ok, Net} -> validate_network(Net);
                undefined -> mainnet
            end;
        NetStr ->
            validate_network(list_to_atom(string:lowercase(NetStr)))
    end.

%% @doc Determine data directory.
%% Priority: env var > application env > default (~/.beamchain)
determine_datadir(Network) ->
    BaseDir = case os:getenv("BEAMCHAIN_DATADIR") of
        false ->
            case application:get_env(beamchain, datadir) of
                {ok, Dir} when Dir =/= undefined -> Dir;
                _ -> default_datadir()
            end;
        Dir -> Dir
    end,
    %% Append network subdirectory for non-mainnet
    case Network of
        mainnet -> BaseDir;
        _ -> filename:join(BaseDir, atom_to_list(Network))
    end.

default_datadir() ->
    Home = os:getenv("HOME", "/tmp"),
    filename:join(Home, ".beamchain").

validate_network(mainnet)  -> mainnet;
validate_network(testnet)  -> testnet;
validate_network(testnet4) -> testnet4;
validate_network(regtest)  -> regtest;
validate_network(signet)   -> signet;
validate_network(Other)    -> error({unknown_network, Other}).

%% @doc Load config from a Bitcoin Core-style INI file
load_config_file(Path) ->
    case file:read_file(Path) of
        {ok, Binary} ->
            parse_config(binary_to_list(Binary));
        {error, enoent} ->
            #{};
        {error, Reason} ->
            logger:warning("Failed to read config file ~s: ~p", [Path, Reason]),
            #{}
    end.

parse_config(Content) ->
    Lines = string:split(Content, "\n", all),
    lists:foldl(fun parse_config_line/2, #{}, Lines).

parse_config_line(Line, Acc) ->
    Trimmed = string:trim(Line),
    case Trimmed of
        "" -> Acc;
        [$# | _] -> Acc;      %% comment
        [$; | _] -> Acc;      %% comment
        [$[ | _] -> Acc;      %% section header, ignore for now
        _ ->
            case string:split(Trimmed, "=") of
                [Key, Value] ->
                    K = list_to_atom(string:trim(Key)),
                    V = string:trim(Value),
                    Acc#{K => V};
                _ ->
                    Acc
            end
    end.

%% @doc Return network parameters for the given network
-spec network_params(atom()) -> #network_params{}.
network_params(mainnet) ->
    #network_params{
        name = mainnet,
        magic = ?MAINNET_MAGIC,
        default_port = 8333,
        rpc_port = 8332,
        genesis_hash = hexstr_to_bin(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        dns_seeds = [
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz"
        ],
        bip34_height = 227931,
        bip65_height = 388381,
        bip66_height = 363725,
        segwit_height = 481824,
        taproot_height = 709632,
        pow_limit = hexstr_to_bin(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_allow_min_diff = false,
        subsidy_halving = ?SUBSIDY_HALVING_INTERVAL,
        bech32_hrp = "bc"
    };

network_params(testnet) ->
    #network_params{
        name = testnet,
        magic = ?TESTNET_MAGIC,
        default_port = 18333,
        rpc_port = 18332,
        genesis_hash = hexstr_to_bin(
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
        dns_seeds = [
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.net",
            "seed.testnet.bitcoin.sprovoost.nl",
            "testnet-seed.bluematt.me"
        ],
        bip34_height = 21111,
        bip65_height = 581885,
        bip66_height = 330776,
        segwit_height = 834624,
        taproot_height = 0,   %% active from genesis on testnet3
        pow_limit = hexstr_to_bin(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_allow_min_diff = true,
        subsidy_halving = ?SUBSIDY_HALVING_INTERVAL,
        bech32_hrp = "tb"
    };

network_params(testnet4) ->
    #network_params{
        name = testnet4,
        magic = ?TESTNET4_MAGIC,
        default_port = 48333,
        rpc_port = 48332,
        genesis_hash = hexstr_to_bin(
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
        dns_seeds = [
            "seed.testnet4.bitcoin.sprovoost.nl",
            "seed.testnet4.wiz.biz"
        ],
        bip34_height = 1,
        bip65_height = 1,
        bip66_height = 1,
        segwit_height = 1,
        taproot_height = 1,
        pow_limit = hexstr_to_bin(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_allow_min_diff = true,
        subsidy_halving = ?SUBSIDY_HALVING_INTERVAL,
        bech32_hrp = "tb"
    };

network_params(regtest) ->
    #network_params{
        name = regtest,
        magic = ?REGTEST_MAGIC,
        default_port = 18444,
        rpc_port = 18443,
        genesis_hash = hexstr_to_bin(
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
        dns_seeds = [],
        bip34_height = 1,
        bip65_height = 1,
        bip66_height = 1,
        segwit_height = 1,
        taproot_height = 1,
        pow_limit = hexstr_to_bin(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_allow_min_diff = true,
        subsidy_halving = 150,
        bech32_hrp = "bcrt"
    };

network_params(signet) ->
    #network_params{
        name = signet,
        magic = ?SIGNET_MAGIC,
        default_port = 38333,
        rpc_port = 38332,
        genesis_hash = hexstr_to_bin(
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
        dns_seeds = [
            "seed.signet.bitcoin.sprovoost.nl"
        ],
        bip34_height = 1,
        bip65_height = 1,
        bip66_height = 1,
        segwit_height = 1,
        taproot_height = 1,
        pow_limit = hexstr_to_bin(
            "00000377ae000000000000000000000000000000000000000000000000000000"),
        pow_allow_min_diff = false,
        subsidy_halving = ?SUBSIDY_HALVING_INTERVAL,
        bech32_hrp = "tb"
    }.

%% @doc Convert a hex string to binary (assumes even-length, lowercase or upper)
hexstr_to_bin(HexStr) ->
    hexstr_to_bin(HexStr, <<>>).

hexstr_to_bin([], Acc) ->
    Acc;
hexstr_to_bin([H1, H2 | Rest], Acc) ->
    Byte = (hex_digit(H1) bsl 4) bor hex_digit(H2),
    hexstr_to_bin(Rest, <<Acc/binary, Byte>>).

hex_digit(C) when C >= $0, C =< $9 -> C - $0;
hex_digit(C) when C >= $a, C =< $f -> C - $a + 10;
hex_digit(C) when C >= $A, C =< $F -> C - $A + 10.
