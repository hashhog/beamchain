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
         mempool_full_rbf/0,
         zmq_enabled/0,
         node_bloom_enabled/0,
         blockfilterindex_enabled/0,
         %% Proxy configuration
         proxy/0,
         onion_proxy/0,
         i2p_sam/0,
         listen_onion/0]).

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
    case get(network_params) of
        #network_params{} = P -> P;
        _ -> error(network_params_not_configured)
    end.

%% @doc Get data directory path
-spec datadir() -> string().
datadir() ->
    case get(datadir) of
        undefined -> error(datadir_not_configured);
        Dir -> Dir
    end.

%% @doc Get network magic bytes
-spec magic() -> binary().
magic() ->
    Params = get(network_params),
    case Params of
        #network_params{magic = Magic} -> Magic;
        _ -> error(network_params_not_configured)
    end.

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

%% @doc Check if any ZMQ notification topic is configured.
%% Returns true if any zmqpub* env var or config option is set.
-spec zmq_enabled() -> boolean().
zmq_enabled() ->
    ZmqEnvVars = [
        "BEAMCHAIN_ZMQPUBHASHBLOCK",
        "BEAMCHAIN_ZMQPUBHASHTX",
        "BEAMCHAIN_ZMQPUBRAWBLOCK",
        "BEAMCHAIN_ZMQPUBRAWTX",
        "BEAMCHAIN_ZMQPUBSEQUENCE"
    ],
    ZmqConfigKeys = [
        zmqpubhashblock,
        zmqpubhashtx,
        zmqpubrawblock,
        zmqpubrawtx,
        zmqpubsequence
    ],
    %% Check env vars first
    EnvEnabled = lists:any(fun(V) -> os:getenv(V) =/= false end, ZmqEnvVars),
    case EnvEnabled of
        true -> true;
        false ->
            %% Check config file
            lists:any(fun(K) -> get(K) =/= undefined end, ZmqConfigKeys)
    end.

%% @doc Check if NODE_BLOOM service is advertised to peers.
%% Reads from config file (peerbloomfilters=1) or env var
%% (BEAMCHAIN_PEERBLOOMFILTERS=1). Defaults to false (disabled), matching
%% Bitcoin Core's `DEFAULT_PEERBLOOMFILTERS = false` in
%% net_processing.h. When true, beamchain advertises NODE_BLOOM in its
%% version handshake services flag and honors BIP35 mempool requests;
%% when false, BIP35 mempool messages are rejected and peers sending
%% them are disconnected (mirrors net_processing.cpp::ProcessMessage's
%% NetMsgType::MEMPOOL gate).
-spec node_bloom_enabled() -> boolean().
node_bloom_enabled() ->
    case os:getenv("BEAMCHAIN_PEERBLOOMFILTERS") of
        "0" -> false;
        "false" -> false;
        false ->
            case get(peerbloomfilters, "0") of
                "1" -> true;
                "true" -> true;
                1 -> true;
                true -> true;
                _ -> false  %% Default to disabled (Core DEFAULT_PEERBLOOMFILTERS)
            end;
        _ -> true
    end.

%% @doc Check if the BIP-157/158 compact block filter index is enabled.
%% Reads from config file (blockfilterindex=1) or env var
%% (BEAMCHAIN_BLOCKFILTERINDEX=1).  Defaults to false (disabled),
%% matching Bitcoin Core's `-blockfilterindex` default.  When enabled,
%% beamchain advertises NODE_COMPACT_FILTERS in its version handshake
%% services flag and answers BIP-157 getcfilters/getcfheaders/
%% getcfcheckpt P2P queries from the persistent filter index.
-spec blockfilterindex_enabled() -> boolean().
blockfilterindex_enabled() ->
    case os:getenv("BEAMCHAIN_BLOCKFILTERINDEX") of
        "0" -> false;
        "false" -> false;
        false ->
            case get(blockfilterindex, "0") of
                "1" -> true;
                "true" -> true;
                "basic" -> true;
                1 -> true;
                true -> true;
                _ -> false
            end;
        _ -> true
    end.

%% @doc Get SOCKS5 proxy configuration for general outbound connections.
%% Format: "socks5://host:port" or "host:port" (default port 9050).
%% Set via BEAMCHAIN_PROXY env var or proxy= config option.
-spec proxy() -> undefined | #{host := string(), port := inet:port_number()}.
proxy() ->
    case os:getenv("BEAMCHAIN_PROXY") of
        false ->
            case get(proxy) of
                undefined -> undefined;
                Addr -> parse_proxy_addr(Addr, 9050)
            end;
        Addr ->
            parse_proxy_addr(Addr, 9050)
    end.

%% @doc Get Tor SOCKS5 proxy configuration for .onion addresses.
%% Format: "host:port" (default 127.0.0.1:9050).
%% Set via BEAMCHAIN_ONION env var or onion= config option.
%% Falls back to general proxy if not set.
-spec onion_proxy() -> undefined | #{host := string(), port := inet:port_number()}.
onion_proxy() ->
    case os:getenv("BEAMCHAIN_ONION") of
        false ->
            case get(onion) of
                undefined -> proxy();  %% Fall back to general proxy
                Addr -> parse_proxy_addr(Addr, 9050)
            end;
        Addr ->
            parse_proxy_addr(Addr, 9050)
    end.

%% @doc Get I2P SAM bridge configuration.
%% Format: "host:port" (default 127.0.0.1:7656).
%% Set via BEAMCHAIN_I2PSAM env var or i2psam= config option.
-spec i2p_sam() -> undefined | #{host := string(), port := inet:port_number()}.
i2p_sam() ->
    case os:getenv("BEAMCHAIN_I2PSAM") of
        false ->
            case get(i2psam) of
                undefined -> undefined;
                Addr -> parse_proxy_addr(Addr, 7656)
            end;
        Addr ->
            parse_proxy_addr(Addr, 7656)
    end.

%% @doc Check if listening for inbound Tor connections is enabled.
%% When enabled, the node will generate a Tor hidden service.
%% Set via BEAMCHAIN_LISTENONION=1 env var or listenonion=1 config option.
-spec listen_onion() -> boolean().
listen_onion() ->
    case os:getenv("BEAMCHAIN_LISTENONION") of
        "1" -> true;
        "true" -> true;
        false ->
            case get(listenonion) of
                "1" -> true;
                "true" -> true;
                1 -> true;
                true -> true;
                _ -> false
            end;
        _ -> false
    end.

%% Parse proxy address string into map.
%% Supports formats: "host:port", "socks5://host:port", "host"
parse_proxy_addr(Addr, DefaultPort) when is_list(Addr) ->
    %% Strip protocol prefix if present
    Addr2 = case lists:prefix("socks5://", Addr) of
        true -> lists:nthtail(9, Addr);
        false -> Addr
    end,
    case string:split(Addr2, ":") of
        [Host, PortStr] ->
            case catch list_to_integer(PortStr) of
                Port when is_integer(Port), Port > 0, Port < 65536 ->
                    #{host => Host, port => Port};
                _ ->
                    #{host => Addr2, port => DefaultPort}
            end;
        [Host] ->
            #{host => Host, port => DefaultPort}
    end;
parse_proxy_addr(Addr, DefaultPort) when is_binary(Addr) ->
    parse_proxy_addr(binary_to_list(Addr), DefaultPort);
parse_proxy_addr(_, _) ->
    undefined.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    %% Create ETS table for fast config reads from any process
    ets:new(?CONFIG_TABLE, [named_table, set, public, {read_concurrency, true}]),

    Network = determine_network(),
    DataDir = determine_datadir(Network),
    ConfigFile = determine_conffile(DataDir),

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

    %% Store port overrides.  Priority: env var > application env > config file.
    case os:getenv("BEAMCHAIN_P2P_PORT") of
        false ->
            case application:get_env(beamchain, p2pport) of
                {ok, P2PPort} when is_integer(P2PPort) ->
                    ets:insert(?CONFIG_TABLE, {p2pport, P2PPort});
                _ -> ok
            end;
        P2PStr ->
            case catch list_to_integer(P2PStr) of
                P2PPort when is_integer(P2PPort) ->
                    ets:insert(?CONFIG_TABLE, {p2pport, P2PPort});
                _ -> ok
            end
    end,
    case os:getenv("BEAMCHAIN_RPC_PORT") of
        false ->
            case application:get_env(beamchain, rpcport) of
                {ok, RPCPort} when is_integer(RPCPort) ->
                    ets:insert(?CONFIG_TABLE, {rpcport, RPCPort});
                _ -> ok
            end;
        RPCStr ->
            case catch list_to_integer(RPCStr) of
                RPCPort when is_integer(RPCPort) ->
                    ets:insert(?CONFIG_TABLE, {rpcport, RPCPort});
                _ -> ok
            end
    end,

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

%% @doc Resolve the path of beamchain.conf.
%% Priority: env var (BEAMCHAIN_CONF) > application env (conffile,
%% set by --conf=) > legacy fixed path under datadir.
%% Mirrors bitcoind's GetConfigFile() / -conf= handling in init.cpp.
determine_conffile(DataDir) ->
    case os:getenv("BEAMCHAIN_CONF") of
        false ->
            case application:get_env(beamchain, conffile) of
                {ok, Path} when is_list(Path), Path =/= "" -> Path;
                _ -> filename:join(DataDir, "beamchain.conf")
            end;
        Path -> Path
    end.

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
