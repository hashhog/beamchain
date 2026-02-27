-module(beamchain_cli).

%% Escript entry point and command-line interface for beamchain.

-include("beamchain.hrl").

-export([main/1]).

-define(VERSION, "0.1.0").

%% Spinner frames (braille pattern dots)
-define(SPINNER, ["\xe2\xa0\x8b", "\xe2\xa0\x99", "\xe2\xa0\xb9",
                  "\xe2\xa0\xb8", "\xe2\xa0\xbc", "\xe2\xa0\xb4",
                  "\xe2\xa0\xa6", "\xe2\xa0\xa7", "\xe2\xa0\x87",
                  "\xe2\xa0\x8f"]).

%% Progress bar width (in characters)
-define(BAR_WIDTH, 25).

%%% ===================================================================
%%% Escript entry point
%%% ===================================================================

main(Args) ->
    case parse_args(Args) of
        {help, _Opts} ->
            print_usage(),
            halt(0);
        {version, _Opts} ->
            io:format("beamchain ~s~n", [?VERSION]),
            halt(0);
        {Command, Opts} ->
            run_command(Command, Opts);
        error ->
            print_usage(),
            halt(1)
    end.

%%% ===================================================================
%%% Command dispatch
%%% ===================================================================

run_command(start, Opts) ->
    start_node(Opts);
run_command(sync, Opts) ->
    sync_blockchain(Opts);
run_command(status, Opts) ->
    ensure_httpc(),
    show_status(Opts);
run_command(stop, Opts) ->
    ensure_httpc(),
    stop_node(Opts);
run_command(getbalance, Opts) ->
    ensure_httpc(),
    get_balance(Opts);
run_command(Unknown, _Opts) ->
    io:format(standard_error, "unknown command: ~s~n~n", [Unknown]),
    print_usage(),
    halt(1).

%% Make sure inets/ssl/crypto are started for httpc RPC calls
ensure_httpc() ->
    ensure_started(crypto),
    ensure_started(asn1),
    ensure_started(public_key),
    ensure_started(ssl),
    inets:start().

%%% ===================================================================
%%% Argument parsing
%%% ===================================================================

parse_args(Args) ->
    parse_args(Args, undefined, #{}).

parse_args([], Command, Opts) ->
    case Command of
        undefined -> {help, Opts};
        _ -> {Command, Opts}
    end;

%% Flags
parse_args(["--help" | _Rest], _Cmd, Opts) ->
    {help, Opts};
parse_args(["-h" | _Rest], _Cmd, Opts) ->
    {help, Opts};
parse_args(["--version" | _Rest], _Cmd, Opts) ->
    {version, Opts};
parse_args(["-v" | _Rest], _Cmd, Opts) ->
    {version, Opts};
parse_args(["--debug" | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{debug => true});

%% Options with values
parse_args(["--network", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{network => list_to_atom(Value)});
parse_args(["--network=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{network => list_to_atom(Value)});

parse_args(["--datadir", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{datadir => Value});
parse_args(["--datadir=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{datadir => Value});

parse_args(["--rpc-port", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{rpc_port => list_to_integer(Value)});
parse_args(["--rpc-port=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{rpc_port => list_to_integer(Value)});

parse_args(["--p2p-port", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{p2p_port => list_to_integer(Value)});
parse_args(["--p2p-port=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{p2p_port => list_to_integer(Value)});

parse_args(["--reset" | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{reset => true});

parse_args(["--limit", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{limit => list_to_integer(Value)});
parse_args(["--limit=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{limit => list_to_integer(Value)});

%% Commands
parse_args(["start" | Rest], undefined, Opts) ->
    parse_args(Rest, start, Opts);
parse_args(["sync" | Rest], undefined, Opts) ->
    parse_args(Rest, sync, Opts);
parse_args(["status" | Rest], undefined, Opts) ->
    parse_args(Rest, status, Opts);
parse_args(["stop" | Rest], undefined, Opts) ->
    parse_args(Rest, stop, Opts);
parse_args(["getbalance", Addr | Rest], undefined, Opts) ->
    parse_args(Rest, getbalance, Opts#{address => Addr});
parse_args(["getbalance" | Rest], undefined, Opts) ->
    parse_args(Rest, getbalance, Opts);

%% Unknown flag or positional arg
parse_args([[$- | _] = Unknown | _Rest], _Cmd, _Opts) ->
    io:format(standard_error, "unknown option: ~s~n~n", [Unknown]),
    error;
parse_args([Arg | Rest], undefined, Opts) ->
    parse_args(Rest, list_to_atom(Arg), Opts);
parse_args([_Arg | Rest], Cmd, Opts) ->
    %% Extra positional args, skip
    parse_args(Rest, Cmd, Opts).

%%% ===================================================================
%%% Usage / help
%%% ===================================================================

print_usage() ->
    io:format(
        "~s~n"
        "~n"
        "~s~n"
        "  beamchain <command> [options]~n"
        "~n"
        "~s~n"
        "  start        start the beamchain node~n"
        "  sync         sync the blockchain with progress display~n"
        "  status       show node status~n"
        "  stop         stop a running node~n"
        "  getbalance   get balance for an address~n"
        "~n"
        "~s~n"
        "  --network=<net>   network: mainnet, testnet, testnet4, regtest, signet~n"
        "  --datadir=<dir>   data directory (default: ~~/.beamchain)~n"
        "  --rpc-port=<n>    rpc port override~n"
        "  --p2p-port=<n>    p2p port override~n"
        "  --debug           enable debug logging~n"
        "  --reset           reset chain data before sync~n"
        "  --limit=<n>       limit sync to n blocks~n"
        "  -h, --help        show this help~n"
        "  -v, --version     show version~n",
        [header("beamchain " ++ ?VERSION ++ " - bitcoin full node in erlang/otp"),
         dim("usage:"),
         dim("commands:"),
         dim("options:")]).

%%% ===================================================================
%%% start command -- launch node and block
%%% ===================================================================

start_node(Opts) ->
    apply_opts(Opts),
    case start_app() of
        ok ->
            print_banner(),
            io:format("~s~n", [green("node started, press Ctrl-C to stop")]),
            %% Block forever -the OTP app runs in the background
            block_forever();
        {error, Reason} ->
            io:format(standard_error, "~s failed to start: ~p~n",
                      [red("error:"), Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% sync command -- start node and show sync progress
%%% ===================================================================

sync_blockchain(Opts) ->
    apply_opts(Opts),
    maybe_reset(Opts),
    case start_app() of
        ok ->
            %% Trap exits for graceful Ctrl-C handling
            process_flag(trap_exit, true),
            Network = beamchain_config:network(),
            DataDir = beamchain_config:datadir(),
            io:format("~s~n", [bold("beamchain sync - " ++
                                     atom_to_list(Network))]),
            io:format("~s ~s~n~n", [dim("data:"), DataDir]),
            StartTime = erlang:monotonic_time(second),
            sync_loop(0, StartTime);
        {error, Reason} ->
            io:format(standard_error, "~s failed to start: ~p~n",
                      [red("error:"), Reason]),
            halt(1)
    end.

sync_loop(Frame, StartTime) ->
    %% Check for exit signals (Ctrl-C)
    receive
        {'EXIT', _Pid, _Reason} ->
            io:format("~n~s~n", [dim("interrupted, shutting down...")]),
            graceful_shutdown(),
            halt(0)
    after 1000 -> ok
    end,
    SyncStatus = try beamchain_sync:get_sync_status()
                 catch _:_ -> #{phase => idle} end,
    Phase = maps:get(phase, SyncStatus, idle),
    HeaderInfo = maps:get(header_sync, SyncStatus, #{}),
    BlockInfo = maps:get(block_sync, SyncStatus, #{}),
    NextFrame = (Frame + 1) rem length(?SPINNER),
    Spinner = lists:nth(NextFrame + 1, ?SPINNER),

    %% Header progress line
    draw_header_progress(Spinner, HeaderInfo),
    %% Block progress line
    draw_block_progress(Spinner, BlockInfo),

    case Phase of
        complete ->
            %% Clear the progress lines
            io:format("\r\e[K\e[1A\r\e[K"),
            Elapsed = erlang:monotonic_time(second) - StartTime,
            {ok, {_Hash, Height}} = beamchain_chainstate:get_tip(),
            AvgRate = case Elapsed of
                0 -> 0.0;
                _ -> Height / Elapsed
            end,
            io:format("~s synced to ~B in ~s (avg ~.1f blk/s)~n",
                      [green("✓"), Height, format_duration(Elapsed),
                       AvgRate]),
            graceful_shutdown(),
            halt(0);
        _ ->
            %% Move cursor up 2 lines for redraw
            io:format("\e[2A"),
            sync_loop(NextFrame, StartTime)
    end.

draw_header_progress(Spinner, Info) ->
    Status = maps:get(status, Info, idle),
    case Status of
        idle ->
            io:format("\r\e[K  ~s ~s~n",
                      [Spinner, dim("waiting for peers...")]);
        not_running ->
            io:format("\r\e[K  ~s ~s~n",
                      [Spinner, dim("starting...")]);
        syncing ->
            Current = maps:get(tip_height, Info, 0),
            Estimated = maps:get(estimated_tip, Info, 0),
            Peers = maps:get(peer_count, Info, 0),
            {Pct, Bar} = case Estimated of
                0 -> {0.0, progress_bar(0.0)};
                E ->
                    P = min(100.0, Current / E * 100),
                    {P, progress_bar(P / 100)}
            end,
            io:format("\r\e[K  ~s ~s ~s ~3.0f%  ~s / ~s  ~s~n",
                      [Spinner, cyan("Headers"), Bar, Pct,
                       format_count(Current), format_count(Estimated),
                       dim(io_lib:format("~B peers", [Peers]))]);
        complete ->
            Current = maps:get(tip_height, Info, 0),
            io:format("\r\e[K  ~s ~s ~s~n",
                      [green("✓"), "Headers",
                       dim(io_lib:format("~B", [Current]))])
    end.

draw_block_progress(Spinner, Info) ->
    Status = maps:get(status, Info, idle),
    case Status of
        idle ->
            io:format("\r\e[K  ~s ~s~n",
                      [Spinner, dim("blocks: waiting for headers...")]);
        not_running ->
            io:format("\r\e[K  ~s ~s~n",
                      [Spinner, dim("blocks: waiting...")]);
        syncing ->
            Current = maps:get(next_to_validate, Info, 0),
            Target = maps:get(target_height, Info, 0),
            Validated = maps:get(blocks_validated, Info, 0),
            Peers = maps:get(peer_count, Info, 0),
            {Pct, Bar} = case Target of
                0 -> {0.0, progress_bar(0.0)};
                T ->
                    P = min(100.0, Current / T * 100),
                    {P, progress_bar(P / 100)}
            end,
            %% Compute blocks per second from validated count
            Rate = block_rate(Validated),
            ETA = case {Target - Current, Rate} of
                {Remaining, R} when R > 0 ->
                    format_duration(round(Remaining / R));
                _ -> "?"
            end,
            io:format("\r\e[K  ~s ~s ~s ~3.0f%  ~s / ~s  ~s  ~s  ~s~n",
                      [Spinner, cyan("Blocks "), Bar, Pct,
                       format_count(Current), format_count(Target),
                       dim(io_lib:format("~.1f blk/s", [Rate])),
                       dim("ETA " ++ ETA),
                       dim(io_lib:format("~B peers", [Peers]))]);
        complete ->
            Current = maps:get(next_to_validate, Info, 0),
            io:format("\r\e[K  ~s ~s ~s~n",
                      [green("✓"), "Blocks ",
                       dim(io_lib:format("~B", [Current]))])
    end.

%%% ===================================================================
%%% status command -- query running node via RPC
%%% ===================================================================

show_status(Opts) ->
    {Host, Port} = rpc_endpoint(Opts),
    case rpc_call(Host, Port, <<"getblockchaininfo">>, [], Opts) of
        {ok, Info} ->
            Chain = maps:get(<<"chain">>, Info, <<"?">>),
            Blocks = maps:get(<<"blocks">>, Info, 0),
            Headers = maps:get(<<"headers">>, Info, 0),
            IBD = maps:get(<<"initialblockdownload">>, Info, true),
            BestHash = maps:get(<<"bestblockhash">>, Info, <<>>),
            io:format("~s~n", [bold("beamchain status")]),
            io:format("  network:     ~s~n", [Chain]),
            io:format("  blocks:      ~B~n", [Blocks]),
            io:format("  headers:     ~B~n", [Headers]),
            io:format("  best block:  ~s~n", [truncate_hash(BestHash)]),
            io:format("  synced:      ~s~n",
                      [case IBD of true -> yellow("no"); false -> green("yes") end]),
            %% Peer info
            case rpc_call(Host, Port, <<"getnetworkinfo">>, [], Opts) of
                {ok, NetInfo} ->
                    Conns = maps:get(<<"connections">>, NetInfo, 0),
                    io:format("  peers:       ~B~n", [Conns]);
                _ -> ok
            end,
            %% Mempool info
            case rpc_call(Host, Port, <<"getmempoolinfo">>, [], Opts) of
                {ok, MemInfo} ->
                    MemSize = maps:get(<<"size">>, MemInfo, 0),
                    io:format("  mempool:     ~B txs~n", [MemSize]);
                _ -> ok
            end,
            %% Uptime
            case rpc_call(Host, Port, <<"uptime">>, [], Opts) of
                {ok, Uptime} when is_integer(Uptime) ->
                    io:format("  uptime:      ~s~n",
                              [format_duration(Uptime)]);
                _ -> ok
            end,
            halt(0);
        {error, Reason} ->
            io:format(standard_error,
                      "~s could not connect to node at ~s:~B~n"
                      "  ~p~n",
                      [red("error:"), Host, Port, Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% stop command -- tell running node to shut down
%%% ===================================================================

stop_node(Opts) ->
    {Host, Port} = rpc_endpoint(Opts),
    case rpc_call(Host, Port, <<"stop">>, [], Opts) of
        {ok, Msg} ->
            io:format("~s~n", [Msg]),
            halt(0);
        {error, Reason} ->
            io:format(standard_error,
                      "~s could not stop node at ~s:~B -~p~n",
                      [red("error:"), Host, Port, Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% getbalance command -- query address balance via RPC
%%% ===================================================================

get_balance(Opts) ->
    case maps:get(address, Opts, undefined) of
        undefined ->
            io:format(standard_error, "~s address required~n"
                      "  usage: beamchain getbalance <address>~n",
                      [red("error:")]),
            halt(1);
        Address ->
            {Host, Port} = rpc_endpoint(Opts),
            Params = [list_to_binary(Address)],
            case rpc_call(Host, Port, <<"getbalance">>, Params, Opts) of
                {ok, Balance} when is_number(Balance) ->
                    io:format("~.8f BTC~n", [Balance]),
                    halt(0);
                {ok, Other} ->
                    io:format("~p~n", [Other]),
                    halt(0);
                {error, Reason} ->
                    io:format(standard_error, "~s ~p~n",
                              [red("error:"), Reason]),
                    halt(1)
            end
    end.

%%% ===================================================================
%%% Application lifecycle
%%% ===================================================================

apply_opts(Opts) ->
    %% Set network in application env before starting
    case maps:get(network, Opts, undefined) of
        undefined -> ok;
        Net -> application:set_env(beamchain, network, Net)
    end,
    case maps:get(datadir, Opts, undefined) of
        undefined -> ok;
        Dir -> application:set_env(beamchain, datadir, Dir)
    end,
    case maps:get(rpc_port, Opts, undefined) of
        undefined -> ok;
        RpcPort -> application:set_env(beamchain, rpcport, RpcPort)
    end,
    case maps:get(p2p_port, Opts, undefined) of
        undefined -> ok;
        P2pPort -> application:set_env(beamchain, p2pport, P2pPort)
    end,
    case maps:get(debug, Opts, false) of
        true ->
            logger:set_primary_config(level, debug);
        false ->
            logger:set_primary_config(level, info)
    end,
    ok.

start_app() ->
    %% Ensure all dependency applications are started
    ensure_started(crypto),
    ensure_started(asn1),
    ensure_started(public_key),
    ensure_started(ssl),
    ensure_started(inets),
    ensure_started(ranch),
    ensure_started(cowlib),
    ensure_started(cowboy),
    ensure_started(jsx),
    case application:ensure_all_started(beamchain) of
        {ok, _Apps} -> ok;
        {error, _} = Err -> Err
    end.

ensure_started(App) ->
    case application:ensure_all_started(App) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok;
        {error, _Reason} -> ok  %% best effort
    end.

print_banner() ->
    Network = beamchain_config:network(),
    DataDir = beamchain_config:datadir(),
    Params = beamchain_config:network_params(),
    P2PPort = Params#network_params.default_port,
    RPCPort = Params#network_params.rpc_port,
    io:format("~n"),
    io:format("  ~s~n", [bold("beamchain " ++ ?VERSION)]),
    io:format("  ~s~n", [dim("bitcoin full node in erlang/otp")]),
    io:format("~n"),
    io:format("  network:   ~s~n", [atom_to_list(Network)]),
    io:format("  datadir:   ~s~n", [DataDir]),
    io:format("  p2p port:  ~B~n", [P2PPort]),
    io:format("  rpc port:  ~B~n", [RPCPort]),
    io:format("~n").

block_forever() ->
    process_flag(trap_exit, true),
    receive
        {'EXIT', _Pid, _Reason} ->
            io:format("~n~s~n", [dim("shutting down...")]),
            graceful_shutdown(),
            halt(0);
        _ ->
            block_forever()
    end.

%% @doc Graceful shutdown -flush state and stop cleanly.
graceful_shutdown() ->
    %% Flush UTXO cache to disk
    try beamchain_chainstate:flush()
    catch _:_ -> ok end,
    %% Stop the application (closes DB, disconnects peers)
    application:stop(beamchain),
    ok.

%% @doc Handle --reset flag: wipe chain data before syncing.
maybe_reset(#{reset := true}) ->
    %% We need config to know the datadir, but the app isn't started yet.
    %% Determine datadir manually from env/defaults.
    Network = case os:getenv("BEAMCHAIN_NETWORK") of
        false ->
            case application:get_env(beamchain, network) of
                {ok, N} -> N;
                _ -> mainnet
            end;
        NS -> list_to_atom(NS)
    end,
    BaseDir = case os:getenv("BEAMCHAIN_DATADIR") of
        false ->
            case application:get_env(beamchain, datadir) of
                {ok, D} when D =/= undefined -> D;
                _ ->
                    Home = os:getenv("HOME", "/tmp"),
                    filename:join(Home, ".beamchain")
            end;
        D -> D
    end,
    DataDir = case Network of
        mainnet -> BaseDir;
        _ -> filename:join(BaseDir, atom_to_list(Network))
    end,
    %% Remove the RocksDB data subdirectory
    DbDir = filename:join(DataDir, "chaindata"),
    io:format("~s ~s~n", [yellow("resetting"), DbDir]),
    os:cmd("rm -rf " ++ DbDir),
    ok;
maybe_reset(_) ->
    ok.

%%% ===================================================================
%%% RPC client (for status/stop/getbalance against running node)
%%% ===================================================================

rpc_endpoint(Opts) ->
    Host = "127.0.0.1",
    Port = case maps:get(rpc_port, Opts, undefined) of
        undefined ->
            %% Guess default port from network
            case maps:get(network, Opts, mainnet) of
                mainnet  -> 8332;
                testnet  -> 18332;
                testnet4 -> 48332;
                regtest  -> 18443;
                signet   -> 38332;
                _        -> 8332
            end;
        P -> P
    end,
    {Host, Port}.

rpc_call(Host, Port, Method, Params, Opts) ->
    %% Read auth cookie from datadir
    Auth = read_auth_cookie(Opts),
    Url = "http://" ++ Host ++ ":" ++ integer_to_list(Port) ++ "/",
    Body = jsx:encode(#{
        <<"jsonrpc">> => <<"1.0">>,
        <<"id">> => <<"beamchain-cli">>,
        <<"method">> => Method,
        <<"params">> => Params
    }),
    Headers = [{"Content-Type", "application/json"}] ++
              case Auth of
                  undefined -> [];
                  AuthStr -> [{"Authorization", "Basic " ++ AuthStr}]
              end,
    case httpc:request(post,
                       {Url, Headers, "application/json", Body},
                       [{timeout, 5000}, {connect_timeout, 2000}],
                       [{body_format, binary}]) of
        {ok, {{_, 200, _}, _RespHeaders, RespBody}} ->
            decode_rpc_response(RespBody);
        {ok, {{_, 401, _}, _, _}} ->
            {error, unauthorized};
        {ok, {{_, 403, _}, _, _}} ->
            {error, forbidden};
        {ok, {{_, Code, _}, _, RespBody}} ->
            case decode_rpc_response(RespBody) of
                {error, _} = E -> E;
                _ -> {error, {http_error, Code}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

decode_rpc_response(Body) ->
    try
        Map = jsx:decode(Body, [return_maps]),
        case maps:get(<<"error">>, Map, null) of
            null -> {ok, maps:get(<<"result">>, Map, null)};
            ErrorMap when is_map(ErrorMap) ->
                {error, maps:get(<<"message">>, ErrorMap, <<"unknown error">>)};
            _ -> {ok, maps:get(<<"result">>, Map, null)}
        end
    catch
        _:_ -> {error, {bad_response, Body}}
    end.

read_auth_cookie(Opts) ->
    DataDir = case maps:get(datadir, Opts, undefined) of
        undefined ->
            Home = os:getenv("HOME", "/tmp"),
            BaseDir = filename:join(Home, ".beamchain"),
            case maps:get(network, Opts, mainnet) of
                mainnet -> BaseDir;
                Net -> filename:join(BaseDir, atom_to_list(Net))
            end;
        Dir -> Dir
    end,
    CookieFile = filename:join(DataDir, ".cookie"),
    case file:read_file(CookieFile) of
        {ok, Cookie} ->
            base64:encode_to_string(binary_to_list(string:trim(Cookie)));
        {error, _} ->
            undefined
    end.

%%% ===================================================================
%%% Progress bar rendering
%%% ===================================================================

%% @doc Render a progress bar. Fraction is 0.0 to 1.0.
progress_bar(Frac) ->
    Filled = round(Frac * ?BAR_WIDTH),
    Empty = ?BAR_WIDTH - Filled,
    "[" ++ green(lists:duplicate(Filled, $█)) ++
    dim(lists:duplicate(Empty, $░)) ++ "]".

%% @doc Approximate block rate -uses process dictionary for simplicity.
%% Stores {LastValidated, LastTime} and computes instantaneous rate.
block_rate(Validated) ->
    Now = erlang:monotonic_time(millisecond),
    case get(last_block_rate) of
        {PrevValidated, PrevTime} when Now > PrevTime ->
            DeltaBlocks = Validated - PrevValidated,
            DeltaMs = Now - PrevTime,
            put(last_block_rate, {Validated, Now}),
            case DeltaMs of
                0 -> 0.0;
                _ -> DeltaBlocks / (DeltaMs / 1000.0)
            end;
        _ ->
            put(last_block_rate, {Validated, Now}),
            0.0
    end.

%%% ===================================================================
%%% Formatting helpers
%%% ===================================================================

format_count(N) when N >= 1000000 ->
    io_lib:format("~.1fM", [N / 1000000.0]);
format_count(N) when N >= 1000 ->
    io_lib:format("~.1fK", [N / 1000.0]);
format_count(N) ->
    integer_to_list(N).

format_duration(Secs) when Secs >= 3600 ->
    H = Secs div 3600,
    M = (Secs rem 3600) div 60,
    io_lib:format("~Bh ~Bm", [H, M]);
format_duration(Secs) when Secs >= 60 ->
    M = Secs div 60,
    S = Secs rem 60,
    io_lib:format("~Bm ~Bs", [M, S]);
format_duration(Secs) ->
    io_lib:format("~Bs", [Secs]).

truncate_hash(Hash) when is_binary(Hash), byte_size(Hash) > 16 ->
    <<Front:8/binary, _/binary>> = Hash,
    Rest = binary:part(Hash, byte_size(Hash), -8),
    <<Front/binary, "...", Rest/binary>>;
truncate_hash(Hash) ->
    Hash.

%%% ===================================================================
%%% ANSI color helpers
%%% ===================================================================

bold(Text)   -> color("1", Text).
header(Text) -> color("1", Text).
dim(Text)    -> color("2", Text).
green(Text)  -> color("32", Text).
yellow(Text) -> color("33", Text).
red(Text)    -> color("31", Text).
cyan(Text)   -> color("36", Text).

color(Code, Text) ->
    case is_tty() of
        true  -> "\e[" ++ Code ++ "m" ++ flatten(Text) ++ "\e[0m";
        false -> flatten(Text)
    end.

flatten(Text) when is_list(Text) ->
    lists:flatten(Text);
flatten(Text) when is_binary(Text) ->
    binary_to_list(Text);
flatten(Text) ->
    io_lib:format("~s", [Text]).

is_tty() ->
    case os:getenv("NO_COLOR") of
        false ->
            case os:type() of
                {unix, _} -> true;
                _ -> false
            end;
        _ ->
            false
    end.
