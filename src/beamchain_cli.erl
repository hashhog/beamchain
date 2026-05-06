-module(beamchain_cli).

%% Escript entry point and command-line interface for beamchain.

-include("beamchain.hrl").

-export([main/1, parse_args/1, apply_debug_categories/1,
         remove_pidfile/0, pidfile_path/1]).

%% Dialyzer suppressions for false positives:
%% import_utxo/1 calls halt/1 (diverges) on one path; dialyzer treats it as
%%   no local return because start_app() is inferred to always return ok.
%% flatten/1: the catch-all clause is legitimate defensive code for iolist/other
%%   types even though dialyzer only sees list/binary from current call sites.
-dialyzer({nowarn_function, [import_utxo/1, flatten/1]}).

-define(VERSION, "0.1.0").

%% Spinner frames (braille pattern dots)
-define(SPINNER, ["\xe2\xa0\x8b", "\xe2\xa0\x99", "\xe2\xa0\xb9",
                  "\xe2\xa0\xb8", "\xe2\xa0\xbc", "\xe2\xa0\xb4",
                  "\xe2\xa0\xa6", "\xe2\xa0\xa7", "\xe2\xa0\x87",
                  "\xe2\xa0\x8f"]).

%% Progress bar width (in characters)
-define(BAR_WIDTH, 25).

%% UTF-8 byte sequences for Unicode glyphs (matches spinner encoding)
-define(CHECK, "\xe2\x9c\x93").       %% ✓ U+2713
-define(BLOCK_FULL, "\xe2\x96\x88").  %% █ U+2588
-define(BLOCK_LIGHT, "\xe2\x96\x91"). %% ░ U+2591

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
run_command(import, Opts) ->
    import_blocks(Opts);
run_command('import-utxo', Opts) ->
    import_utxo(Opts);
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
%% --debug=<categories>: comma-separated category names (net,rpc,...)
%% --debug (bare): turn on debug for all modules.
parse_args(["--debug=" ++ Cats | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{debug => true,
                                 debug_categories => parse_debug_cats(Cats)});
parse_args(["--debug", "=" ++ Cats | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{debug => true,
                                 debug_categories => parse_debug_cats(Cats)});
parse_args(["--debug" | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{debug => true});

%% --daemon: detach into the background (re-exec self under nohup/&).
parse_args(["--daemon" | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{daemon => true});

%% --printtoconsole: explicitly mirror the file logger to stdout/stderr
%% even when running under nohup/--daemon. Default behavior already
%% writes to the local TTY when present; this flag forces it on.
parse_args(["--printtoconsole" | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{printtoconsole => true});
parse_args(["--printtoconsole=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{printtoconsole => parse_bool(Value)});

%% --pid=<path>: PID file path. Default <datadir>/beamchain.pid.
parse_args(["--pid", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{pidfile => Value});
parse_args(["--pid=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{pidfile => Value});

%% --conf=<file>: explicit override for the beamchain.conf path.
%% Falls back to <datadir>/beamchain.conf when omitted (legacy behavior).
parse_args(["--conf", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{conf => Value});
parse_args(["--conf=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{conf => Value});

%% Internal flag emitted by daemonize/1.  Marks the re-exec'd child so it
%% runs the foreground path and does not fork again.  Hidden from help.
parse_args(["--_daemon-child" | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{'_daemon_child' => true});

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

parse_args(["--import-file", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{import_file => Value});
parse_args(["--import-file=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{import_file => Value});

parse_args(["--import-utxo", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{import_utxo => Value});
parse_args(["--import-utxo=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{import_utxo => Value});
%% --load-snapshot=<f>: alias for --import-utxo (matches Core's loadtxoutset
%% RPC argument naming; --import-utxo is kept for backward compatibility).
parse_args(["--load-snapshot", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{import_utxo => Value});
parse_args(["--load-snapshot=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{import_utxo => Value});

parse_args(["--limit", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{limit => list_to_integer(Value)});
parse_args(["--limit=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{limit => list_to_integer(Value)});

%% --cfilter=<N>: BIP-157/158 compact block filter index.
%%   0 = off (default, matches Bitcoin Core's `-blockfilterindex=0`)
%%   1 = basic filter type (matches Core's `-blockfilterindex=basic`)
%% When enabled, the node:
%%   * computes the BasicFilter (BIP-158, M=784931 / P=19) on every
%%     block-connect and persists it under <datadir>/indexes/blockfilter/basic
%%   * advertises NODE_COMPACT_FILTERS (0x40) in version handshake services
%%   * answers BIP-157 getcfilters / getcfheaders / getcfcheckpt queries
%%   * exposes the getblockfilter JSON-RPC method
%% Higher values are reserved for future filter types and currently rejected.
parse_args(["--cfilter", Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{cfilter => parse_cfilter_arg(Value)});
parse_args(["--cfilter=" ++ Value | Rest], Cmd, Opts) ->
    parse_args(Rest, Cmd, Opts#{cfilter => parse_cfilter_arg(Value)});

%% Commands
parse_args(["start" | Rest], undefined, Opts) ->
    parse_args(Rest, start, Opts);
parse_args(["import" | Rest], undefined, Opts) ->
    parse_args(Rest, import, Opts);
parse_args(["import-utxo" | Rest], undefined, Opts) ->
    parse_args(Rest, 'import-utxo', Opts);
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
        "  import       import blocks from stdin or file (bypasses P2P)~n"
        "  import-utxo  import a Bitcoin Core UTXO snapshot (assumeutxo)~n"
        "  status       show node status~n"
        "  stop         stop a running node~n"
        "  getbalance   get balance for an address~n"
        "~n"
        "~s~n"
        "  --network=<net>   network: mainnet, testnet, testnet4, regtest, signet~n"
        "  --datadir=<dir>   data directory (default: ~~/.beamchain)~n"
        "  --conf=<file>     config file (default: <datadir>/beamchain.conf)~n"
        "  --rpc-port=<n>    rpc port override~n"
        "  --p2p-port=<n>    p2p port override~n"
        "  --pid=<file>      pid file path (default: <datadir>/beamchain.pid)~n"
        "  --daemon          fork into the background after starting~n"
        "  --printtoconsole  also write log lines to stdout~n"
        "  --debug[=<cats>]  enable debug logging (optional comma-separated~n"
        "                    categories: net,rpc,mempool,validation,sync,~n"
        "                    db,zmq,wallet,miner,all)~n"
        "  --reset           reset chain data before sync~n"
        "  --limit=<n>       limit sync to n blocks~n"
        "  --import-file=<f> file to import blocks from (default: stdin)~n"
        "  --import-utxo=<f> Core-format UTXO snapshot file (utxo.dat from~n"
        "                    Bitcoin Core's `dumptxoutset`); alias --load-snapshot~n"
        "  --cfilter=<n>     BIP-157/158 compact block filter index~n"
        "                    (0=off, 1=basic; mirrors Core -blockfilterindex)~n"
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
    case maps:get(daemon, Opts, false) of
        true ->
            %% --daemon: detach by re-exec'ing self under nohup with the
            %% --daemon flag stripped, so the child runs the normal
            %% foreground path. See bitcoin-core/src/util/system.cpp's
            %% daemon() helper -- same intent, smaller scope.
            case maps:get('_daemon_child', Opts, false) of
                true ->
                    do_start_node(Opts);
                false ->
                    daemonize(Opts)
            end;
        false ->
            do_start_node(Opts)
    end.

do_start_node(Opts) ->
    apply_opts(Opts),
    case start_app() of
        ok ->
            setup_file_logger(),
            maybe_setup_console_logger(Opts),
            write_pidfile(Opts),
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
                      [green(?CHECK), Height, format_duration(Elapsed),
                       AvgRate]),
            graceful_shutdown(),
            halt(0);
        _ ->
            %% Move cursor up 2 lines for redraw
            io:format("\e[2A"),
            sync_loop(NextFrame, StartTime)
    end.

%%% ===================================================================
%%% import command -- import blocks from stdin/file
%%% ===================================================================

import_blocks(Opts) ->
    apply_opts(Opts),
    case start_app() of
        ok ->
            setup_file_logger(),
            Network = beamchain_config:network(),
            io:format("beamchain import - ~s~n", [atom_to_list(Network)]),
            beamchain_import:run(Opts);
        {error, Reason} ->
            io:format(standard_error, "~s failed to start: ~p~n",
                      [red("error:"), Reason]),
            halt(1)
    end.

%%% ===================================================================
%%% import-utxo command -- import a Bitcoin Core UTXO snapshot
%%% (assumeutxo). Routes through beamchain_chainstate:load_snapshot/1
%%% which calls beamchain_snapshot:load_snapshot/1 (Core-byte-compatible
%%% loader), then verify_snapshot/2 against the chain_params'
%%% m_assumeutxo_data, then populates the UTXO cache.
%%% ===================================================================

import_utxo(Opts) ->
    case maps:get(import_utxo, Opts, undefined) of
        undefined ->
            io:format(standard_error,
                      "~s --import-utxo=<path> is required~n"
                      "  usage: beamchain import-utxo "
                      "--import-utxo=/path/to/utxo.dat~n",
                      [red("error:")]),
            halt(1);
        Path ->
            apply_opts(Opts),
            case start_app() of
                ok ->
                    setup_file_logger(),
                    do_import_utxo(Path);
                {error, Reason} ->
                    io:format(standard_error, "~s failed to start: ~p~n",
                              [red("error:"), Reason]),
                    halt(1)
            end
    end.

do_import_utxo(Path) ->
    %% Pre-flight: read the metadata header so we can fail fast on a
    %% truncated/wrong-network file before the load helper spins up the
    %% verification machinery.
    case beamchain_snapshot:read_metadata(Path) of
        {ok, #{base_hash := BaseHash, num_coins := NumCoins,
               network_magic := MagicBin}} ->
            io:format("loading UTXO snapshot from ~s~n", [Path]),
            io:format("  network magic: ~s~n", [hex_str(MagicBin)]),
            io:format("  base hash:     ~s~n",
                      [hex_str(reverse_bytes(BaseHash))]),
            io:format("  coins count:   ~B~n~n", [NumCoins]),
            case beamchain_chainstate:load_snapshot(Path) of
                {ok, Height} ->
                    io:format("~s loaded snapshot at height ~B~n",
                              [green(?CHECK), Height]),
                    halt(0);
                {error, Reason} ->
                    io:format(standard_error,
                              "~s snapshot load failed: ~p~n",
                              [red("error:"), Reason]),
                    halt(1)
            end;
        {error, Reason} ->
            io:format(standard_error,
                      "~s could not read snapshot metadata at ~s: ~p~n",
                      [red("error:"), Path, Reason]),
            halt(1)
    end.

reverse_bytes(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).

hex_str(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

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
                      [green(?CHECK), "Headers",
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
                      [green(?CHECK), "Blocks ",
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
    %% Set network in application env before starting.
    %% Use [{persistent, true}] so that application:load/1 does not
    %% overwrite these values with the defaults from beamchain.app.
    case maps:get(network, Opts, undefined) of
        undefined -> ok;
        Net -> application:set_env(beamchain, network, Net, [{persistent, true}])
    end,
    case maps:get(datadir, Opts, undefined) of
        undefined -> ok;
        Dir -> application:set_env(beamchain, datadir, Dir, [{persistent, true}])
    end,
    case maps:get(rpc_port, Opts, undefined) of
        undefined -> ok;
        RpcPort -> application:set_env(beamchain, rpcport, RpcPort, [{persistent, true}])
    end,
    case maps:get(p2p_port, Opts, undefined) of
        undefined -> ok;
        P2pPort -> application:set_env(beamchain, p2pport, P2pPort, [{persistent, true}])
    end,
    %% --conf=<file>: explicit beamchain.conf path override. Promoted from
    %% the legacy fixed path at <datadir>/beamchain.conf so operators can
    %% point at a shared/system config (mirrors bitcoind -conf=).
    case maps:get(conf, Opts, undefined) of
        undefined -> ok;
        ConfPath ->
            application:set_env(beamchain, conffile, ConfPath, [{persistent, true}])
    end,
    %% --pid=<path>: opt-in PID file. Default lives under datadir; we
    %% don't pin a default into application env here -- start_node/1
    %% computes it lazily so it picks up the resolved datadir.
    case maps:get(pidfile, Opts, undefined) of
        undefined -> ok;
        PidPath ->
            application:set_env(beamchain, pidfile, PidPath, [{persistent, true}])
    end,
    case maps:get(printtoconsole, Opts, false) of
        true ->
            application:set_env(beamchain, printtoconsole, true,
                                [{persistent, true}]);
        false -> ok
    end,
    case maps:get(debug, Opts, false) of
        true ->
            logger:set_primary_config(level, debug);
        false ->
            logger:set_primary_config(level, info)
    end,
    %% --debug=<cat>: per-module log levels. Applied AFTER the primary
    %% level so categories can opt back in to debug while everything
    %% else stays at info.  Categories map to module name globs in
    %% category_modules/1; an unknown category is a soft warning.
    case maps:get(debug_categories, Opts, []) of
        [] -> ok;
        Cats -> apply_debug_categories(Cats)
    end,
    %% --cfilter: feed through BEAMCHAIN_BLOCKFILTERINDEX so the existing
    %% beamchain_config:blockfilterindex_enabled/0 plumbing picks it up
    %% before init_table/0 reads ETS.  We use the env var path (rather
    %% than directly poking ETS) because config init runs *after*
    %% apply_opts/1, and the env var is checked first by the gate fn.
    case maps:get(cfilter, Opts, undefined) of
        undefined -> ok;
        0 -> os:putenv("BEAMCHAIN_BLOCKFILTERINDEX", "0");
        1 -> os:putenv("BEAMCHAIN_BLOCKFILTERINDEX", "1");
        Other ->
            io:format(standard_error,
                      "warning: --cfilter=~p ignored (only 0 or 1 supported)~n",
                      [Other])
    end,
    ok.

%% Parse the --cfilter=<N> argument.  Accepts integer-as-string only;
%% defers to apply_opts/1 for range validation so we surface a single
%% consistent error path.
parse_cfilter_arg(Str) ->
    case catch list_to_integer(Str) of
        N when is_integer(N) -> N;
        _ ->
            io:format(standard_error,
                      "warning: --cfilter=~s not an integer; ignoring~n",
                      [Str]),
            undefined
    end.

start_app() ->
    %% When running as escript, NIF-based dependencies (rocksdb) cannot
    %% find their .so libraries because code:priv_dir/1 doesn't resolve
    %% inside an escript archive.  Fix: add each dep's ebin/ from the
    %% _build tree to the code path so that code:priv_dir/1 works.
    ensure_nif_deps_on_path(),
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

%% @doc Ensure NIF-based deps (rocksdb) are loadable when running as escript.
%% Escript bundles .beam files inside a zip archive, but NIF .so files
%% live on the real filesystem.  The rocksdb NIF loader checks
%% code:priv_dir(rocksdb) which fails in escript mode because the app
%% is loaded from an archive.  Fix: register the rocksdb application's
%% priv dir in the code server by loading the .app from the filesystem
%% before ensure_all_started triggers the archive copy.
ensure_nif_deps_on_path() ->
    NifOk = case code:priv_dir(rocksdb) of
        {error, bad_name} -> false;
        Dir -> filelib:is_regular(filename:join(Dir, "liberocksdb.so"))
    end,
    case NifOk of
        true ->
            ok;  %% priv_dir resolves to a real directory with the NIF
        false ->
            %% Running as escript — priv_dir points inside the archive
            %% which doesn't contain .so files.  Re-point to filesystem.
            ScriptDir = escript_dir(),
            LibDir = filename:join(filename:dirname(ScriptDir), "lib"),
            case filelib:is_dir(filename:join([LibDir, "rocksdb", "ebin"])) of
                true ->
                    Ebins = filelib:wildcard(filename:join(LibDir, "*/ebin")),
                    lists:foreach(fun(Ebin) -> code:add_patha(Ebin) end, Ebins),
                    %% Unload the escript-archive version of rocksdb
                    %% so it reloads from the filesystem code path
                    %% where priv_dir/1 resolves correctly.
                    application:unload(rocksdb),
                    code:purge(rocksdb),
                    code:delete(rocksdb),
                    code:purge(rocksdb),
                    ok;
                false ->
                    ok
            end
    end.

%% @doc Return the directory containing the running escript.
escript_dir() ->
    case escript:script_name() of
        [] ->
            %% Fallback: cwd
            {ok, Cwd} = file:get_cwd(),
            Cwd;
        Name ->
            filename:dirname(filename:absname(Name))
    end.

print_banner() ->
    Network = beamchain_config:network(),
    DataDir = beamchain_config:datadir(),
    Params = beamchain_config:network_params(),
    P2PPort = case beamchain_config:get(p2pport) of
        undefined -> Params#network_params.default_port;
        PP when is_integer(PP) -> PP;
        PP when is_list(PP) -> list_to_integer(PP)
    end,
    RPCPort = case beamchain_config:get(rpcport) of
        undefined -> Params#network_params.rpc_port;
        RP when is_integer(RP) -> RP;
        RP when is_list(RP) -> list_to_integer(RP)
    end,
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

%% @doc Set up a file logger so sync progress is visible in the log file.
%% Writes to <datadir>/beamchain.log with info level.
setup_file_logger() ->
    DataDir = beamchain_config:datadir(),
    LogFile = filename:join(DataDir, "beamchain.log"),
    ok = filelib:ensure_dir(LogFile),
    logger:add_handler(beamchain_file_logger, logger_std_h, #{
        level => info,
        config => #{
            file => LogFile,
            max_no_bytes => 10485760,   %% 10 MB
            max_no_files => 3
        },
        formatter => {logger_formatter, #{
            template => [time, " [", level, "] ", msg, "\n"],
            single_line => true
        }}
    }),
    ok.

%% @doc Graceful shutdown -flush state and stop cleanly.
graceful_shutdown() ->
    %% Flush UTXO cache to disk
    try beamchain_chainstate:flush()
    catch _:_ -> ok end,
    %% Best-effort PID-file removal. Match bitcoind's behavior in
    %% init/common.cpp ~RemovePidFile: only remove on graceful shutdown
    %% so a crash leaves a stale file as evidence (the file's process
    %% will not exist, so external tools can detect that).
    try remove_pidfile() catch _:_ -> ok end,
    %% Stop the application (closes DB, disconnects peers)
    application:stop(beamchain),
    ok.

%%% ===================================================================
%%% --daemon support
%%% ===================================================================
%%
%% bitcoind's daemon() in src/util/system.cpp wraps the C library
%% daemon(3) call.  Erlang has no exposed daemon(3), so we re-exec the
%% same escript via /bin/sh under nohup, drop --daemon from argv, and
%% append --_daemon-child to mark the child path so it doesn't fork
%% again.  The child inherits the same datadir/network env so the
%% behavior is identical to the foreground command.

daemonize(Opts) ->
    Self = case escript:script_name() of
        []   -> "_build/default/bin/beamchain";
        Name -> Name
    end,
    Args = rebuild_argv_for_daemon(Opts),
    Cmd = build_daemon_cmd(Self, Args),
    DataDir = resolve_datadir_for_daemon(Opts),
    LogPath = filename:join(DataDir, "beamchain.out"),
    ok = filelib:ensure_dir(LogPath),
    %% Spawn the child detached from this VM.  We use os:cmd indirectly
    %% via a shell redirect to /dev/null so erlang doesn't keep the
    %% fd open and block exit.
    FullCmd = io_lib:format(
        "nohup /bin/sh -c ~s >> ~s 2>&1 < /dev/null &",
        [shell_quote(Cmd), shell_quote(LogPath)]),
    _ = os:cmd(lists:flatten(FullCmd)),
    io:format("beamchain: daemonized; logs at ~s~n", [LogPath]),
    halt(0).

rebuild_argv_for_daemon(Opts) ->
    %% We re-emit only the recognized flags.  This keeps argv canonical
    %% and avoids round-tripping unknown garbage to the child.
    Network = maps:get(network, Opts, undefined),
    Datadir = maps:get(datadir, Opts, undefined),
    RpcPort = maps:get(rpc_port, Opts, undefined),
    P2PPort = maps:get(p2p_port, Opts, undefined),
    PidFile = maps:get(pidfile, Opts, undefined),
    Conf    = maps:get(conf, Opts, undefined),
    PrintTC = maps:get(printtoconsole, Opts, false),
    Debug   = maps:get(debug, Opts, false),
    Cats    = maps:get(debug_categories, Opts, []),
    lists:flatten([
        ["start"],
        opt("--network=", Network, fun atom_to_list/1),
        opt("--datadir=", Datadir, fun id/1),
        opt("--rpc-port=", RpcPort, fun integer_to_list/1),
        opt("--p2p-port=", P2PPort, fun integer_to_list/1),
        opt("--pid=", PidFile, fun id/1),
        opt("--conf=", Conf, fun id/1),
        case PrintTC of true -> ["--printtoconsole"]; _ -> [] end,
        case {Debug, Cats} of
            {true, []}   -> ["--debug"];
            {true, Cats} -> ["--debug=" ++ string:join(
                                lists:map(fun atom_to_list/1, Cats), ",")];
            _ -> []
        end,
        ["--_daemon-child"]
    ]).

opt(_Prefix, undefined, _Fmt) -> [];
opt(Prefix, Value, Fmt) -> [Prefix ++ Fmt(Value)].

id(X) -> X.

build_daemon_cmd(Self, Args) ->
    string:join([shell_quote(Self) | [shell_quote(A) || A <- Args]], " ").

shell_quote(S) when is_atom(S) -> shell_quote(atom_to_list(S));
shell_quote(S) when is_binary(S) -> shell_quote(binary_to_list(S));
shell_quote(S) when is_integer(S) -> shell_quote(integer_to_list(S));
shell_quote(S) when is_list(S) ->
    %% Single-quote and escape any embedded single quotes.
    "'" ++ lists:flatten([escape_squote(C) || C <- S]) ++ "'".

escape_squote($') -> "'\\''";
escape_squote(C)  -> [C].

resolve_datadir_for_daemon(Opts) ->
    case maps:get(datadir, Opts, undefined) of
        undefined ->
            Net = maps:get(network, Opts, mainnet),
            Home = os:getenv("HOME", "/tmp"),
            Base = filename:join(Home, ".beamchain"),
            case Net of
                mainnet -> Base;
                Other -> filename:join(Base, atom_to_list(Other))
            end;
        Dir -> Dir
    end.

%%% ===================================================================
%%% PID file management
%%% ===================================================================

%% @doc Compute the PID-file path. Honors --pid= override; otherwise
%% defaults to <datadir>/beamchain.pid.  Mirrors bitcoind's
%% g_pidfile_path in init/common.cpp.
pidfile_path(Opts) ->
    case maps:get(pidfile, Opts, undefined) of
        Path when is_list(Path), Path =/= "" ->
            Path;
        _ ->
            case application:get_env(beamchain, pidfile) of
                {ok, P} when is_list(P), P =/= "" -> P;
                _ ->
                    DataDir = beamchain_config:datadir(),
                    filename:join(DataDir, "beamchain.pid")
            end
    end.

%% Resolve the PID path WITHOUT requiring beamchain_config to be alive.
%% Used by remove_pidfile/0 during shutdown when the config gen_server
%% may already be dead.
pidfile_path_safe() ->
    case application:get_env(beamchain, pidfile) of
        {ok, P} when is_list(P), P =/= "" -> P;
        _ ->
            case catch beamchain_config:datadir() of
                Dir when is_list(Dir) -> filename:join(Dir, "beamchain.pid");
                _ -> undefined
            end
    end.

write_pidfile(Opts) ->
    Path = pidfile_path(Opts),
    OsPid = os:getpid(),  %% returns string()
    ok = filelib:ensure_dir(Path),
    case file:write_file(Path, OsPid ++ "\n") of
        ok ->
            application:set_env(beamchain, pidfile, Path, [{persistent, true}]),
            ok;
        {error, Reason} ->
            logger:warning("could not write pid file ~s: ~p", [Path, Reason]),
            ok
    end.

remove_pidfile() ->
    case pidfile_path_safe() of
        undefined -> ok;
        Path ->
            case file:delete(Path) of
                ok -> ok;
                {error, enoent} -> ok;
                {error, _} -> ok
            end
    end.

%%% ===================================================================
%%% --printtoconsole logger handler
%%% ===================================================================

maybe_setup_console_logger(Opts) ->
    Want = case maps:get(printtoconsole, Opts, false) of
        true -> true;
        false ->
            case application:get_env(beamchain, printtoconsole) of
                {ok, true} -> true;
                _ -> false
            end
    end,
    case Want of
        false -> ok;
        true ->
            %% standard_io handler.  add_handler/3 is idempotent enough:
            %% if the handler already exists we ignore the {already_exist}
            %% return.
            Cfg = #{
                level => info,
                config => #{type => standard_io},
                formatter => {logger_formatter, #{
                    template => [time, " [", level, "] ", msg, "\n"],
                    single_line => true
                }}
            },
            _ = logger:add_handler(beamchain_console_logger, logger_std_h, Cfg),
            ok
    end.

%%% ===================================================================
%%% --debug=<cat> per-module logger plumbing
%%% ===================================================================

%% @doc Bitcoin Core's `-debug=<cat>` lets the operator opt-in to
%% per-category debug output (net, rpc, mempool, validation, ...).
%% beamchain ships one module per such category, so we map category
%% names to module-name globs and call logger:set_module_level/2 for
%% each match.  Unknown categories log a notice but do not abort -- this
%% matches Core's behavior (UnsupportedLogCategory in logging.cpp).
apply_debug_categories(Cats) ->
    lists:foreach(fun apply_debug_category/1, Cats).

apply_debug_category(all) ->
    logger:set_primary_config(level, debug);
apply_debug_category(none) ->
    logger:set_primary_config(level, info);
apply_debug_category(Cat) ->
    case category_modules(Cat) of
        [] ->
            logger:notice("ignoring unknown debug category: ~p", [Cat]);
        Mods ->
            lists:foreach(
              fun(M) -> _ = logger:set_module_level(M, debug) end,
              Mods)
    end.

%% Map a category atom to the modules it covers.  Add new categories
%% here as the codebase grows; modules listed here MUST exist (we resolve
%% to ground truth via code:which/1 so a typo fails xref).
category_modules(net) ->
    [beamchain_peer, beamchain_peer_manager, beamchain_p2p_msg,
     beamchain_addrman, beamchain_listener, beamchain_proxy,
     beamchain_transport_v2, beamchain_v2_msg];
category_modules(rpc) ->
    [beamchain_rpc, beamchain_rest];
category_modules(mempool) ->
    [beamchain_mempool, beamchain_mempool_persist, beamchain_fee_estimator];
category_modules(validation) ->
    [beamchain_validation, beamchain_chainstate, beamchain_pow,
     beamchain_script, beamchain_versionbits];
category_modules(sync) ->
    [beamchain_sync, beamchain_block_sync, beamchain_header_sync];
category_modules(db) ->
    [beamchain_db];
category_modules(zmq) ->
    [beamchain_zmq];
category_modules(wallet) ->
    [beamchain_wallet, beamchain_wallet_sup, beamchain_descriptor];
category_modules(miner) ->
    [beamchain_miner];
category_modules(_Other) ->
    [].

parse_debug_cats(Str) ->
    [list_to_atom(string:trim(C)) || C <- string:split(Str, ",", all),
                                     string:trim(C) =/= ""].

parse_bool("1")     -> true;
parse_bool("0")     -> false;
parse_bool("true")  -> true;
parse_bool("false") -> false;
parse_bool(_)       -> true.

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
    "[" ++ green(lists:flatten(lists:duplicate(Filled, ?BLOCK_FULL))) ++
    dim(lists:flatten(lists:duplicate(Empty, ?BLOCK_LIGHT))) ++ "]".

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
