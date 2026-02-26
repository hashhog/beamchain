-module(beamchain_cli).

%% Escript entry point and command-line interface for beamchain.

-include("beamchain.hrl").

-export([main/1]).

-define(VERSION, "0.1.0").

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
    show_status(Opts);
run_command(stop, Opts) ->
    stop_node(Opts);
run_command(getbalance, Opts) ->
    get_balance(Opts);
run_command(Unknown, _Opts) ->
    io:format(standard_error, "unknown command: ~s~n~n", [Unknown]),
    print_usage(),
    halt(1).

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
        "  --datadir=<dir>   data directory (default: ~/.beamchain)~n"
        "  --rpc-port=<n>    rpc port override~n"
        "  --p2p-port=<n>    p2p port override~n"
        "  --debug           enable debug logging~n"
        "  --reset           reset chain data before sync~n"
        "  --limit=<n>       limit sync to n blocks~n"
        "  -h, --help        show this help~n"
        "  -v, --version     show version~n",
        [header("beamchain " ++ ?VERSION ++ " — bitcoin full node in erlang/otp"),
         dim("usage:"),
         dim("commands:"),
         dim("options:")]).

%%% ===================================================================
%%% Stub commands (filled in next commits)
%%% ===================================================================

start_node(_Opts) ->
    io:format("start_node: not yet implemented~n"),
    halt(1).

sync_blockchain(_Opts) ->
    io:format("sync: not yet implemented~n"),
    halt(1).

show_status(_Opts) ->
    io:format("status: not yet implemented~n"),
    halt(1).

stop_node(_Opts) ->
    io:format("stop: not yet implemented~n"),
    halt(1).

get_balance(_Opts) ->
    io:format("getbalance: not yet implemented~n"),
    halt(1).

%%% ===================================================================
%%% ANSI color helpers
%%% ===================================================================

header(Text) -> color("1", Text).    %% bold
dim(Text)    -> color("2", Text).    %% dim

color(Code, Text) ->
    case is_tty() of
        true  -> "\e[" ++ Code ++ "m" ++ Text ++ "\e[0m";
        false -> Text
    end.

is_tty() ->
    case os:getenv("NO_COLOR") of
        false ->
            %% heuristic: assume tty unless piped
            case os:type() of
                {unix, _} -> true;
                _ -> false
            end;
        _ ->
            false
    end.
