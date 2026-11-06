%% -maxmempool (Core node/mempool_args.cpp: max_size_bytes = MB * 1'000'000).
%% Policy cause #14: --maxmempool=5 was ignored; getmempoolinfo said 300000000.
-module(beamchain_maxmempool_tests).
-include_lib("eunit/include/eunit.hrl").

with_env(Val, Fun) ->
    Old = os:getenv("BEAMCHAIN_MAXMEMPOOL"),
    case Val of
        unset -> os:unsetenv("BEAMCHAIN_MAXMEMPOOL");
        _ -> os:putenv("BEAMCHAIN_MAXMEMPOOL", Val)
    end,
    try Fun() after
        case Old of
            false -> os:unsetenv("BEAMCHAIN_MAXMEMPOOL");
            _ -> os:putenv("BEAMCHAIN_MAXMEMPOOL", Old)
        end
    end.

default_is_core_300mb_test() ->
    with_env(unset, fun() ->
        ?assertEqual(300000000, beamchain_config:maxmempool_bytes())
    end).

env_megabytes_test() ->
    with_env("5", fun() ->
        ?assertEqual(5000000, beamchain_config:maxmempool_bytes())
    end).

garbage_falls_back_to_default_test() ->
    with_env("abc", fun() ->
        ?assertEqual(300000000, beamchain_config:maxmempool_bytes())
    end).

cli_flag_parsed_test() ->
    {start, O} = beamchain_cli:parse_args(["start", "--maxmempool=5"]),
    ?assertEqual("5", maps:get(maxmempool, O)),
    {start, O2} = beamchain_cli:parse_args(["start", "-maxmempool=7"]),
    ?assertEqual("7", maps:get(maxmempool, O2)).

getmempoolinfo_reports_configured_maxmempool_test() ->
    with_env("5", fun() ->
        PL = beamchain_rpc:mempoolinfo_proplist(0, 0, 0.0, true),
        ?assertEqual(5000000, proplists:get_value(<<"maxmempool">>, PL))
    end).
