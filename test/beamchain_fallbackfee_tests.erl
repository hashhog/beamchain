-module(beamchain_fallbackfee_tests).
-include_lib("eunit/include/eunit.hrl").

%%% Core-style -fallbackfee (wallet/fees.cpp GetMinimumFeeRate): estimator,
%%% else -fallbackfee, else -6. No fee estimator is running in eunit, which
%%% is the "estimation has no data" case.

with_env(Val, Fun) ->
    Old = os:getenv("BEAMCHAIN_FALLBACKFEE"),
    case Val of
        unset -> os:unsetenv("BEAMCHAIN_FALLBACKFEE");
        _ -> os:putenv("BEAMCHAIN_FALLBACKFEE", Val)
    end,
    try Fun()
    after
        case Old of
            false -> os:unsetenv("BEAMCHAIN_FALLBACKFEE");
            _ -> os:putenv("BEAMCHAIN_FALLBACKFEE", Old)
        end
    end.

cli_eq_form_test() ->
    {start, O} = beamchain_cli:parse_args(["start", "--fallbackfee=0.0002"]),
    ?assertEqual("0.0002", maps:get(fallbackfee, O)).

cli_core_spelling_test() ->
    {start, O} = beamchain_cli:parse_args(["start", "-fallbackfee=0.0001"]),
    ?assertEqual("0.0001", maps:get(fallbackfee, O)).

config_default_disabled_test() ->
    with_env(unset, fun() ->
        ?assertEqual(0, beamchain_config:fallbackfee_satvb()) end).

config_converts_btc_kvb_to_sat_vb_test() ->
    with_env("0.0002", fun() ->
        ?assert(abs(beamchain_config:fallbackfee_satvb() - 20.0) < 1.0e-9) end).

send_fee_rate_uses_fallback_test() ->
    with_env("0.0002", fun() ->
        ?assert(abs(beamchain_rpc:wallet_default_fee_rate() - 20.0) < 1.0e-9) end).

send_fee_rate_fails_minus6_without_fallback_test() ->
    with_env(unset, fun() ->
        ?assertThrow({rpc_error, -6,
                      <<"Fee estimation failed. Fallbackfee is disabled. "
                        "Wait a few blocks or enable -fallbackfee.">>},
                     beamchain_rpc:wallet_default_fee_rate()) end).
