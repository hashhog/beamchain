-module(beamchain_fallbackfee_tests).
-include_lib("eunit/include/eunit.hrl").

%%% Core-style -fallbackfee (wallet/fees.cpp GetMinimumFeeRate): estimator,
%%% else -fallbackfee, else fail (-6 or -4 by RPC). No fee estimator is running in eunit, which
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
        ?assert(beamchain_config:fallbackfee_satvb() == 0) end).

config_converts_btc_kvb_to_sat_vb_test() ->
    with_env("0.0002", fun() ->
        ?assert(abs(beamchain_config:fallbackfee_satvb() - 20.0) < 1.0e-9) end).

send_fee_rate_uses_fallback_test() ->
    with_env("0.0002", fun() ->
        ?assert(abs(beamchain_rpc:wallet_default_fee_rate(-6) - 20.0) < 1.0e-9) end).

-define(FB_DISABLED, <<"Fee estimation failed. Fallbackfee is disabled. "
                       "Wait a few blocks or enable -fallbackfee.">>).

%% sendtoaddress / sendmany: Core SendMoney -> RPC_WALLET_INSUFFICIENT_FUNDS.
send_fee_rate_fails_minus6_without_fallback_test() ->
    with_env(unset, fun() ->
        ?assertThrow({rpc_error, -6, ?FB_DISABLED},
                     beamchain_rpc:wallet_default_fee_rate(-6)) end).

%% send: Core FundTransaction -> RPC_WALLET_ERROR (-4), same text.
send_rpc_fails_minus4_without_fallback_test() ->
    with_env("0", fun() ->
        ?assertThrow({rpc_error, -4, ?FB_DISABLED},
                     beamchain_rpc:wallet_default_fee_rate(-4)) end).

%%% Core ParseMoney (util/moneystr.cpp) on -fallbackfee.

parse_money_accepts_test_() ->
    [?_assertEqual({ok, Sat}, beamchain_config:parse_money(S))
     || {S, Sat} <- [{"0", 0}, {"0.0002", 20000}, {"1", 100000000},
                     {" 0.0001\t", 10000}, {"0.00000001", 1},
                     {"21000000", 2100000000000000}, {".5", 50000000},
                     {"1.", 100000000}, {".", 0}, {"0.05", 5000000}]].

parse_money_rejects_test_() ->
    [?_assertEqual(error, beamchain_config:parse_money(S))
     || S <- ["", "   ", "-0.0001", "+0.0001", "0 .0001", "0.00 01",
              "abc", "0.0001x", "1e-4", "0.000000001", "21000000.00000001",
              "12345678901", "0..1", [$0, 0, $1]]].

%% Core wallet.cpp: Invalid amount -> startup refused, not "disabled".
startup_refuses_invalid_fallbackfee_test_() ->
    [?_test(with_env(V, fun() ->
         ?assertEqual({error, iolist_to_binary(
                                ["Invalid amount for -fallbackfee=<amount>: '",
                                 V, "'"])},
                      beamchain_config:check_fallbackfee())
       end)) || V <- ["-0.0001", "abc", "0.0001x", "0.000000001", "1 0", ""]].

invalid_fallbackfee_is_not_disabled_test() ->
    with_env("abc", fun() ->
        ?assertError({invalid_fallbackfee, _},
                     beamchain_config:fallbackfee_satvb()) end).

fallbackfee_trims_whitespace_test() ->
    with_env(" 0.0002 ", fun() ->
        ?assertEqual(ok, beamchain_config:check_fallbackfee()),
        ?assert(abs(beamchain_config:fallbackfee_satvb() - 20.0) < 1.0e-9) end).

%% Above HIGH_TX_FEE_PER_KB (0.01 BTC/kvB): kept, startup only warns.
high_fallbackfee_kept_with_warning_test() ->
    with_env("0.05", fun() ->
        ?assertMatch({warning, <<"-fallbackfee is set very high!", _/binary>>},
                     beamchain_config:check_fallbackfee()),
        ?assert(abs(beamchain_config:fallbackfee_satvb() - 5000.0) < 1.0e-9) end).

at_high_fee_threshold_no_warning_test() ->
    with_env("0.01", fun() ->
        ?assertEqual(ok, beamchain_config:check_fallbackfee()) end).

%%% Core GetMinimumFeeRate (wallet/fees.cpp) clamps.

%% 0.1 sat/vB fallback is raised to the 1 sat/vB required fee.
low_fallback_raised_to_required_fee_test() ->
    with_env("0.000001", fun() ->
        ?assert(abs(beamchain_rpc:wallet_default_fee_rate(-6) - 1.0) < 1.0e-9)
    end).

fallback_raised_to_mempool_min_test() ->
    ?assertEqual({ok, 7.5},
                 beamchain_rpc:wallet_min_fee_rate({error, no_data}, 2.0, 7.5)).

estimate_raised_to_mempool_min_test() ->
    ?assertEqual({ok, 4.0},
                 beamchain_rpc:wallet_min_fee_rate({ok, 3.0}, 0, 4.0)).

estimate_raised_to_required_fee_test() ->
    ?assertEqual({ok, 1.0},
                 beamchain_rpc:wallet_min_fee_rate({ok, 0.2}, 0, 0.1)).

estimate_above_floors_used_raw_test() ->
    ?assertEqual({ok, 12.5},
                 beamchain_rpc:wallet_min_fee_rate({ok, 12.5}, 20.0, 0.1)).

%% A zero fallback is not raised to any floor: it must still error.
zero_fallback_not_raised_test() ->
    ?assertEqual(fallback_disabled,
                 beamchain_rpc:wallet_min_fee_rate({error, no_data}, 0, 50.0)).
