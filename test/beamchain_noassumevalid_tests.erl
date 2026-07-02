-module(beamchain_noassumevalid_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% --noassumevalid / --assumevalid=0 disable knob
%%%
%%% Verifies the mainnet-replay-harness (assumevalid=0) switch:
%%%   1. CLI parsing routes the flag into Opts (parse_args/1).
%%%   2. With BEAMCHAIN_ASSUMEVALID=0 set, beamchain_chain_params:params/1
%%%      zeroes the mainnet assume_valid field.
%%%   3. EFFECTIVE assert: with the knob on, the real skip_scripts/3 gate
%%%      (the one connect_block calls at validation.erl:1317) returns
%%%      false for a block BELOW the old assumevalid height (938343) — i.e.
%%%      full script verification runs for buried history.
%%%
%%% skip_scripts/3 with a zeroed assume_valid short-circuits at condition 1
%%% without any DB lookup, so these tests need no running database.
%%% ===================================================================

%% Env-var isolation: save/clear BEAMCHAIN_ASSUMEVALID, run Body, restore.
with_env(Value, Body) ->
    Prev = os:getenv("BEAMCHAIN_ASSUMEVALID"),
    try
        case Value of
            unset -> os:unsetenv("BEAMCHAIN_ASSUMEVALID");
            _     -> os:putenv("BEAMCHAIN_ASSUMEVALID", Value)
        end,
        Body()
    after
        case Prev of
            false -> os:unsetenv("BEAMCHAIN_ASSUMEVALID");
            _     -> os:putenv("BEAMCHAIN_ASSUMEVALID", Prev)
        end
    end.

%% --- CLI parsing --------------------------------------------------------

noassumevalid_flag_parses_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--noassumevalid"]),
    ?assertEqual(true, maps:get(noassumevalid, Opts, undefined)).

assumevalid_eq_zero_parses_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--assumevalid=0"]),
    ?assertEqual(true, maps:get(noassumevalid, Opts, undefined)).

assumevalid_space_zero_parses_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--assumevalid", "0"]),
    ?assertEqual(true, maps:get(noassumevalid, Opts, undefined)).

%% A non-zero --assumevalid value leaves the built-in default in place
%% (beamchain only wires the disable direction).
assumevalid_nonzero_keeps_default_test() ->
    {start, Opts} = beamchain_cli:parse_args(["start", "--assumevalid=1"]),
    ?assertEqual(false, maps:get(noassumevalid, Opts, undefined)).

%% --- params/1 override --------------------------------------------------

%% Control: without the knob, mainnet ships a real (non-zero, 32-byte)
%% assume_valid hash — so the gate is armed to skip by default.
default_mainnet_assume_valid_is_set_test() ->
    with_env(unset, fun() ->
        Params = beamchain_chain_params:params(mainnet),
        AV = maps:get(assume_valid, Params),
        ?assertEqual(32, byte_size(AV)),
        ?assertNotEqual(<<0:256>>, AV)
    end).

%% With the knob, params/1 zeroes the mainnet assume_valid field.
knob_zeroes_mainnet_assume_valid_test() ->
    with_env("0", fun() ->
        Params = beamchain_chain_params:params(mainnet),
        ?assertEqual(<<0:256>>, maps:get(assume_valid, Params))
    end).

%% "false"/"none" are accepted spellings of the disable sentinel.
knob_accepts_false_alias_test() ->
    with_env("false", fun() ->
        Params = beamchain_chain_params:params(mainnet),
        ?assertEqual(<<0:256>>, maps:get(assume_valid, Params))
    end).

%% A non-"0" env value must NOT disable (guards against accidental zeroing).
knob_off_leaves_default_test() ->
    with_env("1", fun() ->
        Params = beamchain_chain_params:params(mainnet),
        ?assertNotEqual(<<0:256>>, maps:get(assume_valid, Params))
    end).

%% --- EFFECTIVE assert: full verification of buried history --------------

%% With the knob on, the REAL gate (skip_scripts/3, as called by
%% connect_block) returns false for a block well below the pre-existing
%% mainnet assumevalid height (938343). false => scripts are verified in
%% full for that historical block. This is the computed skip=false the
%% replay harness depends on.
knob_forces_full_verify_below_av_height_test() ->
    with_env("0", fun() ->
        Params = beamchain_chain_params:params(mainnet),
        BelowAvHeight = 500000,           %% << 938343 (old assumevalid height)
        BlockHash = <<7:256>>,
        ?assertNot(
            beamchain_validation:skip_scripts(BelowAvHeight, BlockHash, Params))
    end).
