-module(beamchain_listdescriptors_tests).

%%% ===================================================================
%%% listdescriptors unit regression tests (Core parity).
%%%
%%% NO node / NO regtest: temp HOME, real wallet gen_servers, NO
%%% chainstate (the import rescan no-ops cleanly when the chainstate is
%%% down), driving the exported beamchain_rpc:handle_method/3 directly.
%%% Modeled on beamchain_watchonly_import_tests.
%%%
%%% Ground truth: bitcoin-core/src/wallet/rpc/backup.cpp:464-572
%%% (listdescriptors) + script/descriptor.cpp GetDescriptorChecksum.
%%%
%%% Asserts the Core shape:
%%%   { wallet_name, descriptors: [ { desc (#checksum), timestamp,
%%%     active, [internal active-only], [range/next/next_index ranged-only]
%%%     } ] } sorted by descriptor string.
%%% Checksums are RECOMPUTED with beamchain_descriptor:descriptor_checksum
%%% and compared (NOT hardcoded).  private=true on a watch-only wallet ->
%%% -4; a non-bool private param -> -3.
%%% ===================================================================

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%% Syntactically valid 33-byte compressed pubkeys (hash-only paths; no
%% curve ops are performed for wpkh()/addr()).
-define(PUBHEX,
        "020000000000000000000000000000000000000000000000000000000000000001").
-define(PUBHEX2,
        "030000000000000000000000000000000000000000000000000000000000000002").

setup() ->
    Home = "/tmp/bc_listdescriptors_"
        ++ integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(Home ++ "/"),
    PrevHome = os:getenv("HOME"),
    true = os:putenv("HOME", Home),
    _ = stop_proc(beamchain_wallet),
    _ = stop_proc(beamchain_wallet_sup),
    catch ets:delete(beamchain_wallet_registry),
    {ok, SupPid} = beamchain_wallet_sup:start_link(),
    true = unlink(SupPid),
    {Home, PrevHome}.

cleanup({Home, PrevHome}) ->
    _ = stop_proc(beamchain_wallet_sup),
    _ = stop_proc(beamchain_wallet),
    catch ets:delete(beamchain_wallet_registry),
    case PrevHome of
        false -> os:unsetenv("HOME");
        _     -> os:putenv("HOME", PrevHome)
    end,
    _ = os:cmd("rm -rf " ++ Home),
    ok.

stop_proc(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            MRef = erlang:monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', MRef, process, Pid, _} -> ok
            after 2000 -> ok
            end
    end.

rpc(Method, Params, Wallet) ->
    beamchain_rpc:handle_method(Method, Params, Wallet).

%% Helpers ------------------------------------------------------------

p2wpkh_addr(PubHex) ->
    Pub = hex_to_bin(PubHex),
    list_to_binary(beamchain_wallet:pubkey_to_p2wpkh(Pub, mainnet)).

hex_to_bin(Hex) ->
    beamchain_serialize:hex_decode(list_to_binary(Hex)).

%% Canonical descriptor string WITH the trailing #checksum, computed via
%% the production add_checksum/1 (which delegates to descriptor_checksum/1).
checksummed(Body) ->
    list_to_binary(beamchain_descriptor:add_checksum(Body)).

%% Split "<body>#<checksum>" into {Body, Checksum} (strings).
split_checksum(DescBin) when is_binary(DescBin) ->
    case binary:split(DescBin, <<"#">>) of
        [Body, Chk] -> {binary_to_list(Body), binary_to_list(Chk)};
        [Body]      -> {binary_to_list(Body), ""}
    end.

listdescriptors_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun t_shape_and_correct_checksum/1,
      fun t_sort_order/1,
      fun t_private_true_watchonly_minus4/1,
      fun t_private_nonbool_minus3/1,
      fun t_empty_wallet/1
     ]}.

%%% -------------------------------------------------------------------
%%% Core shape: wallet_name + descriptors[]; desc carries a CORRECT
%%% (recomputed) checksum; timestamp + active present; internal omitted;
%%% no range/next for a non-ranged watch-only descriptor.
%%% -------------------------------------------------------------------
t_shape_and_correct_checksum({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"ld1">>, true, true], <<>>),
        AddrBody = "addr(" ++ binary_to_list(p2wpkh_addr(?PUBHEX)) ++ ")",
        Desc = checksummed(AddrBody),
        {ok, [R]} = rpc(<<"importdescriptors">>,
                        [[#{<<"desc">> => Desc, <<"timestamp">> => 1700000000}]],
                        <<"ld1">>),
        ?assertEqual(true, maps:get(<<"success">>, R)),

        Result = expect_ok(rpc(<<"listdescriptors">>, [], <<"ld1">>)),
        ?assert(is_map(Result)),
        ?assertEqual(<<"ld1">>, maps:get(<<"wallet_name">>, Result)),
        Descs = maps:get(<<"descriptors">>, Result),
        ?assert(is_list(Descs)),
        ?assertEqual(1, length(Descs)),
        [D] = Descs,

        %% desc carries the trailing #checksum.
        DescOut = maps:get(<<"desc">>, D),
        ?assertEqual(Desc, DescOut),
        {Body, Chk} = split_checksum(DescOut),
        %% CORRECT checksum: recompute with descriptor_checksum and compare
        %% (NOT hardcoded).
        ?assertEqual(8, length(Chk)),
        ?assertEqual(beamchain_descriptor:descriptor_checksum(Body), Chk),

        %% timestamp echoed; active=false for a watch-only import.
        ?assertEqual(1700000000, maps:get(<<"timestamp">>, D)),
        ?assertEqual(false, maps:get(<<"active">>, D)),
        %% internal is emitted ONLY for active descriptors -> omitted here.
        ?assertEqual(error, maps:find(<<"internal">>, D)),
        %% non-ranged addr(): no range/next/next_index.
        ?assertEqual(error, maps:find(<<"range">>, D)),
        ?assertEqual(error, maps:find(<<"next">>, D)),
        ?assertEqual(error, maps:find(<<"next_index">>, D))
    end}.

%%% -------------------------------------------------------------------
%%% Sorted by descriptor string (backup.cpp:541-543).
%%% -------------------------------------------------------------------
t_sort_order({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"ld2">>, true, true], <<>>),
        %% Two distinct watch-only descriptors.  addr(...) sorts before
        %% wpkh(...) lexicographically ('a' < 'w').
        AddrDesc = checksummed(
            "addr(" ++ binary_to_list(p2wpkh_addr(?PUBHEX)) ++ ")"),
        WpkhDesc = checksummed("wpkh(" ++ ?PUBHEX2 ++ ")"),
        {ok, [_, _]} = rpc(<<"importdescriptors">>,
            [[#{<<"desc">> => WpkhDesc, <<"timestamp">> => 1},
              #{<<"desc">> => AddrDesc, <<"timestamp">> => 2}]], <<"ld2">>),

        Result = expect_ok(rpc(<<"listdescriptors">>, [false], <<"ld2">>)),
        Descs = maps:get(<<"descriptors">>, Result),
        ?assertEqual(2, length(Descs)),
        Strs = [maps:get(<<"desc">>, D) || D <- Descs],
        ?assertEqual(lists:sort(Strs), Strs),
        ?assertEqual([AddrDesc, WpkhDesc], Strs)
    end}.

%%% -------------------------------------------------------------------
%%% private=true on a watch-only (disable_private_keys) wallet -> -4.
%%% -------------------------------------------------------------------
t_private_true_watchonly_minus4({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"ld3">>, true, true], <<>>),
        ?assertEqual(
            {error, -4,
             <<"Can't get private descriptor string for watch-only wallets">>},
            rpc(<<"listdescriptors">>, [true], <<"ld3">>))
    end}.

%%% -------------------------------------------------------------------
%%% non-bool private param -> -3 (RPC_TYPE_ERROR).
%%% -------------------------------------------------------------------
t_private_nonbool_minus3({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"ld4">>, true, true], <<>>),
        {error, Code, _Msg} =
            rpc(<<"listdescriptors">>, [<<"yes">>], <<"ld4">>),
        ?assertEqual(-3, Code)
    end}.

%%% -------------------------------------------------------------------
%%% Empty wallet (no imports): wallet_name + empty descriptors array.
%%% -------------------------------------------------------------------
t_empty_wallet({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"ld5">>, true, true], <<>>),
        Result = expect_ok(rpc(<<"listdescriptors">>, [], <<"ld5">>)),
        ?assertEqual(<<"ld5">>, maps:get(<<"wallet_name">>, Result)),
        ?assertEqual([], maps:get(<<"descriptors">>, Result))
    end}.

%% Unwrap a successful handle_method/3 result (either {ok, Map} or
%% {ok_raw_json, Bin}).
expect_ok({ok, Map}) when is_map(Map) ->
    Map;
expect_ok({ok_raw_json, Bin}) ->
    jsx:decode(Bin, [return_maps]).
