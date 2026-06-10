-module(beamchain_watchonly_import_tests).

%%% ===================================================================
%%% Watch-only unit regression tests (importdescriptors / createwallet /
%%% getaddressinfo / getwalletinfo — Core parity, 2026-06 watch-only
%%% campaign).  Modeled on beamchain_wallet_persist_tests: temp HOME,
%%% real gen_servers, NO chainstate (the import rescan and balance paths
%%% no-op cleanly when the chainstate is down), driving the exported
%%% beamchain_rpc:handle_method/3 directly.
%%%
%%% Ground truth: bitcoin-core/src/wallet/rpc/backup.cpp:127-460
%%% (ProcessDescriptorImport + GetImportTimestamp), script/descriptor.cpp
%%% :2838-2869 (CheckChecksum strings), wallet/rpc/wallet.cpp:346-432
%%% (createwallet), wallet/rpc/addresses.cpp:423-510 (getaddressinfo).
%%% ===================================================================

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%% Syntactically valid 33-byte compressed pubkeys (hash-only paths; no
%% curve ops are performed for wpkh()).
-define(PUBHEX,
        "020000000000000000000000000000000000000000000000000000000000000001").
-define(PUBHEX2,
        "030000000000000000000000000000000000000000000000000000000000000002").
-define(PUBHEX3,
        "020000000000000000000000000000000000000000000000000000000000000003").

setup() ->
    Home = "/tmp/bc_watchonly_import_"
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

start_default_wallet() ->
    {ok, Pid} = beamchain_wallet:start_link(),
    true = unlink(Pid),
    Pid.

rpc(Method, Params, Wallet) ->
    beamchain_rpc:handle_method(Method, Params, Wallet).

%% Helpers ------------------------------------------------------------

p2wpkh_addr(PubHex) ->
    Pub = hex_to_bin(PubHex),
    list_to_binary(beamchain_wallet:pubkey_to_p2wpkh(Pub, mainnet)).

hex_to_bin(Hex) ->
    beamchain_serialize:hex_decode(list_to_binary(Hex)).

checksummed(Body) ->
    list_to_binary(beamchain_descriptor:add_checksum(Body)).

wif_testnet_compressed(PrivKey32) ->
    list_to_binary(
        beamchain_address:base58check_encode(
            16#ef, <<PrivKey32/binary, 16#01>>)).

decode_walletinfo(Name) ->
    {ok_raw_json, Bin} = rpc(<<"getwalletinfo">>, [], Name),
    jsx:decode(Bin, [return_maps]).

watchonly_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun t_createwallet_named_args_dpk/1,
      fun t_createwallet_positional_dpk/1,
      fun t_createwallet_dpk_passphrase_minus4/1,
      fun t_createwallet_descriptors_false_minus4/1,
      fun t_import_timestamp_whole_batch_minus3/1,
      fun t_import_checksum_minus5_per_element/1,
      fun t_import_privkey_into_dpk_minus4/1,
      fun t_import_watchonly_into_priv_wallet_minus4/1,
      fun t_import_registers_persists_reloads/1,
      fun t_getaddressinfo_shapes/1
     ]}.

%%% -------------------------------------------------------------------
%%% createwallet — Core arg set + dpk honored end-to-end
%%% -------------------------------------------------------------------
t_createwallet_named_args_dpk({_Home, _}) ->
    {timeout, 120, fun() ->
        R = rpc(<<"createwallet">>,
                #{<<"wallet_name">> => <<"wo1">>,
                  <<"disable_private_keys">> => true,
                  <<"blank">> => true}, <<>>),
        ?assertMatch({ok, _}, R),
        {ok, Plist} = R,
        ?assertEqual(<<"wo1">>, proplists:get_value(<<"name">>, Plist)),
        Info = decode_walletinfo(<<"wo1">>),
        ?assertEqual(false, maps:get(<<"private_keys_enabled">>, Info)),
        %% dpk wallet hands out no key-derived addresses (Core -4).
        ?assertMatch({error, -4, <<"Error: This wallet has no available keys">>},
                     rpc(<<"getnewaddress">>, [], <<"wo1">>)),
        %% ... and can never spend (Core -4, checked before coin selection).
        ?assertMatch({error, -4, _},
                     rpc(<<"sendtoaddress">>,
                         [p2wpkh_addr(?PUBHEX), 1], <<"wo1">>))
    end}.

t_createwallet_positional_dpk({_Home, _}) ->
    {timeout, 120, fun() ->
        ?assertMatch({ok, _},
                     rpc(<<"createwallet">>, [<<"wo2">>, true, true], <<>>)),
        Info = decode_walletinfo(<<"wo2">>),
        ?assertEqual(false, maps:get(<<"private_keys_enabled">>, Info)),
        %% Plain single-arg form still works and keeps privkeys enabled.
        ?assertMatch({ok, _}, rpc(<<"createwallet">>, [<<"pe1">>], <<>>)),
        Info2 = decode_walletinfo(<<"pe1">>),
        ?assertEqual(true, maps:get(<<"private_keys_enabled">>, Info2))
    end}.

t_createwallet_dpk_passphrase_minus4({_Home, _}) ->
    {timeout, 120, fun() ->
        {error, Code, Msg} =
            rpc(<<"createwallet">>,
                [<<"wo3">>, true, true, <<"secret">>], <<>>),
        ?assertEqual(-4, Code),
        ?assertMatch({_, _}, binary:match(Msg, <<"private keys are disabled">>))
    end}.

t_createwallet_descriptors_false_minus4({_Home, _}) ->
    {timeout, 120, fun() ->
        {error, Code, Msg} =
            rpc(<<"createwallet">>,
                [<<"wo4">>, false, false, null, false, false], <<>>),
        ?assertEqual(-4, Code),
        ?assertMatch({_, _}, binary:match(Msg, <<"legacy wallet">>))
    end}.

%%% -------------------------------------------------------------------
%%% importdescriptors — whole-batch -3 timestamp gate (backup.cpp:390)
%%% -------------------------------------------------------------------
t_import_timestamp_whole_batch_minus3({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"wo5">>, true, true], <<>>),
        GoodDesc = checksummed("addr("
            ++ binary_to_list(p2wpkh_addr(?PUBHEX)) ++ ")"),
        %% Missing timestamp aborts the WHOLE batch even when another
        %% element is fine (Core evaluates it outside the per-element
        %% try/catch).
        ?assertEqual(
            {error, -3, <<"Missing required timestamp field for key">>},
            rpc(<<"importdescriptors">>,
                [[#{<<"desc">> => GoodDesc, <<"timestamp">> => 0},
                  #{<<"desc">> => GoodDesc}]], <<"wo5">>)),
        %% Wrong type -> -3 with the Core message (got type bool).
        {error, -3, Msg} =
            rpc(<<"importdescriptors">>,
                [[#{<<"desc">> => GoodDesc, <<"timestamp">> => true}]],
                <<"wo5">>),
        ?assertMatch({_, _}, binary:match(Msg,
            <<"Expected number or \"now\" timestamp value for key">>)),
        ?assertMatch({_, _}, binary:match(Msg, <<"bool">>))
    end}.

%%% -------------------------------------------------------------------
%%% importdescriptors — checksum -5, per-element, batch never aborts
%%% -------------------------------------------------------------------
t_import_checksum_minus5_per_element({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"wo6">>, true, true], <<>>),
        AddrDesc = "addr(" ++ binary_to_list(p2wpkh_addr(?PUBHEX)) ++ ")",
        NoChk = list_to_binary("wpkh(" ++ ?PUBHEX ++ ")"),
        BadChk = <<(checksummed(AddrDesc))/binary>>,
        %% Corrupt the last checksum char ('q' <-> 'p' are distinct
        %% bech32 symbols).
        Sz = byte_size(BadChk) - 1,
        <<Pre:Sz/binary, LastC>> = BadChk,
        Corrupt = <<Pre/binary, (case LastC of $q -> $p; _ -> $q end)>>,
        {ok, [R1, R2, R3]} =
            rpc(<<"importdescriptors">>,
                [[#{<<"desc">> => NoChk, <<"timestamp">> => 0},
                  #{<<"desc">> => Corrupt, <<"timestamp">> => 0},
                  #{<<"desc">> => checksummed(AddrDesc),
                    <<"timestamp">> => 0}]], <<"wo6">>),
        %% Element 1: missing checksum, Core-exact -5 string.
        ?assertEqual(false, maps:get(<<"success">>, R1)),
        ?assertEqual(-5, maps:get(<<"code">>, maps:get(<<"error">>, R1))),
        ?assertEqual(<<"Missing checksum">>,
                     maps:get(<<"message">>, maps:get(<<"error">>, R1))),
        %% Element 2: checksum mismatch -5 with both checksums named.
        ?assertEqual(false, maps:get(<<"success">>, R2)),
        ?assertEqual(-5, maps:get(<<"code">>, maps:get(<<"error">>, R2))),
        ?assertMatch({_, _},
            binary:match(maps:get(<<"message">>, maps:get(<<"error">>, R2)),
                         <<"does not match computed checksum">>)),
        %% Element 3 (valid) still succeeded: a failure never aborts the
        %% batch and order/length are preserved.
        ?assertEqual(true, maps:get(<<"success">>, R3)),
        %% Missing desc key -> -8 "Descriptor not found." (backup.cpp:147).
        {ok, [R4]} = rpc(<<"importdescriptors">>,
                         [[#{<<"timestamp">> => 0}]], <<"wo6">>),
        ?assertEqual(-8, maps:get(<<"code">>, maps:get(<<"error">>, R4))),
        ?assertEqual(<<"Descriptor not found.">>,
                     maps:get(<<"message">>, maps:get(<<"error">>, R4)))
    end}.

%%% -------------------------------------------------------------------
%%% importdescriptors — privkey-into-dpk -4 (and the mirror rule)
%%% -------------------------------------------------------------------
t_import_privkey_into_dpk_minus4({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"wo7">>, true, true], <<>>),
        Wif = wif_testnet_compressed(<<1:256>>),   %% scalar 1 — valid key
        PrivDesc = checksummed("wpkh(" ++ binary_to_list(Wif) ++ ")"),
        {ok, [R]} = rpc(<<"importdescriptors">>,
                        [[#{<<"desc">> => PrivDesc, <<"timestamp">> => 0}]],
                        <<"wo7">>),
        ?assertEqual(false, maps:get(<<"success">>, R)),
        ?assertEqual(-4, maps:get(<<"code">>, maps:get(<<"error">>, R))),
        ?assertEqual(<<"Cannot import private keys to a wallet with "
                       "private keys disabled">>,
                     maps:get(<<"message">>, maps:get(<<"error">>, R)))
    end}.

t_import_watchonly_into_priv_wallet_minus4({_Home, _}) ->
    {timeout, 120, fun() ->
        {ok, _} = rpc(<<"createwallet">>, [<<"pe2">>], <<>>),
        Desc = checksummed("wpkh(" ++ ?PUBHEX ++ ")"),
        {ok, [R]} = rpc(<<"importdescriptors">>,
                        [[#{<<"desc">> => Desc, <<"timestamp">> => 0}]],
                        <<"pe2">>),
        ?assertEqual(false, maps:get(<<"success">>, R)),
        ?assertEqual(-4, maps:get(<<"code">>, maps:get(<<"error">>, R))),
        ?assertEqual(<<"Cannot import descriptor without private keys to "
                       "a wallet with private keys enabled">>,
                     maps:get(<<"message">>, maps:get(<<"error">>, R)))
    end}.

%%% -------------------------------------------------------------------
%%% The stub replacement: import REGISTERS scripts, persists, reloads
%%% -------------------------------------------------------------------
t_import_registers_persists_reloads({_Home, _}) ->
    {timeout, 120, fun() ->
        %% Default wallet (registered process — resolve_wallet(<<>>)).
        Pid = start_default_wallet(),
        {ok, _} = gen_server:call(
                      Pid, {create, crypto:strong_rand_bytes(32), undefined,
                            #{disable_private_keys => true, blank => true}}),
        Addr = p2wpkh_addr(?PUBHEX),
        {ok, Script} = beamchain_address:address_to_script(
                           binary_to_list(Addr), mainnet),
        ?assertNot(beamchain_wallet:is_wallet_script(Script)),
        Desc = checksummed("addr(" ++ binary_to_list(Addr) ++ ")"),
        {ok, [R]} = rpc(<<"importdescriptors">>,
                        [[#{<<"desc">> => Desc, <<"timestamp">> => 0,
                            <<"label">> => <<"wo">>}]], <<>>),
        ?assertEqual(true, maps:get(<<"success">>, R)),
        %% REAL registration: the block-connect scan would now credit it.
        ?assert(beamchain_wallet:is_wallet_script(Script)),
        %% No gen_server crash on key ops against a path-less watch entry.
        ?assertEqual({error, not_found},
                     beamchain_wallet:get_private_key(
                         Pid, binary_to_list(Addr))),
        ?assert(is_process_alive(Pid)),
        %% Survives an UNCLEAN restart (ETS dies with the process; the
        %% persisted addresses list re-registers the script on load).
        ok = stop_proc(beamchain_wallet),
        Pid2 = start_default_wallet(),
        _ = Pid2,
        ?assert(beamchain_wallet:is_wallet_script(Script)),
        ok = stop_proc(beamchain_wallet)
    end}.

%%% -------------------------------------------------------------------
%%% getaddressinfo — Core field order + watch-only shapes
%%% -------------------------------------------------------------------
t_getaddressinfo_shapes({_Home, _}) ->
    {timeout, 120, fun() ->
        Pid = start_default_wallet(),
        {ok, _} = gen_server:call(
                      Pid, {create, crypto:strong_rand_bytes(32), undefined,
                            #{disable_private_keys => true, blank => true}}),
        AddrA = p2wpkh_addr(?PUBHEX),
        DescA = checksummed("addr(" ++ binary_to_list(AddrA) ++ ")"),
        DescW = checksummed("wpkh(" ++ ?PUBHEX2 ++ ")"),
        {ok, [_, _]} = rpc(<<"importdescriptors">>,
                           [[#{<<"desc">> => DescA, <<"timestamp">> => 0,
                               <<"label">> => <<"wo">>},
                             #{<<"desc">> => DescW, <<"timestamp">> => 0}]],
                           <<>>),
        %% addr(A): ismine, NOT solvable, NO desc, parent_desc present.
        {ok, P1} = rpc(<<"getaddressinfo">>, [AddrA], <<>>),
        ?assertEqual(true, proplists:get_value(<<"ismine">>, P1)),
        ?assertEqual(false, proplists:get_value(<<"solvable">>, P1)),
        ?assertEqual(undefined, proplists:get_value(<<"desc">>, P1)),
        ?assertEqual(DescA, proplists:get_value(<<"parent_desc">>, P1)),
        ?assertEqual(false, proplists:get_value(<<"iswatchonly">>, P1)),
        ?assertEqual([<<"wo">>], proplists:get_value(<<"labels">>, P1)),
        %% Core pushKV order: address first ... labels LAST.
        Keys1 = [K || {K, _} <- P1],
        ?assertEqual([<<"address">>, <<"scriptPubKey">>, <<"ismine">>,
                      <<"solvable">>, <<"parent_desc">>, <<"iswatchonly">>,
                      <<"isscript">>, <<"iswitness">>],
                     lists:sublist(Keys1, 8)),
        ?assertEqual(<<"labels">>, lists:last(Keys1)),
        %% wpkh(PUB): solvable with desc + the pubkey known.
        PubAddr = p2wpkh_addr(?PUBHEX2),
        {ok, P2} = rpc(<<"getaddressinfo">>, [PubAddr], <<>>),
        ?assertEqual(true, proplists:get_value(<<"ismine">>, P2)),
        ?assertEqual(true, proplists:get_value(<<"solvable">>, P2)),
        ?assertEqual(DescW, proplists:get_value(<<"desc">>, P2)),
        ?assertEqual(list_to_binary(?PUBHEX2),
                     proplists:get_value(<<"pubkey">>, P2, undefined)),
        ?assertEqual(0, proplists:get_value(<<"witness_version">>, P2)),
        %% Unknown-but-valid address: ismine false, empty labels, no error.
        Other = p2wpkh_addr(?PUBHEX3),
        {ok, P3} = rpc(<<"getaddressinfo">>, [Other], <<>>),
        ?assertEqual(false, proplists:get_value(<<"ismine">>, P3)),
        ?assertEqual([], proplists:get_value(<<"labels">>, P3)),
        %% Invalid address -> -5.
        ?assertMatch({error, -5, _},
                     rpc(<<"getaddressinfo">>, [<<"notanaddress">>], <<>>)),
        ok = stop_proc(beamchain_wallet)
    end}.
