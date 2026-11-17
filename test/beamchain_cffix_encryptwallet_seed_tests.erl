-module(beamchain_cffix_encryptwallet_seed_tests).

%%% ===================================================================
%%% encryptwallet must not leave the plaintext seed on disk.
%%%
%%% Core: CWallet::EncryptWallet (wallet/wallet.cpp) finishes with
%%% GetDatabase().Rewrite() because "the database might keep bits of the
%%% unencrypted private key in slack space in the database file".
%%%
%%% beamchain's durable writer (atomic_write_wallet/2) copies the previous
%%% wallet.json to wallet.json.bak before every save. The save that
%%% encryptwallet triggers therefore copied the PLAINTEXT wallet (with its
%%% "seed" field) into wallet.json.bak, where it stayed readable
%%% indefinitely next to the encrypted file.
%%%
%%% These tests encrypt a wallet, then read every file in the wallet
%%% directory and assert that the seed's bytes (raw or hex) appear in none.
%%% A negative control first proves the scan does find the seed in the
%%% plaintext wallet file before encryption.
%%% ===================================================================

-include_lib("eunit/include/eunit.hrl").

setup() ->
    Env = beamchain_wallet_test_env:setup(),
    _ = stop_default(),
    Env.

cleanup(Env) ->
    _ = stop_default(),
    beamchain_wallet_test_env:teardown(Env).

stop_default() ->
    case whereis(beamchain_wallet) of
        undefined -> ok;
        Pid ->
            _ = unlink(Pid),
            MRef = erlang:monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', MRef, process, Pid, _} -> ok
            after 2000 -> ok
            end
    end.

start_default() ->
    {ok, Pid} = beamchain_wallet:start_link(),
    true = unlink(Pid),
    Pid.

%% All regular files under Dir (wallet.json, .bak, .tmp, ...).
all_files(Dir) ->
    filelib:fold_files(Dir, ".*", true, fun(F, Acc) -> [F | Acc] end, []).

hex(Bin) ->
    list_to_binary([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

%% Files whose bytes contain the seed raw, as lower hex or as upper hex.
files_holding_seed(Dir, Seed) ->
    Needles = [Seed, hex(Seed), string:uppercase(hex(Seed))],
    [F || F <- all_files(Dir),
          begin
              {ok, Bytes} = file:read_file(F),
              lists:any(fun(N) -> binary:match(Bytes, N) =/= nomatch end,
                        Needles)
          end].

encryptwallet_seed_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun scan_finds_plaintext_seed_before_encrypt/1,
      fun encryptwallet_leaves_no_plaintext_seed_on_disk/1,
      fun encrypted_wallet_reloads_and_unlocks_after_scrub/1
     ]}.

%% Negative control: if the scan could not see the seed, the next test
%% would pass for the wrong reason.
scan_finds_plaintext_seed_before_encrypt({Dir, _}) ->
    fun() ->
        Pid = start_default(),
        Seed = crypto:strong_rand_bytes(32),
        {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
        {ok, _} = gen_server:call(Pid, {get_new_address, p2wpkh}),
        ?assertNotEqual([], files_holding_seed(Dir, Seed)),
        ok = stop_default()
    end.

encryptwallet_leaves_no_plaintext_seed_on_disk({Dir, _}) ->
    fun() ->
        Pid = start_default(),
        Seed = crypto:strong_rand_bytes(32),
        {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
        %% A second save, so a previous plaintext file exists for the
        %% durable writer to rotate into wallet.json.bak.
        {ok, _} = gen_server:call(Pid, {get_new_address, p2wpkh}),
        ok = gen_server:call(Pid, {encryptwallet, <<"correct horse">>}),
        ok = stop_default(),
        ?assertEqual([], files_holding_seed(Dir, Seed))
    end.

%% The scrubbed backup must still be a usable recovery copy: an encrypted
%% wallet that reloads locked and unlocks with the passphrase.
encrypted_wallet_reloads_and_unlocks_after_scrub({Dir, _}) ->
    fun() ->
        Pid = start_default(),
        Seed = crypto:strong_rand_bytes(32),
        {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
        {ok, Addr} = gen_server:call(Pid, {get_new_address, p2wpkh}),
        ok = gen_server:call(Pid, {encryptwallet, <<"correct horse">>}),
        ok = stop_default(),
        [Bak] = [F || F <- all_files(Dir),
                      filename:basename(F) =:= "wallet.json.bak"],
        {ok, BakBytes} = file:read_file(Bak),
        BakMap = jsx:decode(BakBytes, [return_maps]),
        ?assertEqual(true, maps:get(<<"encrypted">>, BakMap)),
        ?assertNot(maps:is_key(<<"seed">>, BakMap)),
        Pid2 = start_default(),
        ?assert(beamchain_wallet:is_locked(Pid2)),
        ok = gen_server:call(Pid2, {walletpassphrase, <<"correct horse">>, 60}),
        {ok, Addrs} = gen_server:call(Pid2, list_addresses),
        ?assert(lists:any(
                  fun(A) -> maps:get(<<"address">>, A) =:= list_to_binary(Addr) end,
                  Addrs)),
        ok = stop_default()
    end.
