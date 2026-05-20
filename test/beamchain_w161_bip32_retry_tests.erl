%%%-------------------------------------------------------------------
%%% @doc W161 BUG-2 / BUG-4 — BIP-32 MUST-retry on IL>=n or child==0.
%%%
%%% Closes 6-WAVE LONGEST single-bug carry-forward W156->W161.
%%%
%%% Per BIP-32 §"Private parent key -> private child key" /
%%% §"Public parent key -> private child key": *"In case parse256(IL) >= n
%%% or k_i = 0, the resulting key is invalid, and one should proceed with
%%% the next value for i."*
%%%
%%% Bitcoin Core: `bitcoin-core/src/key.cpp::CKey::Derive` returns the
%%% libsecp256k1 success flag; caller advances the keypool index.
%%%
%%% Pre-fix: `derive_child/2` hard-matched `{ok, _}` and crashed the
%%% gen_server on the rare-but-spec-required `{error, _}` from
%%% `seckey_tweak_add` / `pubkey_tweak_add`.
%%%
%%% Post-fix: `derive_child/2` loops on the next child index in the same
%%% hardened/unhardened range, raising `extkey_exhausted` only when retry
%%% would cross the 2^31 hardened boundary.
%%%
%%% Verification: corpus entry absent (IL>=n hits at ~2^-256 probability so
%%% an injection mock is the only practical test vector — meck used here).
%%%-------------------------------------------------------------------
-module(beamchain_w161_bip32_retry_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(HARDENED, 16#80000000).

%%% -------------------------------------------------------------------
%%% Happy path: existing BIP-32 test vectors must still pass.
%%% This is a regression guard: the refactor MUST NOT break the canonical
%%% derivation behavior. (Full BIP-32 vector coverage lives in
%%% beamchain_wallet_tests.erl; this is a focused smoke-check.)
%%% -------------------------------------------------------------------
happy_path_no_retry_test() ->
    Seed = hex_to_bin("000102030405060708090a0b0c0d0e0f"),
    Master = beamchain_wallet:master_from_seed(Seed),
    %% m/0' — the BIP-32 vector 1 first-hardened-child case. With real
    %% (non-pathological) seed material the retry helper hits the happy
    %% path on its first iteration.
    Child = beamchain_wallet:derive_child(Master, 16#80000000),
    ExpPriv = hex_to_bin("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"),
    ?assertEqual(ExpPriv, element(2, Child)),
    ?assertEqual(1, element(5, Child)),                 % depth = 1
    ?assertEqual(16#80000000, element(7, Child)).       % child_index = 0'

happy_path_unhardened_test() ->
    Seed = hex_to_bin("000102030405060708090a0b0c0d0e0f"),
    Master = beamchain_wallet:master_from_seed(Seed),
    Child0H = beamchain_wallet:derive_child(Master, 16#80000000),
    Child1  = beamchain_wallet:derive_child(Child0H, 1),
    ExpPriv = hex_to_bin("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"),
    ?assertEqual(ExpPriv, element(2, Child1)),
    ?assertEqual(2, element(5, Child1)),                % depth = 2
    ?assertEqual(1, element(7, Child1)).                % child_index = 1

%%% -------------------------------------------------------------------
%%% Retry path (BUG-2): contrive seckey_tweak_add to return {error, _} at
%%% child_num=0 via meck; assert derive_child returns a valid child at
%%% child_num=1 instead of crashing the gen_server.
%%% -------------------------------------------------------------------
retry_advances_on_il_ge_n_priv_test() ->
    Seed = hex_to_bin("000102030405060708090a0b0c0d0e0f"),
    Master = beamchain_wallet:master_from_seed(Seed),

    %% Pre-compute the canonical real-NIF result for child_num=1 BEFORE
    %% meck'ing (meck:passthrough reloads the module and unbinds NIFs).
    ExpectedChild1 = beamchain_wallet:derive_child(Master, 1),

    %% First call (child_num=0): force {error, tweak_failed}.
    %% Second call (child_num=1): return the pre-computed real result.
    %% We can't use passthrough on a NIF module, so we install a stub that
    %% returns the canonical {ok, ChildPriv1} extracted from ExpectedChild1.
    ExpectedPriv1 = element(2, ExpectedChild1),
    ExpectedChainCode1 = element(4, ExpectedChild1),
    %% Also pre-compute pubkey_from_privkey result for retry-branch.
    {ok, ExpectedPub1} = beamchain_crypto:pubkey_from_privkey(ExpectedPriv1),

    erlang:put({?MODULE, latched}, false),
    ok = meck:new(beamchain_crypto, [no_link]),
    try
        ok = meck:expect(beamchain_crypto, seckey_tweak_add,
            fun(_SecKey, _Tweak) ->
                case erlang:get({?MODULE, latched}) of
                    false ->
                        erlang:put({?MODULE, latched}, true),
                        {error, tweak_failed};
                    true ->
                        {ok, ExpectedPriv1}
                end
            end),
        ok = meck:expect(beamchain_crypto, pubkey_from_privkey,
            fun(_) -> {ok, ExpectedPub1} end),
        ok = meck:expect(beamchain_crypto, hmac_sha512,
            fun(_Key, _Data) ->
                %% chain_code = anything 32 bytes; the test only asserts
                %% structural invariants. Return a known fixture.
                <<ExpectedChainCode1/binary, ExpectedChainCode1/binary>>
            end),
        ok = meck:expect(beamchain_crypto, hash160,
            fun(_) -> <<0,0,0,0, 0:224>> end),

        %% Derive m/0 — the requested index is 0. First attempt fails
        %% (mocked), retry at child_num=1 must succeed and return a key
        %% whose child_index field is 1, NOT 0.
        Child = beamchain_wallet:derive_child(Master, 0),
        ?assertEqual(1, element(7, Child)),
        ?assertEqual(1, element(5, Child)),          % depth still parent+1
        ?assertEqual(ExpectedPriv1, element(2, Child)),
        ?assertEqual(true, erlang:get({?MODULE, latched}))
    after
        meck:unload(beamchain_crypto),
        erlang:erase({?MODULE, latched})
    end.

retry_advances_on_il_ge_n_pub_test() ->
    Seed = hex_to_bin("000102030405060708090a0b0c0d0e0f"),
    Master = beamchain_wallet:master_from_seed(Seed),
    %% Strip private key to exercise the pub-only branch (BUG-4).
    Neutered = setelement(2, Master, undefined),

    %% Pre-compute canonical real-NIF result for the pub-side child_num=1.
    ExpectedNeuteredChild = beamchain_wallet:derive_child(Neutered, 1),
    ExpectedChildPub = element(3, ExpectedNeuteredChild),
    ExpectedChainCode = element(4, ExpectedNeuteredChild),

    erlang:put({?MODULE, latched_pub}, false),
    ok = meck:new(beamchain_crypto, [no_link]),
    try
        ok = meck:expect(beamchain_crypto, pubkey_tweak_add,
            fun(_PubKey, _Tweak) ->
                case erlang:get({?MODULE, latched_pub}) of
                    false ->
                        erlang:put({?MODULE, latched_pub}, true),
                        {error, tweak_failed};
                    true ->
                        {ok, ExpectedChildPub}
                end
            end),
        ok = meck:expect(beamchain_crypto, hmac_sha512,
            fun(_Key, _Data) ->
                <<ExpectedChainCode/binary, ExpectedChainCode/binary>>
            end),
        ok = meck:expect(beamchain_crypto, hash160,
            fun(_) -> <<0,0,0,0, 0:224>> end),

        Child = beamchain_wallet:derive_child(Neutered, 0),
        %% Retry advanced child_num=0 -> 1.
        ?assertEqual(1, element(7, Child)),
        ?assertEqual(undefined, element(2, Child)),  % still no privkey
        ?assertEqual(ExpectedChildPub, element(3, Child)),
        ?assertEqual(true, erlang:get({?MODULE, latched_pub}))
    after
        meck:unload(beamchain_crypto),
        erlang:erase({?MODULE, latched_pub})
    end.

%%% -------------------------------------------------------------------
%%% Exhausted path: contrive a case where retry would cross the 2^31
%%% boundary; assert proper error return (no crash, well-typed).
%%% Unhardened range: StartIndex < 2^31, CurIndex >= 2^31 must raise.
%%% Hardened range:   StartIndex >= 2^31, CurIndex wraps below must raise.
%%% -------------------------------------------------------------------
exhausted_unhardened_to_hardened_boundary_test() ->
    Seed = hex_to_bin("000102030405060708090a0b0c0d0e0f"),
    Master = beamchain_wallet:master_from_seed(Seed),

    %% Force seckey_tweak_add to ALWAYS return {error, tweak_failed}.
    %% Start at 2^31 - 1 (last unhardened); retry MUST raise rather than
    %% silently fall into hardened range.
    %% Pre-compute the dummy chain_code so hmac_sha512 stub returns a
    %% valid 64-byte binary (the function would otherwise NIF-error).
    Stub64 = <<0:512>>,
    ok = meck:new(beamchain_crypto, [no_link]),
    try
        ok = meck:expect(beamchain_crypto, seckey_tweak_add,
            fun(_, _) -> {error, tweak_failed} end),
        ok = meck:expect(beamchain_crypto, hmac_sha512,
            fun(_, _) -> Stub64 end),
        ok = meck:expect(beamchain_crypto, pubkey_from_privkey,
            fun(_) -> {ok, <<2, 0:256>>} end),
        ok = meck:expect(beamchain_crypto, hash160,
            fun(_) -> <<0:160>> end),

        StartIdx = ?HARDENED - 1,
        ?assertError({extkey_exhausted, StartIdx, ?HARDENED},
                     beamchain_wallet:derive_child(Master, StartIdx))
    after
        meck:unload(beamchain_crypto)
    end.

exhausted_hardened_range_overflow_test() ->
    Seed = hex_to_bin("000102030405060708090a0b0c0d0e0f"),
    Master = beamchain_wallet:master_from_seed(Seed),

    Stub64 = <<0:512>>,
    ok = meck:new(beamchain_crypto, [no_link]),
    try
        ok = meck:expect(beamchain_crypto, seckey_tweak_add,
            fun(_, _) -> {error, tweak_failed} end),
        ok = meck:expect(beamchain_crypto, hmac_sha512,
            fun(_, _) -> Stub64 end),
        ok = meck:expect(beamchain_crypto, pubkey_from_privkey,
            fun(_) -> {ok, <<2, 0:256>>} end),
        ok = meck:expect(beamchain_crypto, hash160,
            fun(_) -> <<0:160>> end),

        %% Start at 2^32 - 1 (last hardened); retry CurIndex+1 = 2^32
        %% triggers the upper boundary guard (CurIndex >= 2^32). The
        %% impl raises rather than looping forever.
        StartIdx = (?HARDENED bsl 1) - 1,
        ?assertError({extkey_exhausted, StartIdx, (?HARDENED bsl 1)},
                     beamchain_wallet:derive_child(Master, StartIdx))
    after
        meck:unload(beamchain_crypto)
    end.

%%% -------------------------------------------------------------------
%%% Descriptor side: derive_bip32_privkey_path / derive_bip32_pubkey_path
%%% in beamchain_descriptor.erl received the SAME refactor (private
%%% helpers derive_priv_step/4 + derive_pub_step/4). The descriptor
%%% helpers are not exported, but the W161 audit identified the same
%%% hard-match shape there (`{ok, _} = …` on lines 910 + 926). The
%%% structural fix is byte-identical to the wallet's; the wallet tests
%%% above cover the contract. Descriptor regression is covered by the
%%% existing beamchain_descriptor_tests EUnit suite (the happy path of
%%% derive_path is exercised end-to-end through the public
%%% derive/2 entry point).
%%% -------------------------------------------------------------------

%%% -------------------------------------------------------------------
%%% helpers
%%% -------------------------------------------------------------------
hex_to_bin(Hex) ->
    << <<(list_to_integer([A,B], 16))>> || <<A, B>> <= list_to_binary(Hex) >>.
