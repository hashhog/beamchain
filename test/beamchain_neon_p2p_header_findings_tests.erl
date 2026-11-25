-module(beamchain_neon_p2p_header_findings_tests).

%% Finding 14 of the Gemini (Neon) audit of beamchain against Bitcoin
%% Core v31.1 (item verify-neon-beamchain-findings). Core's
%% ContextualCheckBlockHeader (validation.cpp), which runs in
%% AcceptBlockHeader for every header a peer sends, refuses nVersion < 2 / 3
%% / 4 at or above BIP34Height / BIP66Height / BIP65Height with
%% bad-version(0x%08x). beamchain's header sync (validate_one_header/2) did
%% not, so such a header was indexed and became the header tip.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% ===================================================================
%%% F14: header sync refuses bad-version
%%% ===================================================================

%% validate_one_header/2 is internal; the TEST build exports it (the
%% export is in this test's own commit, so master runs the same code).
validate(Header, State) ->
    beamchain_header_sync:validate_one_header(Header, State).

%% A regtest header-sync state whose tip is genesis, and a header for
%% height 1 (BIP34/66/65 heights are all 1 on regtest) mined on top.
with_regtest_tip(Fun) ->
    Params = beamchain_chain_params:params(regtest),
    #block{header = GH} = maps:get(genesis_block, Params),
    GHash = beamchain_serialize:block_hash(GH),
    ok = meck:new(beamchain_db, [passthrough, non_strict]),
    try
        meck:expect(beamchain_db, get_block_index,
                    fun(0) -> {ok, #{hash => GHash, header => GH}};
                       (_) -> not_found
                    end),
        meck:expect(beamchain_db, store_block_index, fun(_, _, _, _, _) -> ok end),
        meck:expect(beamchain_db, set_header_tip, fun(_, _) -> ok end),
        meck:expect(beamchain_db, get_meta, fun(_) -> not_found end),
        State = beamchain_header_sync:test_state(
                  #{tip_height => 0, tip_hash => GHash,
                    tip_chainwork => <<2:256>>,
                    mtp_window => [{0, GH#block_header.timestamp}],
                    params => Params}),
        Fun(GHash, State)
    after
        meck:unload(beamchain_db)
    end.

mined(PrevHash, Version) ->
    H0 = #block_header{version = Version, prev_hash = PrevHash,
                       merkle_root = <<Version:256>>,
                       timestamp = erlang:system_time(second) - 600,
                       bits = 16#207fffff, nonce = 0},
    grind(H0, 0).

grind(H0, N) ->
    H = H0#block_header{nonce = N},
    Limit = maps:get(pow_limit, beamchain_chain_params:params(regtest)),
    case beamchain_pow:check_pow(beamchain_serialize:block_hash(H), H#block_header.bits, Limit) of
        true -> H;
        false -> grind(H0, N + 1)
    end.

f14_header_version_1_refused_test() ->
    with_regtest_tip(fun(G, S) ->
        ?assertEqual({error, {bad_version, 1}}, validate(mined(G, 1), S))
    end).

f14_header_version_3_refused_after_bip65_test() ->
    with_regtest_tip(fun(G, S) ->
        ?assertEqual({error, {bad_version, 3}}, validate(mined(G, 3), S))
    end).

%% nVersion is signed: 0x80000004 is negative and fails every gate.
f14_header_negative_version_refused_test() ->
    with_regtest_tip(fun(G, S) ->
        ?assertEqual({error, {bad_version, -16#7ffffffc}},
                     validate(mined(G, -16#7ffffffc), S))
    end).

%% Control: version 4 and a BIP9 version pass and become the tip.
f14_control_version_4_and_bip9_accepted_test() ->
    with_regtest_tip(fun(G, S) ->
        ?assertMatch({ok, _}, validate(mined(G, 4), S)),
        ?assertMatch({ok, _}, validate(mined(G, 16#20000000), S))
    end).
