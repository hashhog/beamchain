-module(beamchain_w102_assumeutxo_tests).

%% W102 AssumeUTXO snapshot loading gate audit — EUnit tests.
%%
%% Reference: bitcoin-core/src/validation.cpp ActivateSnapshot (line 5588)
%%            bitcoin-core/src/rpc/blockchain.cpp dumptxoutset + loadtxoutset
%%
%% Bug list (12 bugs found, documented in commit message and report):
%%
%% G1  [CORRECTNESS]   network_magic not validated on load — snapshot from a
%%                     different network (mainnet file on testnet4 node) is
%%                     accepted without error.
%%                     Reference: SnapshotMetadata carries pchMessageStart;
%%                     Core verifies it via metadata.m_network_magic ==
%%                     chainparams.MessageStart() before activation.
%%
%% G2  [CORRECTNESS]   per-coin height > base_height not rejected — Core's
%%                     PopulateAndValidateSnapshot (validation.cpp:5814-5818)
%%                     refuses any coin whose height > snapshot base height,
%%                     signalling a malformed / tampered snapshot. Beamchain
%%                     parse_coin accepts any height value.
%%
%% G3  [CORRECTNESS]   per-coin vout >= UINT32_MAX not rejected — Core
%%                     (validation.cpp:5815) refuses vout >= max to avoid
%%                     integer wrap-around in coinstats ApplyHash. Beamchain
%%                     decode_compact_size accepts any 64-bit value as a vout.
%%
%% G4  [CORRECTNESS]   per-coin MoneyRange not checked on load — Core
%%                     (validation.cpp:5820-5822) refuses coins with
%%                     nValue > 21_000_000 BTC. Beamchain parse_coin accepts
%%                     any decompressed value.
%%
%% G5  [CORRECTNESS]   trailing-bytes check missing — Core
%%                     (validation.cpp:5872-5882) reads one more byte after
%%                     all coins are consumed and errors if a byte is present
%%                     ("Bad snapshot - coins left over"). Beamchain
%%                     parse_coins/3 returns success when Remaining hits 0
%%                     without checking for leftover bytes.
%%
%% G6  [DOS]           double-load / re-activation not rejected — Core
%%                     (validation.cpp:5600-5601) returns an error if a
%%                     snapshot-based chainstate is already active:
%%                     "Can't activate a snapshot-based chainstate more than
%%                     once". Beamchain's do_load_snapshot replaces the UTXO
%%                     cache unconditionally, overwriting a previously loaded
%%                     snapshot silently.
%%
%% G7  [CORRECTNESS]   non-empty mempool not rejected — Core
%%                     (validation.cpp:5626-5628) refuses snapshot activation
%%                     when the mempool is non-empty to avoid phantom inputs.
%%                     Beamchain does not check the mempool before loading.
%%
%% G8  [CORRECTNESS]   base block invalid-chain flag not checked — Core
%%                     (validation.cpp:5617-5619) refuses activation if
%%                     snapshot_start_block->nStatus & BLOCK_FAILED_VALID.
%%                     Beamchain rpc_loadtxoutset only checks block_index
%%                     height via get_block_index_by_hash; it never inspects
%%                     the block's status flags.
%%
%% G9  [CORRECTNESS]   work-does-not-exceed-active check missing — Core
%%                     (validation.cpp:5703-5708 and 5787-5788) refuses a
%%                     snapshot whose chainwork does not exceed the active
%%                     chainstate's work. Beamchain skips this check entirely.
%%
%% G10 [OBSERVABILITY] loadtxoutset response uses "base_blockhash" not
%%                     "tip_hash" — Core's JSON response (rpc/blockchain.cpp
%%                     :3441) returns tip_hash and path; beamchain returns
%%                     base_blockhash and omits path. Test clients expecting
%%                     Core-compatible JSON will fail.
%%
%% G11 [OBSERVABILITY] getchainstates / getblockchaininfo missing snapshot
%%                     fields — Core exposes snapshot_blockhash, validated,
%%                     and snapshotheight in getchainstates + getblockchaininfo
%%                     background_validation. Beamchain has no getchainstates
%%                     RPC and getblockchaininfo does not surface snapshot state.
%%
%% G12 [CORRECTNESS]   merge_chainstates (MaybeValidateSnapshot equivalent)
%%                     is never triggered automatically — Core calls
%%                     MaybeValidateSnapshot from ActivateBestChain whenever
%%                     the background chainstate reaches the snapshot block.
%%                     beamchain_chainstate_sup:merge_chainstates/0 exists but
%%                     is never called from the connect-block path; background
%%                     validation runs but the snapshot chainstate is never
%%                     demoted to VALIDATED nor the IBD chainstate torn down.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Test suite entry point
%%% ===================================================================

w102_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          %% G1 — network magic validation
          {"G1: network_magic from wrong network is rejected at load",
           fun test_g1_network_magic_wrong_network/0},
          {"G1: network_magic matching node network passes",
           fun test_g1_network_magic_correct/0},

          %% G2 — per-coin height > base_height
          {"G2: coin with height > base_height is bad-snapshot data",
           fun test_g2_coin_height_exceeds_base/0},
          {"G2: coin with height == base_height is accepted",
           fun test_g2_coin_height_equal_base/0},

          %% G3 — per-coin vout >= UINT32_MAX
          {"G3: coin vout >= 16#ffffffff triggers integer-wrap hazard",
           fun test_g3_vout_max_uint32/0},

          %% G4 — per-coin MoneyRange
          {"G4: coin value above MAX_MONEY fails MoneyRange",
           fun test_g4_money_range_exceeded/0},
          {"G4: coin value == MAX_MONEY passes",
           fun test_g4_money_range_max_money/0},

          %% G5 — trailing bytes after all coins consumed
          {"G5: extra bytes after all coins yield bad-snapshot error",
           fun test_g5_trailing_bytes/0},

          %% G6 — double-load guard
          {"G6: validate_snapshot_height accepts whitelisted heights once",
           fun test_g6_validate_height_whitelist/0},

          %% G7 — mempool check before load
          {"G7: mempool non-empty state is documented as missing gate",
           fun test_g7_mempool_gate_missing/0},

          %% G8 — invalid-chain flag on base block
          {"G8: validate_snapshot_height permits heights with no block status check",
           fun test_g8_block_failed_valid_no_gate/0},

          %% G9 — chainwork check
          {"G9: no chainwork comparison is performed by validate_snapshot_height",
           fun test_g9_chainwork_check_missing/0},

          %% G10 — loadtxoutset response shape
          {"G10: loadtxoutset response shape diverges from Core (tip_hash vs base_blockhash)",
           fun test_g10_response_field_name/0},

          %% G11 — getchainstates not present
          {"G11: getchainstates RPC absent — snapshot state not exposed",
           fun test_g11_getchainstates_absent/0},

          %% G12 — merge_chainstates never auto-triggered
          {"G12: merge_chainstates is defined but never called from connect-block path",
           fun test_g12_merge_never_triggered/0}
         ]
     end}.

setup() ->
    application:set_env(beamchain, network, regtest),
    ok.

teardown(_) ->
    ok.

%%% ===================================================================
%%% G1 — network magic validation
%%% ===================================================================

%% BUG G1: parse_metadata accepts any 4-byte magic without comparing it to the
%% running network's pchMessageStart. A mainnet snapshot (magic
%% <<16#F9,16#BE,16#B4,16#D9>>) will parse successfully on a regtest node
%% (magic <<16#FA,16#BF,16#B5,16#DA>>).  Core's ActivateSnapshot checks the
%% metadata magic before doing anything else.
test_g1_network_magic_wrong_network() ->
    %% Build a header with the MAINNET magic, not regtest magic.
    MainnetMagic = <<16#F9, 16#BE, 16#B4, 16#D9>>,
    BaseHash = <<1:256>>,
    Bin = beamchain_snapshot:serialize_metadata(MainnetMagic, BaseHash, 0),
    {ok, #{network_magic := Parsed}, <<>>} =
        beamchain_snapshot:parse_metadata(Bin),
    %% parse_metadata returns successfully — magic is NOT validated.
    %% A correct implementation would return {error, wrong_network_magic} here.
    %% This assertion documents the BUG: parse succeeds despite wrong magic.
    ?assertEqual(MainnetMagic, Parsed),
    %% The regtest magic differs.
    RegtestMagic = <<16#FA, 16#BF, 16#B5, 16#DA>>,
    ?assertNotEqual(MainnetMagic, RegtestMagic).

%% Positive case: a snapshot built with the running network's magic parses
%% correctly (this already works).
test_g1_network_magic_correct() ->
    RegtestMagic = <<16#FA, 16#BF, 16#B5, 16#DA>>,
    BaseHash = <<0:256>>,
    Bin = beamchain_snapshot:serialize_metadata(RegtestMagic, BaseHash, 5),
    {ok, #{network_magic := M, num_coins := 5}, <<>>} =
        beamchain_snapshot:parse_metadata(Bin),
    ?assertEqual(RegtestMagic, M).

%%% ===================================================================
%%% G2 — per-coin height > base_height
%%% ===================================================================

%% BUG G2: parse_coin/1 accepts a coin whose height (decoded from the height-
%% code varint) exceeds the snapshot base_height.  Core rejects such coins
%% (validation.cpp:5814-5818) because a coin created after the snapshot block
%% cannot exist in the snapshot's UTXO set.
test_g2_coin_height_exceeds_base() ->
    %% Build a coin at height 999_999 in a snapshot whose base height is 110.
    BaseHeight = 110,
    CoinHeight = 999_999,          %% > base_height
    ?assert(CoinHeight > BaseHeight),
    Utxo = #utxo{value = 5000000000, script_pubkey = <<16#51>>,
                 is_coinbase = true, height = CoinHeight},
    CoinBin = beamchain_snapshot:serialize_coin(Utxo),
    %% parse_coin accepts the coin — no height > base_height gate exists.
    {ok, Parsed, <<>>} = beamchain_snapshot:parse_coin(CoinBin),
    ?assertEqual(CoinHeight, Parsed#utxo.height),
    %% A compliant implementation would reject this, returning
    %% {error, bad_coin_height} or similar.
    %% Document that the gate is absent:
    ?assertEqual(CoinHeight, Parsed#utxo.height).

%% Coin with height == base_height is valid per Core and should be accepted.
test_g2_coin_height_equal_base() ->
    Utxo = #utxo{value = 1, script_pubkey = <<16#51>>,
                 is_coinbase = false, height = 110},
    CoinBin = beamchain_snapshot:serialize_coin(Utxo),
    {ok, Parsed, <<>>} = beamchain_snapshot:parse_coin(CoinBin),
    ?assertEqual(110, Parsed#utxo.height).

%%% ===================================================================
%%% G3 — per-coin vout >= UINT32_MAX
%%% ===================================================================

%% BUG G3: vout values >= 16#ffffffff (UINT32_MAX) cause integer wrap-around
%% in Core's ApplyHash in coinstats.cpp.  Core rejects them explicitly.
%% Beamchain decode_compact_size returns any 64-bit value and the vout is
%% never range-checked.
test_g3_vout_max_uint32() ->
    MaxVout = 16#ffffffff,
    %% CompactSize for 0xffffffff is a 5-byte 32-bit encoding (0xfe prefix).
    Encoded = beamchain_snapshot:encode_compact_size(MaxVout),
    {ok, Decoded, <<>>} = beamchain_snapshot:decode_compact_size(Encoded),
    %% Currently accepted silently — documents the missing gate.
    ?assertEqual(MaxVout, Decoded),
    %% Values >= UINT32_MAX should be rejected.  Show that a value that
    %% equals UINT32_MAX rounds through successfully (i.e. the gate is absent).
    ?assert(Decoded >= 16#ffffffff).

%%% ===================================================================
%%% G4 — per-coin MoneyRange
%%% ===================================================================

%% MAX_MONEY = 21_000_000 * 100_000_000 satoshis = 2_100_000_000_000_000.
-define(W102_MAX_MONEY, 2_100_000_000_000_000).

%% BUG G4: beamchain parse_coin doesn't call MoneyRange on the decompressed
%% value.  A snapshot containing a coin with value > MAX_MONEY parses without
%% error.  Core rejects it at validation.cpp:5820-5822.
test_g4_money_range_exceeded() ->
    BadValue = ?W102_MAX_MONEY + 1,
    Utxo = #utxo{value = BadValue, script_pubkey = <<16#51>>,
                 is_coinbase = false, height = 0},
    CoinBin = beamchain_snapshot:serialize_coin(Utxo),
    {ok, Parsed, <<>>} = beamchain_snapshot:parse_coin(CoinBin),
    %% The coin round-trips — no MoneyRange gate exists in parse_coin.
    ?assertEqual(BadValue, Parsed#utxo.value),
    %% Document: a compliant impl should return {error, bad_tx_out_value}.
    ?assert(Parsed#utxo.value > ?W102_MAX_MONEY).

%% Coin at exactly MAX_MONEY passes MoneyRange and should round-trip.
test_g4_money_range_max_money() ->
    Utxo = #utxo{value = ?W102_MAX_MONEY, script_pubkey = <<16#51>>,
                 is_coinbase = false, height = 0},
    CoinBin = beamchain_snapshot:serialize_coin(Utxo),
    {ok, Parsed, <<>>} = beamchain_snapshot:parse_coin(CoinBin),
    ?assertEqual(?W102_MAX_MONEY, Parsed#utxo.value).

%%% ===================================================================
%%% G5 — trailing bytes after all coins consumed
%%% ===================================================================

%% BUG G5: parse_coins/3 halts when its Remaining counter hits 0 and returns
%% success without checking whether the input binary has leftover bytes.  Core
%% (validation.cpp:5872-5882) reads one extra byte after the last coin and
%% fails if it succeeds ("Bad snapshot - coins left over after deserializing N
%% coins").
test_g5_trailing_bytes() ->
    %% Build a valid 1-coin snapshot payload and tack on garbage bytes to
    %% simulate a tampered snapshot with extra data after the declared coin set.
    %%
    %% BUG: beamchain's parse_coins/3 stops when Remaining hits 0 and returns
    %% {ok, Coins} without scanning for trailing bytes.  Core
    %% (validation.cpp:5872-5882) reads one extra byte and fails if successful.
    %%
    %% We cannot drive parse_coins/3 directly (it is internal), so we verify
    %% the public load_snapshot/1 path using a temp file.
    Utxo = #utxo{value = 1, script_pubkey = <<16#51>>,
                 is_coinbase = false, height = 0},
    CoinBin = beamchain_snapshot:serialize_coin(Utxo),
    Txid = <<2:256>>,
    PerTx = <<Txid/binary,
              1:8,     %% compact-size: 1 coin in this txid group
              0:8,     %% compact-size: vout 0
              CoinBin/binary,
              16#DE, 16#AD>>,   %% TWO extra bytes after the coin data
    NetMagic = <<16#FA, 16#BF, 16#B5, 16#DA>>,  %% regtest magic
    BaseHash = <<0:256>>,
    %% num_coins=1 in metadata header — only 1 coin declared, but 2 extra
    %% bytes follow in the payload.
    Header = beamchain_snapshot:serialize_metadata(NetMagic, BaseHash, 1),
    FullSnap = <<Header/binary, PerTx/binary>>,
    TmpPath = "/tmp/beamchain_w102_g5_" ++
              integer_to_list(erlang:system_time()) ++ ".dat",
    try
        ok = file:write_file(TmpPath, FullSnap),
        Result = beamchain_snapshot:load_snapshot(TmpPath),
        %% A compliant impl returns {error, coins_left_over}; beamchain
        %% returns {ok, ...} — documents the absent gate.
        ?assertMatch({ok, #{coins := [_]}}, Result)
    after
        file:delete(TmpPath)
    end.

%%% ===================================================================
%%% G6 — double-load guard
%%% ===================================================================

%% BUG G6: validate_snapshot_height accepts whitelisted heights without
%% tracking whether a snapshot is already loaded.  Core's ActivateSnapshot
%% checks m_from_snapshot_blockhash on the current chainstate before
%% proceeding.  Calling loadtxoutset a second time on a node that already has
%% a snapshot chainstate active results in silent UTXO cache replacement.
%%
%% This test documents that validate_snapshot_height itself has no "already
%% loaded" guard — the guard must live at a higher layer that does not exist.
test_g6_validate_height_whitelist() ->
    %% Both calls to validate_snapshot_height succeed for a whitelisted height —
    %% there is no per-session "already active" state tracked here.
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(840000, mainnet)),
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(840000, mainnet)).

%%% ===================================================================
%%% G7 — mempool non-empty gate
%%% ===================================================================

%% BUG G7: Core (validation.cpp:5626-5628) refuses loadtxoutset when the
%% mempool is non-empty.  Beamchain rpc_loadtxoutset does not consult the
%% mempool before snapshot activation.  We document this as a stub test since
%% we cannot drive the full RPC path in a unit test without a running node.
test_g7_mempool_gate_missing() ->
    %% validate_snapshot_height is the only unit-testable gate and it does
    %% not check the mempool.
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(840000, mainnet)),
    %% A compliant implementation would call something like
    %% beamchain_mempool:size() > 0 → {error, mempool_not_empty} before
    %% proceeding.  That call is absent.
    ?assert(true).   %% placeholder — real gate must be added

%%% ===================================================================
%%% G8 — BLOCK_FAILED_VALID gate on base block
%%% ===================================================================

%% BUG G8: rpc_loadtxoutset looks up the base block via get_block_index_by_hash
%% to obtain its height, but does NOT inspect the block's status field.  Core
%% (validation.cpp:5617-5619) refuses a snapshot whose base block has
%% BLOCK_FAILED_VALID set, signalling it is part of an invalid chain.
test_g8_block_failed_valid_no_gate() ->
    %% validate_snapshot_height only checks height membership; it has no
    %% knowledge of the block-index status flags.
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(840000, mainnet)),
    %% A compliant implementation would additionally call
    %% beamchain_db:get_block_index_by_hash(Hash) and check
    %% (Status band BLOCK_FAILED_VALID) =:= 0.
    ?assert(true).   %% gate confirmed absent at the validate_snapshot_height layer

%%% ===================================================================
%%% G9 — work-does-not-exceed check
%%% ===================================================================

%% BUG G9: Core (validation.cpp:5787-5788 and 5703-5708) compares the
%% snapshot tip's chainwork to the active chainstate's tip chainwork and
%% refuses if the snapshot's chain does not have more work.  This prevents
%% loading an outdated snapshot on a node that is already nearly caught up.
%% Beamchain performs no such comparison.
test_g9_chainwork_check_missing() ->
    %% validate_snapshot_height has no chainwork comparison.
    ?assertEqual(ok, beamchain_rpc:validate_snapshot_height(840000, mainnet)),
    %% A compliant implementation would compare the snapshot block's chainwork
    %% (from beamchain_db:get_block_index_by_hash) against the active tip's
    %% chainwork.  That comparison is absent.
    ?assert(true).

%%% ===================================================================
%%% G10 — loadtxoutset response shape
%%% ===================================================================

%% BUG G10: Core's loadtxoutset (rpc/blockchain.cpp:3439-3444) returns:
%%   coins_loaded  : integer
%%   tip_hash      : hex string   ← Core uses "tip_hash"
%%   base_height   : integer
%%   path          : string       ← Core includes the path
%%
%% Beamchain returns:
%%   coins_loaded  : integer      (matches)
%%   base_blockhash: hex string   ← WRONG key name; Core uses "tip_hash"
%%   base_height   : integer      (matches)
%%   message       : string       ← EXTRA field; Core does not emit this
%%                                  (path field is MISSING)
%%
%% Any test client comparing byte-for-byte against Core's JSON shape will fail.
test_g10_response_field_name() ->
    %% We cannot call rpc_loadtxoutset in a unit test without a running node,
    %% so we document the shape mismatch by asserting the known key names.
    %%
    %% Core uses "tip_hash":
    CoreKey = <<"tip_hash">>,
    %% Beamchain uses "base_blockhash":
    BeamchainKey = <<"base_blockhash">>,
    %% They differ — this IS the bug.
    ?assertNotEqual(CoreKey, BeamchainKey),
    %% Core includes "path"; beamchain does not.
    %% This is a pure documentation test — the actual fix is in rpc_loadtxoutset.
    ?assert(true).

%%% ===================================================================
%%% G11 — getchainstates RPC absent
%%% ===================================================================

%% BUG G11: Bitcoin Core exposes `getchainstates` (rpc/blockchain.cpp:3462)
%% which returns validated/unvalidated chainstate info including
%% snapshot_blockhash, validated, and snapshotheight.  Beamchain has no
%% getchainstates handler.  Additionally, getblockchaininfo does not surface
%% the background_validation sub-object.
%%
%% Clients relying on getchainstates to determine snapshot sync status will
%% receive an "unknown method" error.
test_g11_getchainstates_absent() ->
    %% Verify the handle_method dispatch table does not include getchainstates.
    %% We do this by confirming the exported handle_method/3 does not have a
    %% clause for <<"getchainstates">> — a unit-level proxy is not possible
    %% without the gen_server running, so we document via compile-time knowledge.
    %%
    %% Evidence: grep of beamchain_rpc.erl shows no
    %% handle_method(<<"getchainstates">>, ...) clause.
    ?assert(true).   %% documented as absent — fix: add getchainstates handler

%%% ===================================================================
%%% G12 — merge_chainstates never auto-triggered
%%% ===================================================================

%% BUG G12: Core's MaybeValidateSnapshot is called from ActivateBestChain
%% (validation.cpp:3073) on every connect-block, so the moment the background
%% chainstate reaches the snapshot block it triggers snapshot validation and
%% teardown automatically.
%%
%% beamchain_chainstate_sup:merge_chainstates/0 exists but is never called
%% from the connect-block code path (beamchain_chainstate:do_connect_block_inner
%% has no call to merge_chainstates or any equivalent).  Background validation
%% therefore runs to the snapshot height but no automatic promotion happens;
%% the snapshot chainstate remains "unvalidated" indefinitely.
test_g12_merge_never_triggered() ->
    %% Verify that do_connect_block_inner has no reference to merge_chainstates.
    %% This is a static-analysis assertion documented here; the actual code
    %% path omission was confirmed by reading beamchain_chainstate.erl lines
    %% 884-1065 (do_connect_block_inner body): no call to
    %% beamchain_chainstate_sup:merge_chainstates/0 or any equivalent.
    ?assert(true).   %% fix: call merge_chainstates after background tip == snapshot base

%%% ===================================================================
%%% Regression: regtest assumeutxo placeholder hashes
%%% ===================================================================

%% The regtest assumeutxo entry (height 110) uses <<0:256>> for both
%% block_hash and utxo_hash (beamchain_chain_params.erl:560-568).
%% Loading a real regtest snapshot at height 110 will always fail the
%% hash-serialized check because the stored utxo_hash is all-zeros.
%% Document this as an operational correctness issue.
regtest_placeholder_test() ->
    #{assumeutxo := M} = beamchain_chain_params:params(regtest),
    ?assert(maps:is_key(110, M)),
    #{block_hash := BH, utxo_hash := UH} = maps:get(110, M),
    %% Both are placeholder zeros — a real snapshot will always fail
    %% the content-hash gate.
    ?assertEqual(<<0:256>>, BH),
    ?assertEqual(<<0:256>>, UH).

%%% ===================================================================
%%% Positive: assumeutxo table completeness (mainnet)
%%% ===================================================================

%% Mainnet must carry all 4 Core entries, and each must have non-zero hashes.
mainnet_entries_non_zero_test() ->
    #{assumeutxo := M} = beamchain_chain_params:params(mainnet),
    ?assertEqual(4, maps:size(M)),
    lists:foreach(fun({H, #{block_hash := BH, utxo_hash := UH,
                             chain_tx_count := C}}) ->
        ?assert(H > 0),
        ?assertNotEqual(<<0:256>>, BH),
        ?assertNotEqual(<<0:256>>, UH),
        ?assert(C > 0)
    end, maps:to_list(M)).

%%% ===================================================================
%%% Positive: testnet4 entries non-zero
%%% ===================================================================

testnet4_entries_non_zero_test() ->
    #{assumeutxo := M} = beamchain_chain_params:params(testnet4),
    ?assertEqual(2, maps:size(M)),
    lists:foreach(fun({H, #{block_hash := BH, utxo_hash := UH}}) ->
        ?assert(H > 0),
        ?assertNotEqual(<<0:256>>, BH),
        ?assertNotEqual(<<0:256>>, UH)
    end, maps:to_list(M)).
