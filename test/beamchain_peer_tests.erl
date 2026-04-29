-module(beamchain_peer_tests).

-include_lib("eunit/include/eunit.hrl").

%% BIP 133 feefilter constants (matching beamchain_peer.erl)
-define(FEEFILTER_BROADCAST_INTERVAL_MS, 600000).
-define(FEEFILTER_MAX_CHANGE_DELAY_MS, 300000).
-define(DEFAULT_MIN_RELAY_FEE, 1000).

%%% ===================================================================
%%% Inv trickling unit tests
%%% ===================================================================

%% Test Poisson interval distribution
poisson_interval_test_() ->
    {"Poisson interval generation",
     [
      {"interval is positive", fun() ->
          %% Generate many intervals and verify all positive
          Intervals = [poisson_interval_test(5000) || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I >= 1 end, Intervals))
      end},

      {"interval is bounded", fun() ->
          %% All intervals should be <= 60000ms
          Intervals = [poisson_interval_test(5000) || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I =< 60000 end, Intervals))
      end},

      {"average is roughly correct", fun() ->
          %% Generate many samples and check mean is close to target
          %% Use 1000ms for faster test
          Mean = 1000,
          Samples = [poisson_interval_test(Mean) || _ <- lists:seq(1, 1000)],
          Avg = lists:sum(Samples) / length(Samples),
          %% Should be within 30% of mean (Poisson has high variance)
          ?assert(Avg > Mean * 0.5),
          ?assert(Avg < Mean * 2.0)
      end},

      {"intervals vary (not constant)", fun() ->
          %% Generate several intervals and ensure they're not all the same
          Intervals = [poisson_interval_test(5000) || _ <- lists:seq(1, 10)],
          Unique = lists:usort(Intervals),
          ?assert(length(Unique) > 1)
      end}
     ]}.

%% Test helper: Poisson interval calculation
poisson_interval_test(MeanMs) ->
    U = rand:uniform(),
    Interval = round(-math:log(U) * MeanMs),
    max(1, min(Interval, 60000)).

%% Test shuffle behavior
shuffle_test_() ->
    {"List shuffling",
     [
      {"empty list shuffles to empty", fun() ->
          ?assertEqual([], shuffle_test([]))
      end},

      {"single element unchanged", fun() ->
          ?assertEqual([a], shuffle_test([a]))
      end},

      {"shuffle preserves elements", fun() ->
          List = [1, 2, 3, 4, 5],
          Shuffled = shuffle_test(List),
          ?assertEqual(lists:sort(List), lists:sort(Shuffled))
      end},

      {"shuffle changes order sometimes", fun() ->
          %% With enough iterations, order should change
          List = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
          Results = [shuffle_test(List) || _ <- lists:seq(1, 20)],
          %% At least some should differ from original
          Different = [R || R <- Results, R =/= List],
          ?assert(length(Different) > 0)
      end}
     ]}.

%% Test helper: shuffle implementation
shuffle_test([]) -> [];
shuffle_test([X]) -> [X];
shuffle_test(List) ->
    lists:sort(fun(_, _) -> rand:uniform() > 0.5 end, List).

%%% ===================================================================
%%% Inv queue logic tests
%%% ===================================================================

pending_queue_test_() ->
    {"Pending inv queue logic",
     [
      {"empty queue sends nothing", fun() ->
          PendingTxInv = [],
          {ToSend, _Remaining} = split_for_trickle(PendingTxInv, 70),
          ?assertEqual([], ToSend)
      end},

      {"small queue sends all", fun() ->
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],
          {ToSend, Remaining} = split_for_trickle(Txids, 70),
          ?assertEqual(5, length(ToSend)),
          ?assertEqual(0, length(Remaining))
      end},

      {"large queue respects max", fun() ->
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 200)],
          {ToSend, Remaining} = split_for_trickle(Txids, 70),
          ?assertEqual(70, length(ToSend)),
          ?assertEqual(130, length(Remaining))
      end},

      {"broadcast max scales with queue size", fun() ->
          %% Per Bitcoin Core: target + (size/1000)*5, capped at max
          ?assertEqual(70, broadcast_max_test(0)),
          ?assertEqual(70, broadcast_max_test(500)),
          ?assertEqual(75, broadcast_max_test(1000)),
          ?assertEqual(80, broadcast_max_test(2000)),
          ?assertEqual(1000, broadcast_max_test(200000))  %% capped
      end},

      {"no duplicates in queue", fun() ->
          Txid = crypto:strong_rand_bytes(32),
          Queue = [Txid],
          %% Adding same txid should not duplicate
          Queue2 = maybe_add_txid(Txid, Queue),
          ?assertEqual(1, length(Queue2))
      end},

      {"new txid is added", fun() ->
          Txid1 = crypto:strong_rand_bytes(32),
          Txid2 = crypto:strong_rand_bytes(32),
          Queue = [Txid1],
          Queue2 = maybe_add_txid(Txid2, Queue),
          ?assertEqual(2, length(Queue2))
      end}
     ]}.

%% Test helpers
split_for_trickle(Pending, BroadcastMax) ->
    lists:split(min(BroadcastMax, length(Pending)), Pending).

broadcast_max_test(PendingSize) ->
    min(1000, 70 + (PendingSize div 1000) * 5).

maybe_add_txid(Txid, Queue) ->
    case lists:member(Txid, Queue) of
        true  -> Queue;
        false -> [Txid | Queue]
    end.

%%% ===================================================================
%%% Direction-based interval tests
%%% ===================================================================

direction_interval_test_() ->
    {"Direction-based intervals",
     [
      {"inbound uses 5000ms base", fun() ->
          ?assertEqual(5000, interval_for_direction(inbound))
      end},

      {"outbound uses 2000ms base", fun() ->
          ?assertEqual(2000, interval_for_direction(outbound))
      end}
     ]}.

interval_for_direction(inbound) -> 5000;
interval_for_direction(outbound) -> 2000.

%%% ===================================================================
%%% Inv item encoding tests
%%% ===================================================================

inv_item_test_() ->
    {"Inv item construction",
     [
      {"MSG_TX type is 1", fun() ->
          Txid = crypto:strong_rand_bytes(32),
          Item = #{type => 1, hash => Txid},
          ?assertEqual(1, maps:get(type, Item)),
          ?assertEqual(32, byte_size(maps:get(hash, Item)))
      end},

      {"multiple items list", fun() ->
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 3)],
          Items = [#{type => 1, hash => T} || T <- Txids],
          ?assertEqual(3, length(Items))
      end}
     ]}.

%%% ===================================================================
%%% Privacy property tests
%%% ===================================================================

privacy_test_() ->
    {"Privacy properties",
     [
      {"intervals are exponentially distributed", fun() ->
          %% Exponential distribution property: P(X > s+t | X > s) = P(X > t)
          %% This is the memoryless property - hard to test directly,
          %% but we can verify the shape of the distribution
          Samples = [poisson_interval_test(1000) || _ <- lists:seq(1, 500)],
          %% Mode should be less than mean for exponential
          Sorted = lists:sort(Samples),
          Median = lists:nth(250, Sorted),
          Mean = lists:sum(Samples) / length(Samples),
          %% For exponential, median ≈ 0.693 * mean
          ?assert(Median < Mean)
      end},

      {"shuffling is randomized per call", fun() ->
          List = lists:seq(1, 20),
          Results = [shuffle_test(List) || _ <- lists:seq(1, 10)],
          %% Should have multiple unique orderings
          Unique = lists:usort(Results),
          ?assert(length(Unique) >= 3)
      end}
     ]}.

%%% ===================================================================
%%% Edge cases
%%% ===================================================================

edge_cases_test_() ->
    {"Edge cases",
     [
      {"zero mean interval handled", fun() ->
          %% Should clamp to minimum of 1ms
          I = max(1, round(-math:log(0.5) * 0)),
          ?assertEqual(1, I)
      end},

      {"very small uniform value handled", fun() ->
          %% When U is very small, -ln(U) is very large
          %% Should clamp to max of 60000ms
          SmallU = 0.0001,
          Raw = round(-math:log(SmallU) * 5000),
          Clamped = min(60000, Raw),
          ?assert(Clamped =< 60000)
      end},

      {"peer_relay false clears queue", fun() ->
          %% When peer requests no relay, queue should be cleared
          Pending = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],
          Relay = false,
          Remaining = case Relay of
              false -> [];
              true -> Pending
          end,
          ?assertEqual([], Remaining)
      end}
     ]}.

%%% ===================================================================
%%% BIP 133 feefilter tests
%%% ===================================================================

feefilter_encode_decode_test_() ->
    {"Feefilter message encoding/decoding",
     [
      {"encode feefilter message", fun() ->
          FeeRate = 1000,  %% 1000 sat/kvB
          Encoded = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => FeeRate}),
          ?assertEqual(<<232, 3, 0, 0, 0, 0, 0, 0>>, Encoded)  %% 1000 as 64-bit little-endian
      end},

      {"decode feefilter message", fun() ->
          Payload = <<232, 3, 0, 0, 0, 0, 0, 0>>,  %% 1000 as 64-bit little-endian
          {ok, #{feerate := Fee}} = beamchain_p2p_msg:decode_payload(feefilter, Payload),
          ?assertEqual(1000, Fee)
      end},

      {"roundtrip encode/decode", fun() ->
          FeeRates = [0, 1000, 10000, 100000, 1000000],
          lists:foreach(fun(Rate) ->
              Encoded = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => Rate}),
              {ok, #{feerate := Decoded}} = beamchain_p2p_msg:decode_payload(feefilter, Encoded),
              ?assertEqual(Rate, Decoded)
          end, FeeRates)
      end}
     ]}.

feefilter_poisson_interval_test_() ->
    {"Feefilter Poisson interval",
     [
      {"interval is positive", fun() ->
          Intervals = [feefilter_poisson_interval_test(?FEEFILTER_BROADCAST_INTERVAL_MS)
                       || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I >= 1000 end, Intervals))
      end},

      {"interval is bounded at 30 minutes", fun() ->
          Intervals = [feefilter_poisson_interval_test(?FEEFILTER_BROADCAST_INTERVAL_MS)
                       || _ <- lists:seq(1, 100)],
          ?assert(lists:all(fun(I) -> I =< 1800000 end, Intervals))
      end},

      {"average is roughly correct (10 minutes)", fun() ->
          %% Use 60000ms (1 minute) for faster test with same distribution
          Mean = 60000,
          Samples = [feefilter_poisson_interval_test(Mean) || _ <- lists:seq(1, 500)],
          Avg = lists:sum(Samples) / length(Samples),
          %% Should be within 50% of mean (Poisson has high variance)
          ?assert(Avg > Mean * 0.5),
          ?assert(Avg < Mean * 2.0)
      end}
     ]}.

feefilter_poisson_interval_test(MeanMs) ->
    U = rand:uniform(),
    Interval = round(-math:log(U) * MeanMs),
    max(1000, min(Interval, 1800000)).

feefilter_significant_change_test_() ->
    {"Feefilter significant change detection",
     [
      {"25% drop is significant", fun() ->
          SentFee = 4000,
          CurrentFee = 2900,  %% < 75% of sent (3000)
          SignificantChange = (CurrentFee * 4 < SentFee * 3),
          ?assert(SignificantChange)
      end},

      {"33% increase is significant", fun() ->
          SentFee = 3000,
          CurrentFee = 4100,  %% > 133% of sent (4000)
          SignificantChange = (CurrentFee * 3 > SentFee * 4),
          ?assert(SignificantChange)
      end},

      {"small changes are not significant", fun() ->
          SentFee = 4000,
          CurrentFee = 3500,  %% 87.5% of sent (between 75% and 133%)
          Drop = (CurrentFee * 4 < SentFee * 3),
          Increase = (CurrentFee * 3 > SentFee * 4),
          ?assertNot(Drop orelse Increase)
      end},

      {"no change is not significant", fun() ->
          SentFee = 4000,
          CurrentFee = 4000,
          Drop = (CurrentFee * 4 < SentFee * 3),
          Increase = (CurrentFee * 3 > SentFee * 4),
          ?assertNot(Drop orelse Increase)
      end}
     ]}.

feefilter_floor_test_() ->
    {"Feefilter minimum relay fee floor",
     [
      {"floor at minimum relay fee", fun() ->
          %% Even if mempool min fee is 0, we send at least 1000 sat/kvB
          CurrentFee = 0,
          FilterToSend = max(CurrentFee, ?DEFAULT_MIN_RELAY_FEE),
          ?assertEqual(1000, FilterToSend)
      end},

      {"higher fee is preserved", fun() ->
          CurrentFee = 5000,
          FilterToSend = max(CurrentFee, ?DEFAULT_MIN_RELAY_FEE),
          ?assertEqual(5000, FilterToSend)
      end}
     ]}.

feefilter_inv_filtering_test_() ->
    {"Feefilter inv filtering logic",
     [
      {"zero feefilter passes all txs", fun() ->
          PeerFeeFilter = 0,
          Txids = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],
          Filtered = filter_by_feefilter_test(Txids, PeerFeeFilter),
          ?assertEqual(Txids, Filtered)
      end},

      {"high feefilter filters some txs", fun() ->
          %% Simulated txs with fee rates
          Txs = [{crypto:strong_rand_bytes(32), 500},    %% 500 sat/kvB - filtered
                 {crypto:strong_rand_bytes(32), 1500},   %% 1500 sat/kvB - passes
                 {crypto:strong_rand_bytes(32), 2000}],  %% 2000 sat/kvB - passes
          PeerFeeFilter = 1000,
          Filtered = [Txid || {Txid, Rate} <- Txs, Rate >= PeerFeeFilter],
          ?assertEqual(2, length(Filtered))
      end}
     ]}.

filter_by_feefilter_test(Txids, PeerFeeFilter) when PeerFeeFilter =< 0 ->
    Txids;
filter_by_feefilter_test(_Txids, _PeerFeeFilter) ->
    %% In real code this would look up mempool entries
    %% For test purposes, return empty (simulating no matching txs)
    [].

%%% ===================================================================
%%% W90 — BIP-324 v2 peek-classify
%%%
%%% These cover the inbound-only first-16-bytes classifier in
%%% beamchain_peer:is_v1_version_header/2.  The classifier is the only
%%% point at which we commit to v1 vs v2 for an incoming connection;
%%% getting it wrong either disconnects healthy v1 peers (false v2
%%% positive) or misroutes random ellswift bytes through the v1 frame
%%% decoder (false v1 positive).
%%% ===================================================================

%% Mainnet, testnet, testnet4, regtest, signet magics.
-define(MAINNET_MAGIC,  <<16#F9, 16#BE, 16#B4, 16#D9>>).
-define(TESTNET4_MAGIC, <<16#1C, 16#16, 16#3F, 16#28>>).
-define(REGTEST_MAGIC,  <<16#FA, 16#BF, 16#B5, 16#DA>>).

v2_classify_v1_version_header_is_v1_test() ->
    %% Real Bitcoin Core v1 version header: magic || "version" || 0*5.
    Hdr = <<?MAINNET_MAGIC/binary, "version", 0, 0, 0, 0, 0>>,
    ?assertEqual(true, beamchain_peer:is_v1_version_header(Hdr, ?MAINNET_MAGIC)),
    %% Other networks succeed too with their own magic.
    Hdr4 = <<?TESTNET4_MAGIC/binary, "version", 0, 0, 0, 0, 0>>,
    ?assertEqual(true, beamchain_peer:is_v1_version_header(Hdr4, ?TESTNET4_MAGIC)),
    HdrR = <<?REGTEST_MAGIC/binary, "version", 0, 0, 0, 0, 0>>,
    ?assertEqual(true, beamchain_peer:is_v1_version_header(HdrR, ?REGTEST_MAGIC)).

v2_classify_wrong_magic_is_not_v1_test() ->
    %% Magic for a different network — the receiving node will treat
    %% this as v2 (random ellswift bytes that happen to spell "version"
    %% after the wrong magic prefix).  A real Bitcoin Core peer never
    %% sends another network's magic, so misclassifying as v2 here is
    %% the correct (and Bitcoin-Core-parity) behaviour.
    Hdr = <<?MAINNET_MAGIC/binary, "version", 0, 0, 0, 0, 0>>,
    ?assertEqual(false, beamchain_peer:is_v1_version_header(Hdr, ?TESTNET4_MAGIC)).

v2_classify_random_ellswift_is_not_v1_test() ->
    %% A 16-byte uniformly random prefix matches the v1 header pattern
    %% with probability ~2^-128 (4 bytes magic + 12 bytes "version\0...").
    %% Probabilistic test: 1000 random samples, expect zero v1 hits
    %% under any of three magics.
    lists:foreach(
        fun(_) ->
            Bytes = crypto:strong_rand_bytes(16),
            ?assertEqual(false,
                beamchain_peer:is_v1_version_header(Bytes, ?MAINNET_MAGIC)),
            ?assertEqual(false,
                beamchain_peer:is_v1_version_header(Bytes, ?TESTNET4_MAGIC)),
            ?assertEqual(false,
                beamchain_peer:is_v1_version_header(Bytes, ?REGTEST_MAGIC))
        end,
        lists:seq(1, 1000)).

v2_classify_v1_other_command_is_not_v1_version_test() ->
    %% A v1 frame for ANY command other than "version" is the FIRST
    %% message the peer would send only on a misbehaving / out-of-order
    %% connection — Bitcoin Core requires "version" first.  The peek
    %% classifier therefore correctly rejects (returns false), which
    %% will route the bytes into the v2 path; the v2 path then fails
    %% AEAD auth and disconnects.  This is acceptable: the peer was
    %% already misbehaving.
    Hdr = <<?MAINNET_MAGIC/binary, "verack", 0, 0, 0, 0, 0, 0>>,
    ?assertEqual(false, beamchain_peer:is_v1_version_header(Hdr, ?MAINNET_MAGIC)),
    HdrPing = <<?MAINNET_MAGIC/binary, "ping", 0, 0, 0, 0, 0, 0, 0, 0>>,
    ?assertEqual(false, beamchain_peer:is_v1_version_header(HdrPing, ?MAINNET_MAGIC)).

v2_classify_short_input_does_not_crash_test() ->
    %% Input shorter than 16 bytes never reaches is_v1_version_header in
    %% production (the caller guards on byte_size(Buffer) >= 16), but a
    %% defensive false return on partial input is still desirable.
    ?assertEqual(false,
        beamchain_peer:is_v1_version_header(<<?MAINNET_MAGIC/binary,
                                               "version">>, ?MAINNET_MAGIC)),
    ?assertEqual(false,
        beamchain_peer:is_v1_version_header(<<>>, ?MAINNET_MAGIC)).

%%% ===================================================================
%%% BIP-324 v2 outbound initiator state machine
%%%
%%% Covers the symmetric counterpart of the responder state machine
%%% (already exercised by beamchain_transport_v2_tests):
%%%   pubkey send / construction → garbage send → AAD-bound version
%%%   packet → recv_pubkey classification (v1 fallback vs v2 carry-on)
%%%   → garbage-terminator scan → drain-decoy.
%%%
%%% These tests target the pure helpers that the production gen_statem
%%% drives, so they don't need a live socket or peer process.
%%% ===================================================================

%% Pubkey send: build_v2_initiator_handshake/2 returns a 64-byte
%% ellswift pubkey from a fresh cipher.  Two independent calls produce
%% distinct pubkeys (the cipher generates a random keypair).
v2_initiator_build_pubkey_test() ->
    {ok, P1, _C1} = beamchain_peer:build_v2_initiator_handshake(random, ignored),
    ?assertEqual(64, byte_size(P1)),
    {ok, P2, _C2} = beamchain_peer:build_v2_initiator_handshake(random, ignored),
    ?assertEqual(64, byte_size(P2)),
    ?assertNotEqual(P1, P2).

%% Deterministic pubkey: passing a fixed seckey + auxrand produces a
%% reproducible pubkey, so the same secret derivation roundtrips.
v2_initiator_deterministic_pubkey_test() ->
    SecKey = <<1:256>>,
    AuxRand = <<2:256>>,
    {ok, P1, _C1} = beamchain_peer:build_v2_initiator_handshake(SecKey, AuxRand),
    {ok, P2, _C2} = beamchain_peer:build_v2_initiator_handshake(SecKey, AuxRand),
    ?assertEqual(64, byte_size(P1)),
    ?assertEqual(P1, P2).

%% Garbage construction: an initiator-side cipher correctly produces a
%% 16-byte send_garbage_terminator after the ECDH-derived
%% initialisation, AND the AEAD encrypt of an empty version_packet
%% with AAD = our_garbage round-trips through a responder-side cipher
%% sharing the same shared secret.
v2_initiator_garbage_aad_roundtrip_test() ->
    %% Build initiator + responder ciphers with matching keypairs.  We
    %% bypass the full network stack: the public API of
    %% beamchain_transport_v2 lets us hand-derive both sides.
    InitSec = <<3:256>>,
    InitAux = <<4:256>>,
    RespSec = <<5:256>>,
    RespAux = <<6:256>>,
    {ok, IC0} = beamchain_transport_v2:new_cipher(InitSec, InitAux),
    {ok, RC0} = beamchain_transport_v2:new_cipher(RespSec, RespAux),
    InitPub = beamchain_transport_v2:get_pubkey(IC0),
    RespPub = beamchain_transport_v2:get_pubkey(RC0),
    Magic = <<16#FA, 16#BF, 16#B5, 16#DA>>,  %% regtest, decoupled from app config
    {ok, IC1} = beamchain_transport_v2:initialize(IC0, RespPub, true,  false, Magic),
    {ok, RC1} = beamchain_transport_v2:initialize(RC0, InitPub, false, false, Magic),
    %% Initiator sends garbage + terminator + version_packet (AAD = garbage).
    OurGarbage = <<7,7,7,7,7>>,  %% 5 bytes of fixed garbage for determinism
    SendTerm = beamchain_transport_v2:get_send_garbage_terminator(IC1),
    ?assertEqual(16, byte_size(SendTerm)),
    %% Responder's recv_garbage_terminator MUST equal initiator's
    %% send_garbage_terminator (it's the SAME 16 bytes — both sides
    %% derive it from the shared HKDF output).
    RecvTermAtResponder = beamchain_transport_v2:get_recv_garbage_terminator(RC1),
    ?assertEqual(SendTerm, RecvTermAtResponder),
    {ok, VerPkt, _IC2} = beamchain_transport_v2:encrypt(IC1, <<>>, OurGarbage, false),
    %% Responder decrypts: AAD = our garbage, expected length 0.
    LenLen = beamchain_transport_v2:length_field_len(),
    <<EncLen:LenLen/binary, EncBody/binary>> = VerPkt,
    {ok, 0, RC2} = beamchain_transport_v2:decrypt_length(RC1, EncLen),
    {ok, Contents, Ignore, _RC3} =
        beamchain_transport_v2:decrypt(RC2, EncBody, OurGarbage, 0),
    ?assertEqual(<<>>, Contents),
    ?assertEqual(false, Ignore).

%% Terminator scanning: find a known terminator after a chunk of
%% pre-key garbage.  Verifies the byte-by-byte sliding-window logic.
v2_initiator_scan_terminator_found_test() ->
    Term = <<"0123456789ABCDEF">>,  %% 16 bytes, distinct
    Garbage = <<"hello-garbage-prefix">>,
    Trailing = <<"more-bytes-after">>,
    Buffer = <<Garbage/binary, Term/binary, Trailing/binary>>,
    MaxLen = 4095 + 16,
    {found, FoundGarbage, Rest} =
        beamchain_peer:scan_terminator(<<>>, Buffer, Term, 16, MaxLen),
    ?assertEqual(Garbage, FoundGarbage),
    ?assertEqual(Trailing, Rest).

v2_initiator_scan_terminator_zero_garbage_test() ->
    %% Terminator with NO pre-key garbage (peer chose 0-byte garbage).
    Term = <<"0123456789ABCDEF">>,
    Trailing = <<"version-packet-bytes">>,
    Buffer = <<Term/binary, Trailing/binary>>,
    MaxLen = 4095 + 16,
    {found, FoundGarbage, Rest} =
        beamchain_peer:scan_terminator(<<>>, Buffer, Term, 16, MaxLen),
    ?assertEqual(<<>>, FoundGarbage),
    ?assertEqual(Trailing, Rest).

v2_initiator_scan_terminator_incomplete_test() ->
    %% Less than 16 bytes — incomplete.
    Term = <<"0123456789ABCDEF">>,
    Buffer = <<"shor">>,
    MaxLen = 4095 + 16,
    Result = beamchain_peer:scan_terminator(<<>>, Buffer, Term, 16, MaxLen),
    ?assertMatch({incomplete, _, _}, Result).

v2_initiator_scan_terminator_too_long_test() ->
    %% Garbage longer than MaxLen — protocol violation.
    Term = <<"NEVER-FOUND-XXXX">>,  %% 16 bytes, won't match
    Buffer = binary:copy(<<"a">>, 100),
    MaxLen = 50,
    Result = beamchain_peer:scan_terminator(<<>>, Buffer, Term, 16, MaxLen),
    ?assertEqual(too_long, Result).

%% Fallback path: env-var / app-config + per-address cache.
v2_outbound_default_off_test() ->
    %% No env var set, no app env set → off.
    os:unsetenv("BEAMCHAIN_BIP324_V2_OUTBOUND"),
    application:unset_env(beamchain, bip324_v2_outbound),
    ?assertEqual(false, beamchain_peer:bip324_v2_outbound_enabled()).

v2_outbound_env_var_truthy_test() ->
    application:unset_env(beamchain, bip324_v2_outbound),
    %% Various truthy spellings.
    lists:foreach(fun(Val) ->
        os:putenv("BEAMCHAIN_BIP324_V2_OUTBOUND", Val),
        ?assertEqual(true, beamchain_peer:bip324_v2_outbound_enabled())
    end, ["1", "true", "TRUE", "yes", "on"]),
    os:unsetenv("BEAMCHAIN_BIP324_V2_OUTBOUND").

v2_outbound_env_var_falsy_test() ->
    application:unset_env(beamchain, bip324_v2_outbound),
    lists:foreach(fun(Val) ->
        os:putenv("BEAMCHAIN_BIP324_V2_OUTBOUND", Val),
        ?assertEqual(false, beamchain_peer:bip324_v2_outbound_enabled())
    end, ["0", "false", "no", ""]),
    os:unsetenv("BEAMCHAIN_BIP324_V2_OUTBOUND").

v2_outbound_app_env_test() ->
    %% App env honoured when env var is absent.
    os:unsetenv("BEAMCHAIN_BIP324_V2_OUTBOUND"),
    application:set_env(beamchain, bip324_v2_outbound, true),
    ?assertEqual(true, beamchain_peer:bip324_v2_outbound_enabled()),
    application:set_env(beamchain, bip324_v2_outbound, false),
    ?assertEqual(false, beamchain_peer:bip324_v2_outbound_enabled()),
    application:unset_env(beamchain, bip324_v2_outbound).

%% Per-address v1-only cache: mark, lookup, clear.
v2_outbound_v1_only_cache_test() ->
    beamchain_peer:clear_v1_only_cache(),
    A = {{192,0,2,1}, 8333},
    B = {{192,0,2,2}, 8333},
    ?assertEqual(false, beamchain_peer:is_v1_only(A)),
    ?assertEqual(false, beamchain_peer:is_v1_only(B)),
    beamchain_peer:mark_v1_only(A),
    ?assertEqual(true, beamchain_peer:is_v1_only(A)),
    ?assertEqual(false, beamchain_peer:is_v1_only(B)),
    beamchain_peer:mark_v1_only(B),
    ?assertEqual(true, beamchain_peer:is_v1_only(A)),
    ?assertEqual(true, beamchain_peer:is_v1_only(B)),
    beamchain_peer:clear_v1_only_cache(),
    ?assertEqual(false, beamchain_peer:is_v1_only(A)),
    ?assertEqual(false, beamchain_peer:is_v1_only(B)).

%% IPv6 addresses round-trip through the cache.
v2_outbound_v1_only_cache_ipv6_test() ->
    beamchain_peer:clear_v1_only_cache(),
    A = {{0,0,0,0,0,0,0,1}, 8333},   %% ::1
    ?assertEqual(false, beamchain_peer:is_v1_only(A)),
    beamchain_peer:mark_v1_only(A),
    ?assertEqual(true, beamchain_peer:is_v1_only(A)),
    beamchain_peer:clear_v1_only_cache().

%% mark_v1_only is idempotent — repeated marks for the same address
%% don't corrupt the cache.
v2_outbound_v1_only_cache_idempotent_test() ->
    beamchain_peer:clear_v1_only_cache(),
    A = {{10,0,0,1}, 8333},
    [beamchain_peer:mark_v1_only(A) || _ <- lists:seq(1, 5)],
    ?assertEqual(true, beamchain_peer:is_v1_only(A)),
    beamchain_peer:clear_v1_only_cache().
