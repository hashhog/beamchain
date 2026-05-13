-module(beamchain_w107_compactsize_tests).

%% W107 — CompactSize + VarInt serialization 30-gate audit
%%
%% Reference: bitcoin-core/src/serialize.h
%%   WriteCompactSize / ReadCompactSize  (lines 300-362)
%%   WriteVarInt / ReadVarInt            (lines 426-464)
%%   MAX_SIZE = 0x02000000               (line 34)
%%
%% Two distinct encodings in beamchain:
%%   1. CompactSize (= Bitcoin "varint" in P2P / block wire format):
%%        beamchain_serialize:encode_varint/1 + decode_varint/1
%%        (despite the name, this IS CompactSize — 1/3/5/9 byte prefix)
%%        Also: beamchain_snapshot:encode_compact_size/1 + decode_compact_size/1
%%              beamchain_mempool_persist delegates to beamchain_serialize
%%   2. VarInt  (Bitcoin Core serialize.h WriteVarInt/ReadVarInt — MSB-first
%%        base-128 variable-length encoding used in UTXO snapshot coins):
%%        beamchain_snapshot:encode_varint/1 + decode_varint/1
%%
%% Gate groups:
%%   G1-G9    CompactSize wire encoding (beamchain_serialize)
%%   G10-G15  CompactSize MAX_SIZE + range checks
%%   G16-G22  VarInt (MSB-base-128, snapshot) correctness
%%   G23-G27  VarInt overflow / truncation guards
%%   G28-G30  Cross-context correctness: snapshot, mempool_persist, p2p_msg

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% -------------------------------------------------------------------
%%% G1: CompactSize 1-byte range [0,252] encodes as single byte
%%% Core: if (nSize < 253) ser_writedata8(os, nSize)
%%% -------------------------------------------------------------------

g1_compact_size_single_byte_zero_test() ->
    ?assertEqual(<<0>>, beamchain_serialize:encode_varint(0)).

g1_compact_size_single_byte_252_test() ->
    %% 252 (0xFC) is the largest single-byte CompactSize.
    ?assertEqual(<<252>>, beamchain_serialize:encode_varint(252)).

g1_compact_size_single_byte_roundtrip_test() ->
    Values = lists:seq(0, 252),
    lists:foreach(fun(V) ->
        Enc = beamchain_serialize:encode_varint(V),
        ?assertEqual(1, byte_size(Enc),
                     {single_byte_expected_for, V}),
        ?assertEqual({V, <<>>}, beamchain_serialize:decode_varint(Enc))
    end, Values).

%%% -------------------------------------------------------------------
%%% G2: CompactSize 3-byte range [253, 65535] uses 0xFD prefix
%%% Core: ser_writedata8(os, 253); ser_writedata16(os, nSize)
%%% -------------------------------------------------------------------

g2_compact_size_3byte_253_test() ->
    Enc = beamchain_serialize:encode_varint(253),
    %% must be exactly 3 bytes: 0xFD + 16-bit LE
    ?assertEqual(3, byte_size(Enc)),
    ?assertMatch(<<16#FD, 253:16/little>>, Enc).

g2_compact_size_3byte_65535_test() ->
    Enc = beamchain_serialize:encode_varint(65535),
    ?assertEqual(3, byte_size(Enc)),
    ?assertMatch(<<16#FD, 65535:16/little>>, Enc).

g2_compact_size_3byte_roundtrip_test() ->
    Values = [253, 254, 255, 1000, 65534, 65535],
    lists:foreach(fun(V) ->
        Enc = beamchain_serialize:encode_varint(V),
        ?assertEqual(3, byte_size(Enc),
                     {three_byte_expected_for, V}),
        ?assertEqual({V, <<>>}, beamchain_serialize:decode_varint(Enc))
    end, Values).

%%% -------------------------------------------------------------------
%%% G3: CompactSize 5-byte range [65536, 2^32-1] uses 0xFE prefix
%%% Core: ser_writedata8(os, 254); ser_writedata32(os, nSize)
%%% -------------------------------------------------------------------

g3_compact_size_5byte_65536_test() ->
    Enc = beamchain_serialize:encode_varint(65536),
    ?assertEqual(5, byte_size(Enc)),
    ?assertMatch(<<16#FE, 65536:32/little>>, Enc).

g3_compact_size_5byte_max32_test() ->
    Enc = beamchain_serialize:encode_varint(4294967295),  %% 2^32 - 1
    ?assertEqual(5, byte_size(Enc)),
    ?assertMatch(<<16#FE, 4294967295:32/little>>, Enc).

g3_compact_size_5byte_roundtrip_test() ->
    Values = [65536, 100000, 16#00FFFFFF, 16#FFFFFFFF],
    lists:foreach(fun(V) ->
        Enc = beamchain_serialize:encode_varint(V),
        ?assertEqual(5, byte_size(Enc),
                     {five_byte_expected_for, V}),
        ?assertEqual({V, <<>>}, beamchain_serialize:decode_varint(Enc))
    end, Values).

%%% -------------------------------------------------------------------
%%% G4: CompactSize 9-byte range [2^32, 2^64-1] uses 0xFF prefix
%%% Core: ser_writedata8(os, 255); ser_writedata64(os, nSize)
%%% -------------------------------------------------------------------

g4_compact_size_9byte_base_test() ->
    Enc = beamchain_serialize:encode_varint(4294967296),  %% 2^32
    ?assertEqual(9, byte_size(Enc)),
    ?assertMatch(<<16#FF, 4294967296:64/little>>, Enc).

g4_compact_size_9byte_large_test() ->
    Enc = beamchain_serialize:encode_varint(16#0102030405060708),
    ?assertEqual(9, byte_size(Enc)),
    ?assertMatch(<<16#FF, 16#0102030405060708:64/little>>, Enc).

g4_compact_size_9byte_roundtrip_test() ->
    Values = [4294967296, 4294967297, 16#00FFFFFFFFFFFFFF],
    lists:foreach(fun(V) ->
        Enc = beamchain_serialize:encode_varint(V),
        ?assertEqual(9, byte_size(Enc),
                     {nine_byte_expected_for, V}),
        ?assertEqual({V, <<>>}, beamchain_serialize:decode_varint(Enc))
    end, Values).

%%% -------------------------------------------------------------------
%%% G5: CompactSize decode returns (value, rest) with trailing bytes intact
%%% Core: ReadCompactSize returns only the integer; stream positioned after
%%% -------------------------------------------------------------------

g5_compact_size_decode_rest_1byte_test() ->
    {252, <<16#AA, 16#BB>>} =
        beamchain_serialize:decode_varint(<<252, 16#AA, 16#BB>>).

g5_compact_size_decode_rest_3byte_test() ->
    {1000, <<"rest">>} =
        beamchain_serialize:decode_varint(<<16#FD, 1000:16/little, "rest">>).

g5_compact_size_decode_rest_5byte_test() ->
    {65536, <<"tail">>} =
        beamchain_serialize:decode_varint(<<16#FE, 65536:32/little, "tail">>).

g5_compact_size_decode_rest_9byte_test() ->
    {4294967296, <<"end">>} =
        beamchain_serialize:decode_varint(<<16#FF, 4294967296:64/little, "end">>).

%%% -------------------------------------------------------------------
%%% G6: CompactSize non-canonical encoding: values that SHOULD be
%%% rejected by ReadCompactSize() — Core throws "non-canonical ReadCompactSize()"
%% BUG-1 (MISSING CANONICAL CHECK): beamchain_serialize:decode_varint does NOT
%%        reject non-canonical forms:
%%          0xFD 0x00 0x00 encodes 0 (canonical would be 0x00)
%%          0xFD 0xFC 0x00 encodes 252 (canonical would be 0xFC)
%%          0xFE 0x00 0x01 0x00 0x00 encodes 256 (canonical 0xFD 0x00 0x01)
%%          0xFF 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 encodes 65536
%%        Core: raise ios_base::failure("non-canonical ReadCompactSize()")
%%              for each: fd-read < 253, fe-read < 0x10000, ff-read < 0x100000000
%%
%% These tests document the BUG — they PASS currently (decode succeeds, no
%% error), which is WRONG. A conformant impl must FAIL/ERROR on non-canonical.
%%% -------------------------------------------------------------------

%% BUG-1a: 0xFD followed by value < 253 (should be rejected by Core)
g6_non_canonical_fd_below_253_accepted_bug_test() ->
    %% Core throws "non-canonical ReadCompactSize()"; beamchain must now also
    %% reject. FIX: returns {error, non_canonical_compact_size}.
    Result = beamchain_serialize:decode_varint(<<16#FD, 0, 0>>),
    ?assertEqual({error, non_canonical_compact_size}, Result).

%% BUG-1b: 0xFE followed by value < 65536 (should be rejected by Core)
g6_non_canonical_fe_below_65536_accepted_bug_test() ->
    %% Core throws "non-canonical ReadCompactSize()"; beamchain must now also
    %% reject. FIX: returns {error, non_canonical_compact_size}.
    Result = beamchain_serialize:decode_varint(<<16#FE, 255, 0, 0, 0>>),
    ?assertEqual({error, non_canonical_compact_size}, Result).

%% BUG-1c: 0xFF followed by value < 2^32 (should be rejected by Core)
g6_non_canonical_ff_below_2_32_accepted_bug_test() ->
    %% 0xFF 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 = 65536 via 9-byte form.
    %% Core rejects "non-canonical ReadCompactSize()"; beamchain must also
    %% reject. FIX: returns {error, non_canonical_compact_size}.
    Result = beamchain_serialize:decode_varint(<<16#FF, 0, 0, 1, 0, 0, 0, 0, 0>>),
    ?assertEqual({error, non_canonical_compact_size}, Result).

%%% -------------------------------------------------------------------
%%% G7: CompactSize snapshot module — encode_compact_size / decode_compact_size
%%% Returns {ok, N, Rest} with explicit error on truncation
%%% -------------------------------------------------------------------

g7_snapshot_compact_size_encode_test() ->
    ?assertEqual(<<0>>,    beamchain_snapshot:encode_compact_size(0)),
    ?assertEqual(<<252>>,  beamchain_snapshot:encode_compact_size(252)),
    ?assertMatch(<<16#FD, 253:16/little>>, beamchain_snapshot:encode_compact_size(253)),
    ?assertMatch(<<16#FE, 65536:32/little>>, beamchain_snapshot:encode_compact_size(65536)).

g7_snapshot_compact_size_decode_1byte_test() ->
    ?assertEqual({ok, 0, <<>>},   beamchain_snapshot:decode_compact_size(<<0>>)),
    ?assertEqual({ok, 252, <<>>}, beamchain_snapshot:decode_compact_size(<<252>>)).

g7_snapshot_compact_size_decode_3byte_test() ->
    ?assertEqual({ok, 253, <<>>},
        beamchain_snapshot:decode_compact_size(<<253, 253:16/little>>)).

g7_snapshot_compact_size_decode_5byte_test() ->
    ?assertEqual({ok, 65536, <<>>},
        beamchain_snapshot:decode_compact_size(<<254, 65536:32/little>>)).

g7_snapshot_compact_size_decode_9byte_test() ->
    ?assertEqual({ok, 4294967296, <<>>},
        beamchain_snapshot:decode_compact_size(<<255, 4294967296:64/little>>)).

g7_snapshot_compact_size_decode_error_truncated_test() ->
    %% empty binary must return an error, not crash
    ?assertEqual({error, truncated_compact_size},
        beamchain_snapshot:decode_compact_size(<<>>)).

%%% -------------------------------------------------------------------
%%% G8: CompactSize snapshot non-canonical — same BUG-1 applies
%%% BUG-2: snapshot's decode_compact_size also silently accepts non-canonical
%%% (mirrors the wire-serialize bug — both implementations share the flaw)
%%% -------------------------------------------------------------------

g8_snapshot_non_canonical_fd_bug_test() ->
    %% 0xFD 0x00 0x00 = 0 via 3-byte form — Core rejects; beamchain must also
    %% reject. FIX: returns {error, non_canonical_compact_size}.
    Result = beamchain_snapshot:decode_compact_size(<<16#FD, 0, 0>>),
    ?assertEqual({error, non_canonical_compact_size}, Result).

g8_snapshot_non_canonical_fe_bug_test() ->
    %% 0xFE 0x00 0x01 0x00 0x00 = 256 via 5-byte form — Core rejects; beamchain
    %% must also reject. FIX: returns {error, non_canonical_compact_size}.
    Result = beamchain_snapshot:decode_compact_size(<<16#FE, 0, 1, 0, 0>>),
    ?assertEqual({error, non_canonical_compact_size}, Result).

%%% -------------------------------------------------------------------
%%% G9: CompactSize mempool_persist delegates to beamchain_serialize
%%% (round-trip identical to wire format)
%%% -------------------------------------------------------------------

g9_mempool_persist_compact_size_roundtrip_test() ->
    Values = [0, 1, 252, 253, 65535, 65536, 4294967295],
    lists:foreach(fun(V) ->
        Enc = beamchain_mempool_persist:encode_compact_size(V),
        ?assertEqual({V, <<>>},
            beamchain_mempool_persist:decode_compact_size(Enc),
            {roundtrip_failed_for, V})
    end, Values).

%%% -------------------------------------------------------------------
%%% G10: MAX_SIZE check — Core rejects CompactSize values > 0x02000000
%%% BUG-3 (MISSING MAX_SIZE GUARD): beamchain_serialize:decode_varint has NO
%%        check for value > MAX_SIZE (0x02000000 = 33554432). Core throws
%%        "ReadCompactSize(): size too large" when range_check=true (default).
%%        This allows a malicious peer to claim vector lengths > 32MB, leading
%%        to attempted memory allocation before data is received.
%%% -------------------------------------------------------------------

g10_max_size_value_is_33554432_test() ->
    %% MAX_SIZE = 0x02000000 = 33,554,432 — just boundary OK in Core
    MaxSize = 16#02000000,
    %% beamchain silently accepts it (BUG: should be the last valid value
    %% but Core's range_check=true allows exactly MAX_SIZE)
    Enc = beamchain_serialize:encode_varint(MaxSize),
    {Decoded, <<>>} = beamchain_serialize:decode_varint(Enc),
    ?assertEqual(MaxSize, Decoded).

g10_above_max_size_accepted_bug_test() ->
    %% Core throws "ReadCompactSize(): size too large" for N > MAX_SIZE.
    %% FIX: beamchain now returns {error, oversized_compact_size}.
    AboveMax = 16#02000001,
    Enc = beamchain_serialize:encode_varint(AboveMax),
    ?assertEqual({error, oversized_compact_size},
                 beamchain_serialize:decode_varint(Enc)).

g10_large_value_no_range_check_test() ->
    %% Values much larger than MAX_SIZE must now be rejected.
    %% FIX: beamchain returns {error, oversized_compact_size}.
    LargeVal = 16#0FFFFFFF,
    Enc = beamchain_serialize:encode_varint(LargeVal),
    ?assertEqual({error, oversized_compact_size},
                 beamchain_serialize:decode_varint(Enc)).

%%% -------------------------------------------------------------------
%%% G11: Snapshot decode_compact_size also lacks MAX_SIZE check
%%% BUG-4: same missing guard as G10, in snapshot context
%%% -------------------------------------------------------------------

g11_snapshot_no_max_size_check_bug_test() ->
    %% 0x03000000 > MAX_SIZE — snapshot must now reject.
    %% FIX: beamchain returns {error, oversized_compact_size}.
    TooLarge = 16#03000000,
    Enc = beamchain_snapshot:encode_compact_size(TooLarge),
    ?assertEqual({error, oversized_compact_size},
                 beamchain_snapshot:decode_compact_size(Enc)).

%%% -------------------------------------------------------------------
%%% G12: GetSizeOfCompactSize equivalent — no function in beamchain
%%% BUG-5: beamchain has no GetSizeOfCompactSize-equivalent; code that
%%         needs to pre-compute encoded size of a count (e.g., for tx weight)
%%         must encode + measure, wasting allocation.
%%% -------------------------------------------------------------------

g12_get_size_of_compact_size_not_available_test() ->
    %% Verify by encoding and measuring: the correct size can be derived
    ?assertEqual(1, byte_size(beamchain_serialize:encode_varint(0))),
    ?assertEqual(1, byte_size(beamchain_serialize:encode_varint(252))),
    ?assertEqual(3, byte_size(beamchain_serialize:encode_varint(253))),
    ?assertEqual(3, byte_size(beamchain_serialize:encode_varint(65535))),
    ?assertEqual(5, byte_size(beamchain_serialize:encode_varint(65536))),
    ?assertEqual(5, byte_size(beamchain_serialize:encode_varint(4294967295))),
    ?assertEqual(9, byte_size(beamchain_serialize:encode_varint(4294967296))).

%%% -------------------------------------------------------------------
%%% G13: Wire-format decode truncated multi-byte CompactSize — silent misparse
%%% BUG-7 (SILENT TRUNCATION MISPARSE): When a multi-byte CompactSize prefix
%%% (0xFD/0xFE/0xFF) is present but the following bytes are truncated, beamchain's
%%% Erlang pattern-match fallback silently interprets the prefix byte as a
%%% single-byte value (< 253) via the catch-all clause, returning garbage.
%%%
%%% Core: ReadCompactSize reads the first byte, then explicitly reads the
%%% following N bytes — would throw ios_base::failure on short read.
%%% beamchain: <<16#FD, N:16/little, Rest/binary>> fails to match on 1 trailing
%%% byte; Erlang falls through to <<N:8, Rest/binary>> which matches 0xFD=253
%%% as a single-byte value and returns {253, <<remaining_byte>>} — wrong.
%%%
%%% These tests document the current WRONG behaviour.
%%% -------------------------------------------------------------------

g13_decode_truncated_3byte_misparse_bug_test() ->
    %% 0xFD + 1 byte only — should be an error, is silently misparsed.
    %% The 3-byte pattern fails; catch-all reads 0xFD as single-byte 253.
    %% Returns {253, <<0>>} instead of {error, _} or exception.
    Result = beamchain_serialize:decode_varint(<<16#FD, 0>>),
    ?assertEqual({253, <<0>>}, Result).  %% documents BUG-7 wrong value

g13_decode_truncated_5byte_misparse_bug_test() ->
    %% 0xFE + 3 bytes only — 5-byte pattern fails; catch-all reads 0xFE=254
    Result = beamchain_serialize:decode_varint(<<16#FE, 0, 0, 0>>),
    ?assertEqual({254, <<0, 0, 0>>}, Result).  %% BUG-7: wrong, should error

g13_decode_truncated_9byte_misparse_bug_test() ->
    %% 0xFF + 7 bytes only — 9-byte pattern fails; catch-all reads 0xFF=255
    Result = beamchain_serialize:decode_varint(
        <<16#FF, 0, 0, 0, 0, 0, 0, 0>>),
    ?assertEqual({255, <<0, 0, 0, 0, 0, 0, 0>>}, Result).  %% BUG-7: wrong

%%% -------------------------------------------------------------------
%%% G14: Wire-format decode empty input crashes
%%% BUG-8: No safe error return for empty input — badmatch exception
%%% Core: would throw ios_base::failure on EOF during read
%%% -------------------------------------------------------------------

g14_decode_empty_crashes_test() ->
    %% empty binary matches no clause in decode_varint → {badmatch,<<>>}
    ?assertException(error, _, beamchain_serialize:decode_varint(<<>>)).

%%% -------------------------------------------------------------------
%%% G15: Snapshot decode_compact_size handles truncated forms safely
%%% Returns {error, truncated_compact_size} — safe error path
%%% (This is CORRECT in snapshot; G13/G14 show the wire-serialize module
%%  does NOT have this safe path — the safety gap between the two modules)
%%% -------------------------------------------------------------------

g15_snapshot_truncated_3byte_safe_test() ->
    %% 0xFD + 1 byte only — snapshot returns safe error
    Result = beamchain_snapshot:decode_compact_size(<<16#FD, 0>>),
    ?assertEqual({error, truncated_compact_size}, Result).

g15_snapshot_truncated_5byte_safe_test() ->
    Result = beamchain_snapshot:decode_compact_size(<<16#FE, 0, 0, 0>>),
    ?assertEqual({error, truncated_compact_size}, Result).

g15_snapshot_truncated_9byte_safe_test() ->
    Result = beamchain_snapshot:decode_compact_size(<<16#FF, 0, 0, 0, 0, 0, 0, 0>>),
    ?assertEqual({error, truncated_compact_size}, Result).

%%% -------------------------------------------------------------------
%%% G16: VarInt (MSB-base-128) — basic encoding correctness
%%% Core's known test vectors from serialize.h comment block:
%%%   0 → [0x00], 1 → [0x01], 127 → [0x7F]
%%%   128 → [0x80 0x00], 255 → [0x80 0x7F], 256 → [0x81 0x00]
%%%   16383 → [0xFE 0x7F], 16384 → [0xFF 0x00], 16511 → [0xFF 0x7F]
%%%   65535 → [0x82 0xFE 0x7F]
%%%   2^32 → [0x8E 0xFE 0xFE 0xFF 0x00]
%%% -------------------------------------------------------------------

g16_varint_vector_0_test() ->
    ?assertEqual(<<16#00>>, beamchain_snapshot:encode_varint(0)).

g16_varint_vector_1_test() ->
    ?assertEqual(<<16#01>>, beamchain_snapshot:encode_varint(1)).

g16_varint_vector_127_test() ->
    ?assertEqual(<<16#7F>>, beamchain_snapshot:encode_varint(127)).

g16_varint_vector_128_test() ->
    ?assertEqual(<<16#80, 16#00>>, beamchain_snapshot:encode_varint(128)).

g16_varint_vector_255_test() ->
    ?assertEqual(<<16#80, 16#7F>>, beamchain_snapshot:encode_varint(255)).

g16_varint_vector_256_test() ->
    ?assertEqual(<<16#81, 16#00>>, beamchain_snapshot:encode_varint(256)).

g16_varint_vector_16383_test() ->
    ?assertEqual(<<16#FE, 16#7F>>, beamchain_snapshot:encode_varint(16383)).

g16_varint_vector_16384_test() ->
    ?assertEqual(<<16#FF, 16#00>>, beamchain_snapshot:encode_varint(16384)).

g16_varint_vector_16511_test() ->
    ?assertEqual(<<16#FF, 16#7F>>, beamchain_snapshot:encode_varint(16511)).

g16_varint_vector_65535_test() ->
    ?assertEqual(<<16#82, 16#FE, 16#7F>>, beamchain_snapshot:encode_varint(65535)).

g16_varint_vector_2_32_test() ->
    ?assertEqual(<<16#8E, 16#FE, 16#FE, 16#FF, 16#00>>,
                 beamchain_snapshot:encode_varint(4294967296)).

%%% -------------------------------------------------------------------
%%% G17: VarInt decode roundtrip against Core vectors
%%% -------------------------------------------------------------------

g17_varint_decode_0_test() ->
    ?assertEqual({ok, 0, <<>>},
        beamchain_snapshot:decode_varint(<<16#00>>)).

g17_varint_decode_1_test() ->
    ?assertEqual({ok, 1, <<>>},
        beamchain_snapshot:decode_varint(<<16#01>>)).

g17_varint_decode_127_test() ->
    ?assertEqual({ok, 127, <<>>},
        beamchain_snapshot:decode_varint(<<16#7F>>)).

g17_varint_decode_128_test() ->
    ?assertEqual({ok, 128, <<>>},
        beamchain_snapshot:decode_varint(<<16#80, 16#00>>)).

g17_varint_decode_255_test() ->
    ?assertEqual({ok, 255, <<>>},
        beamchain_snapshot:decode_varint(<<16#80, 16#7F>>)).

g17_varint_decode_256_test() ->
    ?assertEqual({ok, 256, <<>>},
        beamchain_snapshot:decode_varint(<<16#81, 16#00>>)).

g17_varint_decode_16383_test() ->
    ?assertEqual({ok, 16383, <<>>},
        beamchain_snapshot:decode_varint(<<16#FE, 16#7F>>)).

g17_varint_decode_16384_test() ->
    ?assertEqual({ok, 16384, <<>>},
        beamchain_snapshot:decode_varint(<<16#FF, 16#00>>)).

g17_varint_decode_65535_test() ->
    ?assertEqual({ok, 65535, <<>>},
        beamchain_snapshot:decode_varint(<<16#82, 16#FE, 16#7F>>)).

g17_varint_decode_2_32_test() ->
    ?assertEqual({ok, 4294967296, <<>>},
        beamchain_snapshot:decode_varint(<<16#8E, 16#FE, 16#FE, 16#FF, 16#00>>)).

%%% -------------------------------------------------------------------
%%% G18: VarInt encode-decode roundtrip over a wide value range
%%% -------------------------------------------------------------------

g18_varint_roundtrip_small_values_test() ->
    Values = lists:seq(0, 200),
    lists:foreach(fun(V) ->
        Enc = beamchain_snapshot:encode_varint(V),
        ?assertEqual({ok, V, <<>>},
            beamchain_snapshot:decode_varint(Enc),
            {varint_roundtrip_failed_for, V})
    end, Values).

g18_varint_roundtrip_boundary_values_test() ->
    Values = [127, 128, 255, 256, 16383, 16384, 16511, 65535, 65536,
              16#FFFFFF, 16#1000000, 4294967295, 4294967296,
              16#FFFFFFFFFFFFFFFF],
    lists:foreach(fun(V) ->
        Enc = beamchain_snapshot:encode_varint(V),
        ?assertEqual({ok, V, <<>>},
            beamchain_snapshot:decode_varint(Enc),
            {varint_roundtrip_failed_for, V})
    end, Values).

%%% -------------------------------------------------------------------
%%% G19: VarInt bijection — every integer has exactly ONE encoding
%%% (Core comment: "No redundancy: every byte sequence corresponds to
%%% a list of encoded integers")
%%% Two distinct integers must produce distinct encodings (injectivity)
%%% -------------------------------------------------------------------

g19_varint_distinct_values_distinct_encodings_test() ->
    Values = [0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536],
    Encoded = [beamchain_snapshot:encode_varint(V) || V <- Values],
    %% All encodings must be distinct (injective)
    ?assertEqual(length(Encoded), length(lists:usort(Encoded))).

%%% -------------------------------------------------------------------
%%% G20: VarInt — the "subtract 1" invariant in continuation bytes
%%% Core: n = (n >> 7) - 1 during encode; n++ after continuation during decode
%%% This ensures bijection. Test: decode(encode(N)) == N for challenging values
%%% that exercise the subtraction path.
%%% -------------------------------------------------------------------

g20_varint_subtraction_invariant_127_128_test() ->
    %% 127 encodes as [0x7F] (no continuation)
    %% 128 encodes as [0x80, 0x00] (continuation byte = 0x80, then 0x00)
    %% key: the 0x80 continuation byte means "128 + (0 + 1) - 1 = 128"
    ?assertEqual({ok, 127, <<>>},
        beamchain_snapshot:decode_varint(beamchain_snapshot:encode_varint(127))),
    ?assertEqual({ok, 128, <<>>},
        beamchain_snapshot:decode_varint(beamchain_snapshot:encode_varint(128))).

g20_varint_three_byte_boundary_test() ->
    %% 16384 = first value needing 3 bytes [0xFF, 0x00]
    %% 16383 = last value in 2 bytes [0xFE, 0x7F]
    ?assertEqual({ok, 16383, <<>>},
        beamchain_snapshot:decode_varint(beamchain_snapshot:encode_varint(16383))),
    ?assertEqual({ok, 16384, <<>>},
        beamchain_snapshot:decode_varint(beamchain_snapshot:encode_varint(16384))).

%%% -------------------------------------------------------------------
%%% G21: VarInt overflow guard in decode
%%% Core: if (n > (max >> 7)) throw "ReadVarInt(): size too large"
%%% beamchain_snapshot:decode_varint_loop checks N > 0xFFFFFFFFFFFFFFFF bsr 7
%%% -------------------------------------------------------------------

g21_varint_overflow_guard_fires_test() ->
    %% Craft a byte sequence that would require N > 2^64-1 during decode.
    %% Feed 11 continuation bytes (each 0x80); after 10 bytes N exceeds
    %% the 64-bit overflow ceiling, so the 11th byte triggers varint_overflow.
    %% (10 bytes alone exhaust the binary → truncated_varint, not overflow.)
    OverflowSeq = binary:copy(<<16#80>>, 11),  %% 11 continuation bytes
    ?assertEqual({error, varint_overflow},
        beamchain_snapshot:decode_varint(OverflowSeq)).

%%% -------------------------------------------------------------------
%%% G22: VarInt truncated input returns {error, truncated_varint}
%%% (safe error path — unlike the wire CompactSize G13/G14)
%%% -------------------------------------------------------------------

g22_varint_truncated_empty_test() ->
    ?assertEqual({error, truncated_varint},
        beamchain_snapshot:decode_varint(<<>>)).

g22_varint_truncated_mid_sequence_test() ->
    %% Start of a 2-byte sequence (0x80 = continuation bit set) with no second byte
    ?assertEqual({error, truncated_varint},
        beamchain_snapshot:decode_varint(<<16#80>>)).

g22_varint_truncated_long_sequence_test() ->
    %% 4 continuation bytes and no terminator
    ?assertEqual({error, truncated_varint},
        beamchain_snapshot:decode_varint(<<16#80, 16#80, 16#80, 16#80>>)).

%%% -------------------------------------------------------------------
%%% G23: VarInt vs CompactSize are DIFFERENT encodings — cross-contamination test
%%% A value encoded with CompactSize must NOT decode correctly as VarInt
%%% (and vice versa for non-trivial values)
%%% -------------------------------------------------------------------

g23_compact_size_not_varint_for_128_test() ->
    %% CompactSize(128) = <<128>> (single byte — same as raw 0x80)
    %% VarInt decoding of <<128>> treats it as a continuation byte with
    %% no terminator → truncation error (safe parse mismatch)
    CSEnc = beamchain_serialize:encode_varint(128),
    ?assertEqual(<<128>>, CSEnc),
    %% Feeding CompactSize(128) to snapshot VarInt decoder:
    VIResult = beamchain_snapshot:decode_varint(CSEnc),
    %% Should be error or wrong value — NOT {ok, 128, <<>>}
    ?assertNotEqual({ok, 128, <<>>}, VIResult).

g23_varint_not_compact_size_for_128_test() ->
    %% VarInt(128) = <<0x80, 0x00>>
    VIEnc = beamchain_snapshot:encode_varint(128),
    ?assertEqual(<<16#80, 16#00>>, VIEnc),
    %% Feeding VarInt(128) to wire CompactSize decoder:
    CSResult = beamchain_serialize:decode_varint(VIEnc),
    %% Should NOT be {128, <<>>} — the 0x80 byte is treated as single-byte 128
    %% in CompactSize (value < 253), leaving <<0x00>> as rest
    ?assertNotEqual({128, <<>>}, CSResult),
    ?assertEqual({128, <<0>>}, CSResult).

%%% -------------------------------------------------------------------
%%% G24: AmountCompression roundtrip (uses VarInt internally)
%%% Core: CompressAmount / DecompressAmount (compressor.cpp)
%%% Snapshot-file coin values are VarInt(CompressAmount(nValue))
%%% -------------------------------------------------------------------

g24_amount_compress_zero_test() ->
    ?assertEqual(0, beamchain_snapshot:compress_amount(0)).

g24_amount_compress_one_satoshi_test() ->
    %% Core: 1 sat → compress_amount = 1 (E=0, N=1, D=1 → 1 + (0*9+0)*10+0 = 1)
    ?assertEqual(1, beamchain_snapshot:compress_amount(1)).

g24_amount_compress_1btc_test() ->
    %% 1 BTC = 100_000_000 sat
    %% DecompressAmount(CompressAmount(100_000_000)) must round-trip
    Compressed = beamchain_snapshot:compress_amount(100000000),
    ?assertEqual(100000000, beamchain_snapshot:decompress_amount(Compressed)).

g24_amount_compress_21m_btc_test() ->
    %% MAX_MONEY = 21M BTC = 2_100_000_000_000_000 sat
    MaxMoney = ?MAX_MONEY,
    Compressed = beamchain_snapshot:compress_amount(MaxMoney),
    ?assertEqual(MaxMoney, beamchain_snapshot:decompress_amount(Compressed)).

g24_amount_roundtrip_values_test() ->
    Values = [0, 1, 100, 546, 1000, 10000, 100000, 1000000, 100000000,
              1000000000, 100000000000, 2100000000000000],
    lists:foreach(fun(V) ->
        C = beamchain_snapshot:compress_amount(V),
        ?assertEqual(V, beamchain_snapshot:decompress_amount(C),
                     {amount_roundtrip_failed_for, V})
    end, Values).

%%% -------------------------------------------------------------------
%%% G25: Snapshot coin roundtrip: serialize_coin / parse_coin
%%% Uses VarInt for code + compressed amount; CompactSize for script size
%%% -------------------------------------------------------------------

g25_snapshot_coin_roundtrip_p2pkh_test() ->
    %% P2PKH output — special script type 0
    Script = <<16#76, 16#a9, 20, 0:160, 16#88, 16#ac>>,
    Utxo = #utxo{value = 5000000000, script_pubkey = Script,
                 is_coinbase = true, height = 100000},
    Bin = beamchain_snapshot:serialize_coin(Utxo),
    {ok, Decoded, <<>>} = beamchain_snapshot:parse_coin(Bin),
    ?assertEqual(Utxo#utxo.value, Decoded#utxo.value),
    ?assertEqual(Utxo#utxo.script_pubkey, Decoded#utxo.script_pubkey),
    ?assertEqual(Utxo#utxo.is_coinbase, Decoded#utxo.is_coinbase),
    ?assertEqual(Utxo#utxo.height, Decoded#utxo.height).

g25_snapshot_coin_roundtrip_p2wpkh_test() ->
    %% P2WPKH — native segwit, NOT a special script → raw path
    Script = <<16#00, 16#14, 0:160>>,  %% OP_0 PUSH20 <20-bytes>
    Utxo = #utxo{value = 1000000, script_pubkey = Script,
                 is_coinbase = false, height = 700000},
    Bin = beamchain_snapshot:serialize_coin(Utxo),
    {ok, Decoded, <<>>} = beamchain_snapshot:parse_coin(Bin),
    ?assertEqual(Script, Decoded#utxo.script_pubkey).

%%% -------------------------------------------------------------------
%%% G26: Snapshot metadata roundtrip
%%% Header contains uint64 LE count (NOT CompactSize) — correct in beamchain
%%% -------------------------------------------------------------------

g26_snapshot_metadata_roundtrip_test() ->
    Magic = <<16#F9, 16#BE, 16#B4, 16#D9>>,  %% mainnet magic
    BaseHash = crypto:strong_rand_bytes(32),
    NumCoins = 100000000,
    Bin = beamchain_snapshot:serialize_metadata(Magic, BaseHash, NumCoins),
    ?assertEqual(51, byte_size(Bin)),
    {ok, Meta, <<>>} = beamchain_snapshot:parse_metadata(Bin),
    ?assertEqual(BaseHash, maps:get(base_hash, Meta)),
    ?assertEqual(NumCoins, maps:get(num_coins, Meta)),
    ?assertEqual(Magic, maps:get(network_magic, Meta)).

g26_snapshot_metadata_size_correct_test() ->
    ?assertEqual(51, beamchain_snapshot:metadata_size()).

%%% -------------------------------------------------------------------
%%% G27: P2P encode_varint / decode_varint used in block/tx list lengths
%%% Large list (> 252 items) must use 3-byte CompactSize
%%% -------------------------------------------------------------------

g27_p2p_large_list_encoding_test() ->
    %% 256 items → count must be 3-byte CompactSize (0xFD 0x00 0x01)
    Enc = beamchain_serialize:encode_varint(256),
    ?assertEqual(3, byte_size(Enc)),
    ?assertMatch(<<16#FD, 256:16/little>>, Enc),
    {256, <<>>} = beamchain_serialize:decode_varint(Enc).

g27_p2p_small_list_encoding_test() ->
    %% < 253 items → single byte
    Enc = beamchain_serialize:encode_varint(100),
    ?assertEqual(1, byte_size(Enc)),
    {100, <<>>} = beamchain_serialize:decode_varint(Enc).

%%% -------------------------------------------------------------------
%%% G28: decode_varstr safety — decode_varstr calls decode_varint (wire CS)
%%% then takes N bytes. If decoded length > available bytes, crashes.
%%% BUG-6: No length guard in decode_varstr — malicious length field causes
%%%        badmatch exception in the binary pattern <<Str:Len/binary, ...>>
%%% -------------------------------------------------------------------

g28_varstr_normal_roundtrip_test() ->
    Data = <<"hello world">>,
    Enc = beamchain_serialize:encode_varstr(Data),
    ?assertEqual({Data, <<>>}, beamchain_serialize:decode_varstr(Enc)).

g28_varstr_empty_roundtrip_test() ->
    ?assertEqual({<<>>, <<>>},
        beamchain_serialize:decode_varstr(
            beamchain_serialize:encode_varstr(<<>>))).

g28_varstr_oversized_length_crashes_bug_test() ->
    %% Encode a CompactSize length of 100 but provide only 3 bytes of data.
    %% decode_varstr will try to match <<Str:100/binary, Rest>> and crash.
    %% This is a BUG: should return {error, truncated} not raise exception.
    FakeBin = <<100, "abc">>,  %% length=100 but only 3 bytes follow
    ?assertException(error, _, beamchain_serialize:decode_varstr(FakeBin)).

%%% -------------------------------------------------------------------
%%% G29: tx_weight uses encode_varint for tx-count prefix in block_weight
%%% Verify the varint size influences block weight calculation correctly
%%% -------------------------------------------------------------------

g29_block_weight_varint_count_test() ->
    %% block_weight/1 uses encode_varint(length(Txs)) * 4 for the tx-count field.
    %% A block with 0 txs: varint(0) = 1 byte → contributes 4 weight units.
    %% A block with 253 txs: varint(253) = 3 bytes → contributes 12 weight units.
    %% We create minimal transactions to test the count field only.
    CoinbaseTx = #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
                         script_sig = <<4, 1, 0, 0, 0>>,
                         sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 5000000000,
                           script_pubkey = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>}],
        locktime = 0
    },
    W1 = beamchain_serialize:block_weight([CoinbaseTx]),
    %% Header contributes 80*4=320; varint(1)=1byte contributes 4; tx weight
    TxWeight = beamchain_serialize:tx_weight(CoinbaseTx),
    ExpectedW1 = 320 + 4 + TxWeight,
    ?assertEqual(ExpectedW1, W1).

%%% -------------------------------------------------------------------
%%% G30: Witness stack encoding — each witness item uses CompactSize length prefix
%%% Core: EncodeWitnessItem writes CompactSize(item_len) then raw bytes
%%% Roundtrip verify: witness items survive encode/decode intact
%%% -------------------------------------------------------------------

g30_witness_stack_encoding_roundtrip_test() ->
    %% A segwit v0 input with 2 witness items: fake sig (70B) + pubkey (33B)
    Sig = <<16#30, 16#44, 0:(68*8)>>,  %% 70-byte fake signature
    PubKey = <<16#02, 0:256>>,          %% 33-byte compressed pubkey
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<1:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#FFFFFFFE,
            witness = [Sig, PubKey]
        }],
        outputs = [#tx_out{value = 100000,
                           script_pubkey = <<16#00, 16#14, 0:160>>}],
        locktime = 0
    },
    Enc = beamchain_serialize:encode_transaction(Tx, witness),
    {Decoded, <<>>} = beamchain_serialize:decode_transaction(Enc),
    [In] = Decoded#transaction.inputs,
    ?assertEqual([Sig, PubKey], In#tx_in.witness).

g30_witness_stack_zero_items_encoding_test() ->
    %% Input with no witness: witness stack must be encoded as varint(0)
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<2:256>>, index = 1},
            script_sig = <<>>,
            sequence = 16#FFFFFFFF,
            witness = []
        }],
        outputs = [#tx_out{value = 50000, script_pubkey = <<0, 20, 0:160>>}],
        locktime = 0
    },
    %% no_witness encoding should not have marker bytes
    LegacyEnc = beamchain_serialize:encode_transaction(Tx, no_witness),
    ?assertNotMatch(<<_:32/little, 0:8, 1:8, _/binary>>, LegacyEnc).

g30_witness_large_item_encoding_test() ->
    %% Witness item larger than 252 bytes requires 3-byte CompactSize length prefix
    LargeItem = binary:copy(<<16#AB>>, 520),  %% MAX_SCRIPT_ELEMENT_SIZE bytes
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<3:256>>, index = 0},
            script_sig = <<>>,
            sequence = 16#FFFFFFFF,
            witness = [LargeItem]
        }],
        outputs = [#tx_out{value = 1, script_pubkey = <<0, 32, 0:256>>}],
        locktime = 0
    },
    Enc = beamchain_serialize:encode_transaction(Tx, witness),
    {Decoded, <<>>} = beamchain_serialize:decode_transaction(Enc),
    [In] = Decoded#transaction.inputs,
    ?assertEqual([LargeItem], In#tx_in.witness).
