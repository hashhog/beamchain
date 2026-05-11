-module(beamchain_blockfilter).

%%% -------------------------------------------------------------------
%%% BIP-158: Compact block filter construction (Golomb-coded set).
%%%
%%% This module implements the *basic* (filter type 0) block filter
%%% defined in BIP-158.  The filter is a probabilistic set of byte
%%% strings, encoded as a Golomb-Rice coded difference list of hashed
%%% values.  Querying the filter never reports a false negative; false
%%% positives occur with probability ~= 1/M per query (M = 784931 for
%%% the basic filter).
%%%
%%% Construction:
%%%   1. Collect every scriptPubKey from outputs in the block (skipping
%%%      empty scripts and OP_RETURN outputs) plus every scriptPubKey
%%%      spent by non-coinbase inputs (skipping empty scripts).
%%%   2. Deduplicate.
%%%   3. Hash each script with SipHash-2-4 keyed on the first 16 bytes
%%%      of the block hash (internal byte order, low half = k0,
%%%      high half = k1) and reduce into [0, N*M) using fast-range.
%%%   4. Sort, take consecutive deltas, Golomb-Rice encode with P=19.
%%%   5. Prefix with CompactSize(N).
%%%
%%% This matches Bitcoin Core's blockfilter.cpp byte-for-byte.  A
%%% per-block filter header chain links each filter to its predecessor
%%% via dSHA256(filter_hash || prev_filter_header).
%%%
%%% Reference:
%%%   bitcoin-core/src/blockfilter.{h,cpp}
%%%   bitcoin-core/src/util/golombrice.h
%%%   https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
%%% -------------------------------------------------------------------

-include("beamchain.hrl").

%% Filter construction
-export([build_basic_filter/1, build_basic_filter/2,
         build_basic_filter_from_elements/2,
         basic_filter_elements/2]).

%% Filter header chain
-export([filter_hash/1, compute_header/2, genesis_prev_header/0]).

%% GCS primitives (exported for testing and reuse)
-export([gcs_encode/4, gcs_match/4, gcs_match_any/4,
         gcs_match/6, gcs_match_any/6,
         hash_to_range/3, siphash_key_from_block_hash/1]).

%% P2P "cfilter" payload serialization (BIP-157)
-export([encode_cfilter/3, decode_cfilter/1]).

%% Filter type constants
-export([basic_filter_type/0]).

%%% -------------------------------------------------------------------
%%% Constants
%%% -------------------------------------------------------------------

%% Filter type 0 = basic
-define(BASIC_FILTER_TYPE, 0).
%% BIP-158 basic filter parameters
-define(BASIC_P, 19).
-define(BASIC_M, 784931).
-define(OP_RETURN, 16#6A).

basic_filter_type() -> ?BASIC_FILTER_TYPE.

%% Genesis prev_filter_header is 32 zero bytes by BIP-157 convention.
genesis_prev_header() -> <<0:256>>.

%%% -------------------------------------------------------------------
%%% Public API
%%% -------------------------------------------------------------------

%% @doc Build a BIP-158 basic block filter from a block, fetching any
%% spent prevout scripts from the on-disk undo data keyed by the block
%% hash.  Returns the encoded filter bytes (the cfilter payload sans
%% the filter_type/block_hash/varint-length wrapper).
-spec build_basic_filter(#block{}) -> binary().
build_basic_filter(Block) ->
    PrevScripts = lookup_prev_scripts(Block),
    build_basic_filter(Block, PrevScripts).

%% @doc Build a BIP-158 basic block filter from a block, given the
%% list of scriptPubKeys for every prevout spent by the block's
%% non-coinbase inputs (in input order across all transactions).  This
%% form is used during block-connect when the undo data has not yet
%% been written, and is the entry point matched by the Core test
%% vectors which embed the prev scripts inline.
-spec build_basic_filter(#block{}, [binary()]) -> binary().
build_basic_filter(#block{} = Block, PrevScripts) when is_list(PrevScripts) ->
    BlockHash = block_hash_internal(Block),
    Elements = basic_filter_elements(Block, PrevScripts),
    build_basic_filter_from_elements(BlockHash, Elements).

%% @doc Build a BIP-158 basic block filter directly from the block
%% hash (internal byte order) and the de-duplicated element set.
-spec build_basic_filter_from_elements(binary(), [binary()]) -> binary().
build_basic_filter_from_elements(BlockHash, Elements)
  when byte_size(BlockHash) =:= 32, is_list(Elements) ->
    {K0, K1} = siphash_key_from_block_hash(BlockHash),
    %% Deduplicate while preserving the BIP-158 set semantics.
    Unique = lists:usort(Elements),
    gcs_encode(Unique, K0, K1, {?BASIC_P, ?BASIC_M}).

%% @doc Collect the BIP-158 element set for the basic filter.
%% Includes every non-empty, non-OP_RETURN output scriptPubKey and
%% every non-empty prevout scriptPubKey spent by non-coinbase inputs.
-spec basic_filter_elements(#block{}, [binary()]) -> [binary()].
basic_filter_elements(#block{transactions = Txs}, PrevScripts) ->
    Outs = collect_output_scripts(Txs, []),
    Ins  = filter_non_empty_scripts(PrevScripts),
    Outs ++ Ins.

%% @doc dSHA256 of the encoded filter bytes — the value used as the
%% leaf in the cfheaders chain.
-spec filter_hash(binary()) -> binary().
filter_hash(FilterBytes) ->
    beamchain_serialize:hash256(FilterBytes).

%% @doc Compute the cfheader for a filter given the previous header.
%%   header = dSHA256(filter_hash || prev_header)
-spec compute_header(binary(), binary()) -> binary().
compute_header(FilterBytes, PrevHeader)
  when byte_size(PrevHeader) =:= 32 ->
    FH = filter_hash(FilterBytes),
    beamchain_serialize:hash256(<<FH/binary, PrevHeader/binary>>).

%%% -------------------------------------------------------------------
%%% GCS encoding / matching
%%% -------------------------------------------------------------------

%% @doc Encode a list of byte-string elements as a BIP-158 GCS filter.
%% Returns: varint(N) || golomb-rice bitstream.
-spec gcs_encode([binary()], non_neg_integer(), non_neg_integer(),
                 {non_neg_integer(), non_neg_integer()}) -> binary().
gcs_encode([], _K0, _K1, _Params) ->
    %% Empty filter: just CompactSize(0) — matches Core's GCSFilter().
    beamchain_serialize:encode_varint(0);
gcs_encode(Elements, K0, K1, {P, M}) ->
    N = length(Elements),
    F = N * M,
    Hashed = lists:sort([hash_to_range(E, F, {K0, K1}) || E <- Elements]),
    {_, Deltas} = lists:foldl(
        fun(V, {Prev, Acc}) -> {V, [V - Prev | Acc]} end,
        {0, []},
        Hashed),
    BitStream = golomb_rice_encode(lists:reverse(Deltas), P),
    NPrefix = beamchain_serialize:encode_varint(N),
    <<NPrefix/binary, BitStream/binary>>.

%% @doc Match a single target byte-string against an encoded basic filter.
%% Uses BASIC_P=19 and BASIC_M=784931.
-spec gcs_match(binary(), binary(), non_neg_integer(),
                non_neg_integer()) -> boolean().
gcs_match(FilterBytes, Target, K0, K1) ->
    gcs_match(FilterBytes, Target, K0, K1, ?BASIC_P, ?BASIC_M).

%% @doc Match a single target against a filter with explicit P and M.
-spec gcs_match(binary(), binary(), non_neg_integer(), non_neg_integer(),
                non_neg_integer(), non_neg_integer()) -> boolean().
gcs_match(FilterBytes, Target, K0, K1, P, M) ->
    gcs_match_any(FilterBytes, [Target], K0, K1, P, M).

%% @doc Match any of a target list against an encoded basic filter.
%% Uses BASIC_P=19 and BASIC_M=784931.
-spec gcs_match_any(binary(), [binary()], non_neg_integer(),
                    non_neg_integer()) -> boolean().
gcs_match_any(FilterBytes, Targets, K0, K1) ->
    gcs_match_any(FilterBytes, Targets, K0, K1, ?BASIC_P, ?BASIC_M).

%% @doc Match any target against a filter with explicit P and M.  The
%% probabilistic membership test: returns true if any target is in
%% the set (or matches a false-positive collision).
%% BUG-1 fix: P and M are now explicit parameters instead of hardcoding
%% ?BASIC_P and ?BASIC_M, which silently broke matching for non-basic
%% filters.  Core's GCSFilter::MatchInternal uses m_params.m_P and
%% m_F = m_N * m_params.m_M.
-spec gcs_match_any(binary(), [binary()], non_neg_integer(), non_neg_integer(),
                    non_neg_integer(), non_neg_integer()) -> boolean().
gcs_match_any(FilterBytes, Targets, K0, K1, P, M) ->
    {N, Stream} = beamchain_serialize:decode_varint(FilterBytes),
    case N of
        0 -> false;
        _ ->
            F = N * M,
            TargetHashes = lists:usort(
                [hash_to_range(T, F, {K0, K1}) || T <- Targets]),
            decode_and_match(Stream, N, P, TargetHashes)
    end.

%%% -------------------------------------------------------------------
%%% P2P payload serialization for BIP-157 cfilter
%%% -------------------------------------------------------------------

%% @doc Serialize a cfilter P2P message payload.
%%   filter_type:1 || block_hash:32 || varint(len) || filter_bytes
-spec encode_cfilter(non_neg_integer(), binary(), binary()) -> binary().
encode_cfilter(FilterType, BlockHash, FilterBytes)
  when byte_size(BlockHash) =:= 32 ->
    LenPrefix = beamchain_serialize:encode_varint(byte_size(FilterBytes)),
    <<FilterType:8, BlockHash/binary,
      LenPrefix/binary, FilterBytes/binary>>.

-spec decode_cfilter(binary()) -> {ok, {non_neg_integer(), binary(), binary()}}
                                  | {error, atom()}.
decode_cfilter(<<FT:8, BH:32/binary, Rest/binary>>) ->
    case beamchain_serialize:decode_varint(Rest) of
        {Len, Body} when byte_size(Body) >= Len ->
            <<FB:Len/binary, _/binary>> = Body,
            {ok, {FT, BH, FB}};
        _ ->
            {error, truncated}
    end;
decode_cfilter(_) ->
    {error, invalid}.

%%% -------------------------------------------------------------------
%%% SipHash key derivation (BIP-158 §"SipHash key")
%%% -------------------------------------------------------------------

%% Internal-byte-order block hash → (k0, k1) for SipHash-2-4.
%% Per Core: m_block_hash.GetUint64(0) and GetUint64(1) reading the
%% raw uint256 storage as little-endian uint64s.
-spec siphash_key_from_block_hash(binary()) ->
    {non_neg_integer(), non_neg_integer()}.
siphash_key_from_block_hash(<<K0:64/little, K1:64/little, _/binary>>) ->
    {K0, K1}.

%%% -------------------------------------------------------------------
%%% Hash-to-range (BIP-158 §"hash to range" — 64-bit fast-range)
%%% -------------------------------------------------------------------

-spec hash_to_range(binary(), non_neg_integer(),
                    {non_neg_integer(), non_neg_integer()}) ->
    non_neg_integer().
hash_to_range(Element, F, {K0, K1}) ->
    H = beamchain_crypto:siphash(K0, K1, Element),
    %% Core's FastRange64: (h * F) >> 64
    (H * F) bsr 64.

%%% -------------------------------------------------------------------
%%% Internal: element collection
%%% -------------------------------------------------------------------

collect_output_scripts([], Acc) ->
    lists:reverse(Acc);
collect_output_scripts([#transaction{outputs = Outs} | Rest], Acc) ->
    Acc2 = lists:foldl(fun output_to_element/2, Acc, Outs),
    collect_output_scripts(Rest, Acc2).

output_to_element(#tx_out{script_pubkey = SPK}, Acc) ->
    case SPK of
        <<>> -> Acc;
        <<?OP_RETURN, _/binary>> -> Acc;
        _ -> [SPK | Acc]
    end.

filter_non_empty_scripts(Scripts) ->
    [S || S <- Scripts, S =/= <<>>].

%% Look up scriptPubKeys for spent prevouts via the on-disk undo data.
%% Returns [] if no undo data is recorded yet (e.g. filter built before
%% block-connect).  In normal operation this is invoked from the
%% blockfilter index after block_connect has stored the undo blob.
lookup_prev_scripts(#block{} = Block) ->
    Hash = block_hash_internal(Block),
    case beamchain_db:get_undo(Hash) of
        {ok, UndoBin} ->
            try beamchain_validation:decode_undo_data(UndoBin) of
                Pairs when is_list(Pairs) ->
                    [Coin#utxo.script_pubkey || {_OP, Coin} <- Pairs]
            catch
                _:_ -> []
            end;
        _ ->
            []
    end.

%% Internal-byte-order block hash, computing it lazily if the record
%% does not have it cached.
block_hash_internal(#block{hash = H}) when byte_size(H) =:= 32 -> H;
block_hash_internal(#block{header = Header}) ->
    beamchain_serialize:block_hash(Header).

%%% -------------------------------------------------------------------
%%% Golomb-Rice coding
%%%
%%% A delta is encoded as:
%%%   q = delta >> P  (quotient — unary: q ones followed by a zero)
%%%   r = delta & ((1 << P) - 1)  (remainder — written big-endian in P bits)
%%% Bits are packed MSB-first within each byte.  The terminal byte is
%%% padded with zero bits to the next byte boundary.
%%% -------------------------------------------------------------------

golomb_rice_encode(Deltas, P) ->
    Mask = (1 bsl P) - 1,
    {Acc, NBits, Buf} = lists:foldl(
        fun(Delta, {Bits, NBits0, Buf0}) ->
            Q = Delta bsr P,
            R = Delta band Mask,
            {Bits1, NBits1, Buf1} = write_unary(Q, Bits, NBits0, Buf0),
            %% terminating zero of the unary code
            {Bits2, NBits2, Buf2} =
                bitwriter_push_bit(0, Bits1, NBits1, Buf1),
            bitwriter_push_bits(R, P, Bits2, NBits2, Buf2)
        end, {0, 0, <<>>}, Deltas),
    bitwriter_flush(Acc, NBits, Buf).

write_unary(0, Bits, NBits, Buf) ->
    {Bits, NBits, Buf};
write_unary(Q, Bits, NBits, Buf) when Q > 0 ->
    %% q ones — push 1-bits one at a time (BIP-158 length is ~10 on
    %% average for P=19; not a hot loop).
    {B1, N1, Buf1} = bitwriter_push_bit(1, Bits, NBits, Buf),
    write_unary(Q - 1, B1, N1, Buf1).

bitwriter_push_bit(Bit, Acc, NBits, Buf) ->
    Acc1 = (Acc bsl 1) bor (Bit band 1),
    NBits1 = NBits + 1,
    case NBits1 of
        8 ->
            {0, 0, <<Buf/binary, Acc1:8>>};
        _ ->
            {Acc1, NBits1, Buf}
    end.

bitwriter_push_bits(_Value, 0, Acc, NBits, Buf) ->
    {Acc, NBits, Buf};
bitwriter_push_bits(Value, NLeft, Acc, NBits, Buf) ->
    %% MSB-first: write bit at position (NLeft - 1).
    Bit = (Value bsr (NLeft - 1)) band 1,
    {A1, N1, B1} = bitwriter_push_bit(Bit, Acc, NBits, Buf),
    bitwriter_push_bits(Value, NLeft - 1, A1, N1, B1).

bitwriter_flush(_Acc, 0, Buf) ->
    Buf;
bitwriter_flush(Acc, NBits, Buf) when NBits > 0 ->
    %% pad remaining low bits with zero
    Final = Acc bsl (8 - NBits),
    <<Buf/binary, Final:8>>.

%%% -------------------------------------------------------------------
%%% GCS decoding (matching path)
%%% -------------------------------------------------------------------

decode_and_match(_Stream, 0, _P, _Targets) ->
    false;
decode_and_match(_Stream, _N, _P, []) ->
    false;
decode_and_match(Stream, N, P, Targets) ->
    decode_and_match_loop(make_bitreader(Stream), N, P, 0, Targets).

decode_and_match_loop(_R, 0, _P, _Val, _Targets) ->
    false;
decode_and_match_loop(R, N, P, Val, Targets) ->
    {Delta, R2} = read_delta(R, P),
    Val1 = Val + Delta,
    case advance_targets(Val1, Targets) of
        match -> true;
        Targets1 ->
            decode_and_match_loop(R2, N - 1, P, Val1, Targets1)
    end.

advance_targets(_Val, []) -> [];
advance_targets(Val, [T | _] = Ts) when T > Val -> Ts;
advance_targets(Val, [Val | _]) -> match;
advance_targets(Val, [_ | Rest]) -> advance_targets(Val, Rest).

read_delta(R0, P) ->
    {Q, R1} = read_unary(R0, 0),
    {Rem, R2} = read_bits_be(R1, P, 0),
    {(Q bsl P) + Rem, R2}.

read_unary(R0, Q) ->
    case read_bit(R0) of
        {1, R1} -> read_unary(R1, Q + 1);
        {0, R1} -> {Q, R1}
    end.

read_bits_be(R, 0, Acc) -> {Acc, R};
read_bits_be(R0, N, Acc) ->
    {Bit, R1} = read_bit(R0),
    read_bits_be(R1, N - 1, (Acc bsl 1) bor Bit).

%% Simple bitreader implemented as a tuple {Binary, BitsConsumedInHead}.
make_bitreader(Bin) -> {Bin, 0}.

read_bit({<<>>, _}) ->
    erlang:error(gcs_underrun);
read_bit({<<Byte:8, Rest/binary>>, Pos}) ->
    Bit = (Byte bsr (7 - Pos)) band 1,
    case Pos + 1 of
        8 -> {Bit, {Rest, 0}};
        Pos1 -> {Bit, {<<Byte:8, Rest/binary>>, Pos1}}
    end.
