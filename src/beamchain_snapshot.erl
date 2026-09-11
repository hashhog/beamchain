-module(beamchain_snapshot).

%% Bitcoin Core-compatible UTXO snapshot loading, verification and dumping.
%%
%% File format (matches bitcoin-core/src/node/utxo_snapshot.h SnapshotMetadata
%% + the per-coin loop in rpc/blockchain.cpp WriteUTXOSnapshot):
%%
%%   Metadata header (FIXED 51 bytes):
%%     magic       : 5 bytes  "utxo" + 0xff
%%     version     : uint16 LE      (currently 2)
%%     net magic   : 4 bytes        (pchMessageStart, raw bytes)
%%     base hash   : 32 bytes       (uint256, internal byte order)
%%     coins count : uint64 LE      (8 bytes — NOT a CompactSize)
%%
%%   Per-tx group (repeated until coins_count UTXOs have been read):
%%     txid           : 32 bytes (uint256, internal byte order)
%%     coins_per_tx   : CompactSize
%%     For each coin:
%%       vout         : CompactSize
%%       coin         : VARINT(code) ++ TxOutCompression(out)
%%         code       = (height << 1) | fCoinBase   (VARINT, default mode)
%%         value      = VARINT(CompressAmount(nValue))
%%         scriptPubKey =
%%           ScriptCompression: if it matches one of the 6 special forms
%%             (P2PKH, P2SH, P2PK-compressed-02/03, P2PK-uncompressed-04/05),
%%             write the compressed form (a 21- or 33-byte blob whose first
%%             byte is the special-script type 0x00..0x05).
%%           Otherwise: VARINT(size + nSpecialScripts) ++ raw bytes,
%%             where nSpecialScripts = 6.
%%
%% NOTE: VARINT here is Bitcoin Core's variable-length integer (serialize.h
%% WriteVarInt/ReadVarInt), NOT CompactSize. They are different encodings.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([load_snapshot/1, load_snapshot_validated/3, verify_snapshot/2]).
-export([compute_utxo_hash/0, serialize_snapshot/2]).
-export([read_metadata/1]).
-export([compute_utxo_hash_from_list/1]).
%% Streaming load / HASH_SERIALIZED. Production import-utxo and
%% gettxoutsetinfo MUST use these: they never materialise the coin set.
%% compute_utxo_hash_from_list/1 is the in-memory helper for tests and
%% small fixtures, not the 188M-coin production hasher.
-export([fold_snapshot_groups/3, fold_snapshot_groups_validated/5]).
-export([fold_utxo_txid_groups/2, compute_utxo_hash_stream/0]).
-export([compute_utxo_stats/1, verify_hash_serialized/3]).
%% MuHash3072 helpers — used by `gettxoutsetinfo hash_type=muhash` (NOT by
%% the loadtxoutset strict-content-hash check, which is HASH_SERIALIZED /
%% SHA256d per validation.cpp:5910-5914 + kernel/coinstats.cpp:161).
-export([compute_txoutset_muhash_from_list/1, txoutset_muhash_apply/3]).

%% Backwards-compatible alias kept so any straggler caller still links. The
%% function it routes to is the canonical SHA256d-via-HashWriter commitment
%% used by Core's HASH_SERIALIZED — i.e. the right hash for the strict
%% loadtxoutset gate. Not deprecated.
-export([compute_utxo_hash_from_list_legacy/1]).

%% Internal helpers exported for unit tests.
-export([encode_compact_size/1, decode_compact_size/1,
         encode_varint/1, decode_varint/1,
         compress_amount/1, decompress_amount/1,
         compress_script/1, decompress_script/2,
         serialize_coin/1, parse_coin/1,
         serialize_metadata/3, parse_metadata/1,
         metadata_size/0,
         tx_out_ser/3]).

%% Dialyzer suppressions for false positives:
%% group_consecutive/2: dialyzer infers the list arg is always [] because it
%% tracks only the base-case input at one call site; the non-empty clauses are
%% the functional heart of the grouping algorithm.
-dialyzer({nowarn_function, group_consecutive/2}).

%% Snapshot magic bytes
-define(SNAPSHOT_MAGIC, <<"utxo", 16#ff>>).
-define(SNAPSHOT_VERSION, 2).
-define(METADATA_SIZE, 51).
-define(N_SPECIAL_SCRIPTS, 6).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Load a UTXO snapshot from file path.
%% Returns {ok, #{base_hash, num_coins, coins}} or {error, Reason}.
%%
%% This accumulates the coin list. It is the small-fixture / test helper.
%% Production import-utxo MUST use fold_snapshot_groups_validated/5 so the
%% full 188M-coin set is never resident. The file is streamed (raw fd);
%% file:read_file/1 of the whole dump is the 8G HIT_CAP anti-pattern.
-spec load_snapshot(string()) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           coins => [{binary(), non_neg_integer(), #utxo{}}]}} |
    {error, term()}.
load_snapshot(Path) ->
    case fold_snapshot_groups(Path, fun acc_group_coins/3, []) of
        {ok, Meta, Acc} ->
            {ok, Meta#{coins => lists:reverse(Acc)}};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Load a UTXO snapshot with per-coin validation gates (G2-G5).
%% ExpectedMagic is the running network's pchMessageStart (G1).
%% BaseHeight is the snapshot base block height for the per-coin height check (G2).
%%
%% Same memory caveat as load_snapshot/1: the returned `coins` list is for
%% tests. Production walks fold_snapshot_groups_validated/5 and discards
%% each txid group after write/flush.
-spec load_snapshot_validated(string(), binary(), non_neg_integer()) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           network_magic => binary(),
           coins => [{binary(), non_neg_integer(), #utxo{}}]}} |
    {error, term()}.
load_snapshot_validated(Path, ExpectedMagic, BaseHeight) ->
    case fold_snapshot_groups_validated(Path, ExpectedMagic, BaseHeight,
                                        fun acc_group_coins/3, []) of
        {ok, Meta, Acc} ->
            {ok, Meta#{coins => lists:reverse(Acc)}};
        {error, Reason} ->
            {error, Reason}
    end.

%% Fold callback for the accumulating load_* helpers: prepend each coin
%% so a final lists:reverse/1 restores file order. Not used on the
%% production import path.
acc_group_coins(Txid, Coins, Acc) ->
    lists:foldl(fun({Vout, Utxo}, A) -> [{Txid, Vout, Utxo} | A] end,
                Acc, Coins).

%% @doc Read only the metadata from a snapshot file.
%% Returns {ok, #{base_hash, num_coins, network_magic}} or {error, Reason}.
-spec read_metadata(string()) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           network_magic => binary()}} |
    {error, term()}.
read_metadata(Path) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, Fd} ->
            Result = read_metadata_from_fd(Fd),
            file:close(Fd),
            Result;
        {error, Reason} ->
            {error, {file_open_failed, Reason}}
    end.

%% @doc Verify a loaded snapshot against expected parameters.
%% Mirrors bitcoin-core/src/validation.cpp:5901-5914 where Core calls
%%   ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, ...)
%% and compares the resulting `hashSerialized` to
%% `au_data.hash_serialized` (kernel/coinstats.cpp:161 selects a
%% `HashWriter` for the HASH_SERIALIZED branch — that's a SHA256d over
%% the streamed `TxOutSer` bytes, NOT MuHash3072).
%%
%% The chainparams `m_assumeutxo_data.hash_serialized` values shipped in
%% beamchain_chain_params (840k=a2a5521b..., 880k, 910k, 935k mainnet;
%% 90k, 120k testnet4) are byte-for-byte the Core values, which means
%% they are SHA256d-via-HashWriter digests. The comparator MUST use
%% SHA256d-via-HashWriter — NOT MuHash3072 (that one drives the
%% `gettxoutsetinfo hash_type=muhash` path; see
%% compute_txoutset_muhash_from_list/1).
%%
%% On mismatch we emit the verbatim Core wording from validation.cpp:5913
%% ("Bad snapshot content hash: expected <expected>, got <actual>") with the
%% hex strings rendered in display order (reverse of internal byte order),
%% matching uint256::ToString.
-spec verify_snapshot(map(), atom()) -> ok | {error, term()}.
verify_snapshot(#{base_hash := BaseHash, coins := Coins} = _Snapshot, Network) ->
    %% In-memory path for tests / small fixtures. Production import hashes
    %% the coins just written via compute_utxo_hash_stream/0 (one txid
    %% group at a time) and calls verify_hash_serialized/3 directly.
    ComputedHash = compute_utxo_hash_from_list(Coins),
    verify_hash_serialized(BaseHash, ComputedHash, Network).

%% @doc Compare a HASH_SERIALIZED digest to the assumeutxo whitelist.
%% ComputedHash is the 32-byte uint256 in INTERNAL byte order, the same
%% layout as `m_assumeutxo_data.hash_serialized`.
-spec verify_hash_serialized(binary(), binary(), atom()) -> ok | {error, term()}.
verify_hash_serialized(BaseHash, ComputedHash, Network)
        when byte_size(BaseHash) =:= 32, byte_size(ComputedHash) =:= 32 ->
    case beamchain_chain_params:get_assumeutxo_by_hash(BaseHash, Network) of
        {ok, _Height, #{utxo_hash := ExpectedUtxoHash}} ->
            case ComputedHash =:= ExpectedUtxoHash of
                true -> ok;
                false ->
                    Msg = format_bad_content_hash(ExpectedUtxoHash, ComputedHash),
                    {error, Msg}
            end;
        not_found ->
            %% HASHHOG_UNSAFE_SNAPSHOT_HEIGHT: development-only escape from
            %% the chainparams assumeutxo whitelist. loadtxoutset is a trust
            %% shortcut for end users, which is why Core hardcodes the
            %% anchors; with no anchor there is no hash_serialized to compare
            %% against, so the strict-content-hash gate cannot run and the
            %% snapshot is taken on faith. This project needs to validate
            %% arbitrary block ranges in parallel from a locally generated
            %% snapshot ladder, where correctness comes from checking each
            %% range's OUTPUT utxo hash against an independent commitment,
            %% not from trusting the input snapshot. Unset (the default, and
            %% what ships) keeps production trust semantics intact.
            case beamchain_chain_params:unsafe_snapshot_height() of
                {ok, UnsafeHeight} ->
                    beamchain_chain_params:warn_unsafe_snapshot(
                      "beamchain_snapshot:verify_hash_serialized/3 "
                      "(strict-content-hash gate)", UnsafeHeight, BaseHash),
                    ok;
                undefined ->
                    {error, {unknown_snapshot_base, BaseHash}}
            end
    end.

%% @doc Format the verbatim Core "Bad snapshot content hash" refusal string.
%% Display hex is the reverse of internal byte order (uint256::ToString).
-spec format_bad_content_hash(binary(), binary()) -> binary().
format_bad_content_hash(Expected, Got)
        when byte_size(Expected) =:= 32, byte_size(Got) =:= 32 ->
    ExpectedHex = bin_to_display_hex(Expected),
    GotHex = bin_to_display_hex(Got),
    iolist_to_binary(
      io_lib:format("Bad snapshot content hash: expected ~s, got ~s",
                    [ExpectedHex, GotHex])).

bin_to_display_hex(Bin) when is_binary(Bin) ->
    Reversed = list_to_binary(lists:reverse(binary_to_list(Bin))),
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B:8>> <= Reversed]).

%% @doc Compute the UTXO-set commitment from the current chainstate.
%% This is the HASH_SERIALIZED commitment — SHA256d via HashWriter over
%% Core's `TxOutSer` per-coin layout (kernel/coinstats.cpp:46-51 +
%% kernel/coinstats.cpp:161). Same commitment that
%% `m_assumeutxo_data.hash_serialized` checks against in
%% loadtxoutset's strict-content-hash gate (validation.cpp:5901-5914,
%% mirrored in verify_snapshot/2).
%%
%% For the MuHash3072 commitment exposed by `gettxoutsetinfo
%% hash_type=muhash`, see compute_txoutset_muhash_from_list/1 — that's a
%% separate Core code path and a different digest.
-spec compute_utxo_hash() -> binary().
compute_utxo_hash() ->
    %% STREAMING-HASH: flush dirty cache so the CF is authoritative, then
    %% walk one txid group at a time. Must not collect_all_utxos/0 into a
    %% list — that is the 8G HIT_CAP on a 188M-coin set.
    beamchain_chainstate:flush(),
    compute_utxo_hash_stream().

%%% ===================================================================
%%% MuHash3072 over the UTXO set (gettxoutsetinfo "muhash" mode)
%%%
%%% Mirrors bitcoin-core/src/kernel/coinstats.cpp ApplyCoinHash + TxOutSer.
%%% Each UTXO is serialised as:
%%%   COutPoint     := txid (32 bytes, internal byte order) || vout (uint32 LE)
%%%   uint32 LE     := (height << 1) | fCoinBase
%%%   CTxOut        := nValue (int64 LE) || CompactSize(scriptPubKey size) ||
%%%                    scriptPubKey raw bytes
%%% That blob is fed to MuHash3072::Insert (or Remove for spends). Order
%%% does not matter — MuHash3072 is a commutative incremental accumulator
%%% (see beamchain_muhash module header for the algebra).
%%%
%%% This is the "muhash" hash_type for `gettxoutsetinfo`, NOT the
%%% HASH_SERIALIZED used by assumeutxo loadtxoutset (validation.cpp:5912).
%%% Those two are independent UTXO-set commitments; we maintain the
%%% MuHash one online so we can answer the muhash RPC without a full scan.
%%% ===================================================================

%% @doc Serialise a single UTXO to its TxOutSer wire bytes.
%% Used as the input to MuHash3072::Insert / Remove.
-spec tx_out_ser(binary(), non_neg_integer(), #utxo{}) -> binary().
tx_out_ser(Txid, Vout,
           #utxo{value = Value, script_pubkey = Script,
                 is_coinbase = IsCoinbase, height = Height})
        when byte_size(Txid) =:= 32,
             is_integer(Vout), Vout >= 0,
             is_integer(Value), Value >= 0,
             is_binary(Script),
             is_integer(Height), Height >= 0 ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    Code = (Height bsl 1) bor CoinbaseFlag,
    ScriptLen = encode_compact_size(byte_size(Script)),
    <<Txid:32/binary,
      Vout:32/little,
      Code:32/little,
      Value:64/little,
      ScriptLen/binary,
      Script/binary>>.

%% @doc Apply one UTXO to a MuHash3072 accumulator.
%% Op is `add` for spent->unspent (creation) or `remove` for unspent->spent.
%% Returns the updated accumulator.
-spec txoutset_muhash_apply(add | remove,
                            {binary(), non_neg_integer(), #utxo{}},
                            beamchain_muhash:muhash()) ->
    beamchain_muhash:muhash().
txoutset_muhash_apply(Op, {Txid, Vout, Utxo}, Acc) ->
    Bytes = tx_out_ser(Txid, Vout, Utxo),
    case Op of
        add    -> beamchain_muhash:add(Bytes, Acc);
        remove -> beamchain_muhash:remove(Bytes, Acc)
    end.

%% @doc Compute MuHash3072 finalize digest over a list of UTXOs.
%% Order-independent. Returns the 32-byte SHA256 of the collapsed
%% accumulator value, byte-for-byte equivalent to Bitcoin Core's
%% `gettxoutsetinfo muhash` -> .muhash (raw uint256 in internal byte
%% order; reverse for display hex).
-spec compute_txoutset_muhash_from_list([{binary(), non_neg_integer(),
                                          #utxo{}}]) ->
    binary().
compute_txoutset_muhash_from_list(Coins) when is_list(Coins) ->
    Acc = lists:foldl(
        fun(Coin, A) -> txoutset_muhash_apply(add, Coin, A) end,
        beamchain_muhash:new(),
        Coins),
    beamchain_muhash:finalize(Acc).

%% @doc Serialize current UTXO set to snapshot format.
%% Returns binary snapshot data in Bitcoin Core's exact byte format.
-spec serialize_snapshot(binary(), atom()) -> binary().
serialize_snapshot(BaseBlockHash, Network) ->
    Params = beamchain_chain_params:params(Network),
    #{magic := NetworkMagic} = Params,

    %% Collect all UTXOs grouped by txid (lexicographic order on txid)
    Coins = collect_all_utxos(),
    GroupedCoins = group_coins_by_txid(Coins),
    NumCoins = length(Coins),

    %% Header (51 bytes, fixed)
    Header = serialize_metadata(NetworkMagic, BaseBlockHash, NumCoins),

    %% Per-tx coin groups (no separate top-level coins-count — that lives
    %% in the header)
    CoinsBin = serialize_grouped_coins(GroupedCoins),

    <<Header/binary, CoinsBin/binary>>.

%% @doc Return the fixed metadata-header size in bytes (51).
-spec metadata_size() -> non_neg_integer().
metadata_size() ->
    ?METADATA_SIZE.

%% @doc Build the 51-byte metadata header.
-spec serialize_metadata(binary(), binary(), non_neg_integer()) -> binary().
serialize_metadata(NetworkMagic, BaseBlockHash, NumCoins)
        when byte_size(NetworkMagic) =:= 4,
             byte_size(BaseBlockHash) =:= 32,
             is_integer(NumCoins), NumCoins >= 0 ->
    <<?SNAPSHOT_MAGIC/binary,
      ?SNAPSHOT_VERSION:16/little,
      NetworkMagic/binary,
      BaseBlockHash:32/binary,
      NumCoins:64/little>>.

%% @doc Parse the 51-byte metadata header. Returns {ok, Map, Rest} or
%% {error, Reason}.
parse_metadata(<<Magic:5/binary, Version:16/little,
                 NetworkMagic:4/binary, BaseHash:32/binary,
                 NumCoins:64/little, Rest/binary>>)
        when Magic =:= ?SNAPSHOT_MAGIC ->
    case Version of
        ?SNAPSHOT_VERSION ->
            {ok, #{base_hash => BaseHash,
                   num_coins => NumCoins,
                   network_magic => NetworkMagic}, Rest};
        _ ->
            {error, {unsupported_version, Version}}
    end;
parse_metadata(<<Magic:5/binary, _/binary>>) when Magic =/= ?SNAPSHOT_MAGIC ->
    {error, invalid_magic};
parse_metadata(_) ->
    {error, truncated_header}.

%%% ===================================================================
%%% Streaming snapshot fold (raw fd, one txid group at a time)
%%%
%%% Mirrors bitcoin-core/src/validation.cpp PopulateAndValidateSnapshot
%%% (the per-txid loop at L5797-5863) and rpc/blockchain.cpp
%%% WriteUTXOSnapshot (txid group = 32-byte txid + CompactSize count +
%%% count * (CompactSize vout + Coin)).
%%%
%%% The previous load path did file:read_file/1 of the entire Core
%%% dumptxoutset (9.9 GB at soak-875000) into one binary, then parsed
%%% 188M `{txid,vout,#utxo{}}` tuples. That cannot fit in 8G (HIT_CAP,
%%% curl_rc=143). This walk holds one txid's coins plus a bounded read
%%% buffer; the callback writes/flushes that group and discards it.
%%% ===================================================================

%% 4 MiB read-ahead, same cadence as haskoin's streamSnapshotIntoLegacyUTXO.
-define(SNAP_READ_CHUNK, 4 * 1024 * 1024).
%% CompactSize MAX_SIZE plus one chunk of slack: a malicious script length
%% must not grow the buffer without bound.
-define(SNAP_MAX_BUF, 16#02000000 + ?SNAP_READ_CHUNK).

-record(snap_rdr, {
    fd  :: file:fd(),
    buf = <<>> :: binary()
}).

%% G3 guard: vout must be < UINT32_MAX (Core validation.cpp:5815).
-define(MAX_VOUT, 16#fffffffe).   %% = UINT32_MAX - 1; largest valid vout index

%% @doc Stream a snapshot file, invoking Fun once per txid group.
%% Fun(Txid, [{Vout, #utxo{}}], Acc) -> Acc.
%% Groups are in file order; vouts inside a group are file order (Core
%% WriteUTXOSnapshot cursor order). The HASH_SERIALIZED hasher sorts
%% vouts numerically per group (std::map<uint32_t, Coin>).
-spec fold_snapshot_groups(string(),
                           fun((binary(), [{non_neg_integer(), #utxo{}}], Acc)
                               -> Acc),
                           Acc) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           network_magic => binary()}, Acc} |
    {error, term()}.
fold_snapshot_groups(Path, Fun, Acc0) when is_function(Fun, 3) ->
    fold_snapshot(Path, Fun, Acc0, undefined, undefined).

%% @doc Like fold_snapshot_groups/3 plus G1-G5 (network magic, per-coin
%% height/vout/MoneyRange, leftover bytes). This is the production
%% import-utxo walker.
-spec fold_snapshot_groups_validated(string(), binary(), non_neg_integer(),
                                     fun((binary(), [{non_neg_integer(), #utxo{}}], Acc)
                                         -> Acc),
                                     Acc) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           network_magic => binary()}, Acc} |
    {error, term()}.
fold_snapshot_groups_validated(Path, ExpectedMagic, BaseHeight, Fun, Acc0)
        when byte_size(ExpectedMagic) =:= 4,
             is_integer(BaseHeight), BaseHeight >= 0,
             is_function(Fun, 3) ->
    fold_snapshot(Path, Fun, Acc0, ExpectedMagic, BaseHeight).

fold_snapshot(Path, Fun, Acc0, ExpectedMagic, BaseHeight) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, Fd} ->
            try
                fold_snapshot_fd(#snap_rdr{fd = Fd}, Fun, Acc0,
                                 ExpectedMagic, BaseHeight)
            after
                _ = file:close(Fd)
            end;
        {error, Reason} ->
            {error, {file_open_failed, Reason}}
    end.

fold_snapshot_fd(R0, Fun, Acc0, ExpectedMagic, BaseHeight) ->
    case read_exact(R0, ?METADATA_SIZE) of
        {ok, Header, R1} ->
            case parse_metadata(Header) of
                {ok, #{base_hash := BaseHash, num_coins := NumCoins,
                       network_magic := FileMagic} = Meta, <<>>} ->
                    case ExpectedMagic =:= undefined orelse
                         FileMagic =:= ExpectedMagic of
                        false ->
                            {error, {wrong_network_magic, FileMagic}};
                        true ->
                            case fold_groups(R1, NumCoins, Fun, Acc0,
                                             BaseHeight) of
                                {ok, Acc, R2} ->
                                    case leftover_check(R2, ExpectedMagic) of
                                        ok ->
                                            {ok, Meta#{base_hash => BaseHash,
                                                       num_coins => NumCoins,
                                                       network_magic => FileMagic},
                                             Acc};
                                        {error, _} = E ->
                                            E
                                    end;
                                {error, _} = E ->
                                    E
                            end
                    end;
                {ok, _Meta, _Rest} ->
                    {error, truncated_header};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Unvalidated load ignores trailing bytes (historical behaviour of
%% parse_coins/3). Validated load (ExpectedMagic =/= undefined) is G5.
leftover_check(_R, undefined) ->
    ok;
leftover_check(#snap_rdr{buf = Buf}, _ExpectedMagic) when byte_size(Buf) > 0 ->
    {error, coins_left_over};
leftover_check(#snap_rdr{fd = Fd}, _ExpectedMagic) ->
    case file:read(Fd, 1) of
        {ok, <<_>>} -> {error, coins_left_over};
        {ok, <<>>} -> ok;
        eof -> ok;
        {error, Reason} -> {error, {read_failed, Reason}}
    end.

fold_groups(R, 0, _Fun, Acc, _BaseHeight) ->
    {ok, Acc, R};
fold_groups(R, Remaining, Fun, Acc, BaseHeight) when Remaining > 0 ->
    case read_txid_group(R, Remaining, BaseHeight) of
        {ok, _Txid, Coins, CoinsRead, R1} ->
            Acc1 = Fun(_Txid, Coins, Acc),
            fold_groups(R1, Remaining - CoinsRead, Fun, Acc1, BaseHeight);
        {error, Reason} ->
            {error, Reason}
    end.

read_txid_group(R, Remaining, BaseHeight) ->
    case read_exact(R, 32) of
        {ok, Txid, R1} ->
            case read_parsed(R1, fun decode_compact_size/1) of
                {ok, CoinsPerTxid, _RTooMany} when CoinsPerTxid > Remaining ->
                    {error, coins_count_mismatch};
                {ok, CoinsPerTxid, R2} ->
                    case read_group_coins(R2, Txid, CoinsPerTxid, BaseHeight, []) of
                        {ok, Coins, R3} ->
                            {ok, Txid, Coins, CoinsPerTxid, R3};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, truncated} ->
            {error, truncated_txid};
        {error, Reason} ->
            {error, Reason}
    end.

read_group_coins(R, _Txid, 0, _BaseHeight, Acc) ->
    {ok, lists:reverse(Acc), R};
read_group_coins(R, Txid, Remaining, BaseHeight, Acc) when Remaining > 0 ->
    case read_parsed(R, fun decode_compact_size/1) of
        {ok, Vout, _R1} when Vout >= 16#ffffffff, BaseHeight =/= undefined ->
            %% G3 (validated path only): vout >= UINT32_MAX wraps ApplyHash.
            {error, {bad_coin_vout, Vout}};
        {ok, Vout, R1} ->
            ParseCoin = case BaseHeight of
                undefined -> fun parse_coin/1;
                _ -> fun(Bin) -> parse_coin_validated(Bin, BaseHeight) end
            end,
            case read_parsed(R1, ParseCoin) of
                {ok, Utxo0, R2} ->
                    Utxo = detach_spk(Utxo0),
                    read_group_coins(R2, Txid, Remaining - 1, BaseHeight,
                                     [{Vout, Utxo} | Acc]);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% ERTS ERL_ONHEAP_BIN_LIMIT: a >64-byte scriptPubKey sliced out of the
%% 4 MiB read buffer is a sub-binary that would pin the whole chunk if
%% stored. Copy it at the parse boundary, same as chainstate:detach_spk/1.
-define(ONHEAP_BIN_LIMIT, 64).
detach_spk(#utxo{script_pubkey = SPK} = Utxo)
        when byte_size(SPK) > ?ONHEAP_BIN_LIMIT ->
    Utxo#utxo{script_pubkey = binary:copy(SPK)};
detach_spk(Utxo) ->
    Utxo.

read_exact(#snap_rdr{buf = Buf} = R, N) when byte_size(Buf) >= N ->
    <<Got:N/binary, Rest/binary>> = Buf,
    {ok, Got, R#snap_rdr{buf = Rest}};
read_exact(R, N) ->
    case fill(R) of
        {ok, R2} -> read_exact(R2, N);
        eof -> {error, truncated};
        {error, _} = E -> E
    end.

read_parsed(R, ParseFun) ->
    case ParseFun(R#snap_rdr.buf) of
        {ok, Val, Rest} ->
            {ok, Val, R#snap_rdr{buf = Rest}};
        {error, Reason} ->
            case is_truncated(Reason) of
                true ->
                    case fill(R) of
                        {ok, R2} ->
                            case byte_size(R2#snap_rdr.buf) >
                                 byte_size(R#snap_rdr.buf) of
                                true -> read_parsed(R2, ParseFun);
                                false -> {error, Reason}
                            end;
                        eof ->
                            {error, Reason};
                        {error, _} = E ->
                            E
                    end;
                false ->
                    {error, Reason}
            end
    end.

is_truncated(truncated) -> true;
is_truncated(truncated_header) -> true;
is_truncated(truncated_txid) -> true;
is_truncated(truncated_compact_size) -> true;
is_truncated(truncated_varint) -> true;
is_truncated(truncated_script) -> true;
is_truncated(truncated_special_script) -> true;
is_truncated(_) -> false.

fill(#snap_rdr{buf = Buf}) when byte_size(Buf) > ?SNAP_MAX_BUF ->
    {error, snapshot_buffer_overflow};
fill(#snap_rdr{fd = Fd, buf = Buf} = R) ->
    case file:read(Fd, ?SNAP_READ_CHUNK) of
        {ok, Data} ->
            {ok, R#snap_rdr{buf = <<Buf/binary, Data/binary>>}};
        eof ->
            eof;
        {error, Reason} ->
            {error, {read_failed, Reason}}
    end.

%% parse_coin_validated/2 — parse_coin/1 plus G2 (height) and G4 (MoneyRange).
parse_coin_validated(Data, BaseHeight) ->
    case decode_varint(Data) of
        {ok, HeightCode, Rest} ->
            Height = HeightCode bsr 1,
            IsCoinbase = (HeightCode band 1) =:= 1,
            %% G2: coin height must not exceed snapshot base height.
            case Height > BaseHeight of
                true ->
                    {error, {bad_coin_height, Height, BaseHeight}};
                false ->
                    case decode_varint(Rest) of
                        {ok, CompressedValue, Rest2} ->
                            Value = decompress_amount(CompressedValue),
                            %% G4: value must satisfy MoneyRange.
                            case Value > ?MAX_MONEY of
                                true ->
                                    {error, {bad_tx_out_value, Value}};
                                false ->
                                    case decode_script(Rest2) of
                                        {ok, Script, Rest3} ->
                                            Utxo = #utxo{
                                                value = Value,
                                                script_pubkey = Script,
                                                is_coinbase = IsCoinbase,
                                                height = Height
                                            },
                                            {ok, Utxo, Rest3};
                                        {error, Reason} ->
                                            {error, Reason}
                                    end
                            end;
                        {error, Reason} ->
                            {error, Reason}
                    end
            end;
        {error, Reason} ->
            {error, Reason}
    end.

read_metadata_from_fd(Fd) ->
    case file:read(Fd, ?METADATA_SIZE) of
        {ok, Data} when byte_size(Data) =:= ?METADATA_SIZE ->
            case parse_metadata(Data) of
                {ok, Meta, _Rest} -> {ok, Meta};
                {error, Reason} -> {error, Reason}
            end;
        {ok, _} ->
            {error, truncated_header};
        eof ->
            {error, truncated_header};
        {error, Reason} ->
            {error, {read_failed, Reason}}
    end.

%% Parse a single coin: VARINT(code) + VARINT(CompressAmount(value)) +
%% ScriptCompression(scriptPubKey)
parse_coin(Data) ->
    case decode_varint(Data) of
        {ok, HeightCode, Rest} ->
            Height = HeightCode bsr 1,
            IsCoinbase = (HeightCode band 1) =:= 1,
            case decode_varint(Rest) of
                {ok, CompressedValue, Rest2} ->
                    Value = decompress_amount(CompressedValue),
                    case decode_script(Rest2) of
                        {ok, Script, Rest3} ->
                            Utxo = #utxo{
                                value = Value,
                                script_pubkey = Script,
                                is_coinbase = IsCoinbase,
                                height = Height
                            },
                            {ok, Utxo, Rest3};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% ScriptCompression: read a VARINT nSize.
%%   If nSize < 6: it's a special script — read the corresponding
%%   compressed payload (20 or 32 bytes) and decompress it.
%%   Else: nSize -= 6 is the raw script length; read raw bytes.
decode_script(Data) ->
    case decode_varint(Data) of
        {ok, Size, Rest} when Size < ?N_SPECIAL_SCRIPTS ->
            PayloadLen = special_script_payload_size(Size),
            case Rest of
                <<Payload:PayloadLen/binary, Rest2/binary>> ->
                    case decompress_script(Size, Payload) of
                        {ok, Script} -> {ok, Script, Rest2};
                        {error, _} = Err -> Err
                    end;
                _ ->
                    {error, truncated_special_script}
            end;
        {ok, Size, Rest} ->
            RealLen = Size - ?N_SPECIAL_SCRIPTS,
            case Rest of
                <<Script:RealLen/binary, Rest2/binary>> ->
                    {ok, Script, Rest2};
                _ ->
                    {error, truncated_script}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Per Core's GetSpecialScriptSize:
%%   sizes 0,1 -> 20 bytes (P2PKH hash, P2SH hash)
%%   sizes 2,3,4,5 -> 32 bytes (compressed pubkey x-coord)
special_script_payload_size(0) -> 20;
special_script_payload_size(1) -> 20;
special_script_payload_size(2) -> 32;
special_script_payload_size(3) -> 32;
special_script_payload_size(4) -> 32;
special_script_payload_size(5) -> 32.

%%% ===================================================================
%%% Internal: Compact size encoding/decoding (Bitcoin's WriteCompactSize)
%%% ===================================================================

%% MAX_SIZE mirrors bitcoin-core/src/serialize.h line 34:
%%   MAX_SIZE = 0x02000000 (= 33,554,432 bytes)
%% ReadCompactSize throws "ReadCompactSize(): size too large" when the
%% decoded value exceeds MAX_SIZE (range_check=true, the default).
-define(MAX_COMPACT_SIZE, 16#02000000).

decode_compact_size(<<N:8, Rest/binary>>) when N < 253 ->
    {ok, N, Rest};
decode_compact_size(<<253, N:16/little, _Rest/binary>>) when N < 253 ->
    {error, non_canonical_compact_size};
decode_compact_size(<<253, N:16/little, _Rest/binary>>) when N > ?MAX_COMPACT_SIZE ->
    {error, oversized_compact_size};
decode_compact_size(<<253, N:16/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(<<254, N:32/little, _Rest/binary>>) when N < 16#10000 ->
    {error, non_canonical_compact_size};
decode_compact_size(<<254, N:32/little, _Rest/binary>>) when N > ?MAX_COMPACT_SIZE ->
    {error, oversized_compact_size};
decode_compact_size(<<254, N:32/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(<<255, N:64/little, _Rest/binary>>) when N < 16#100000000 ->
    {error, non_canonical_compact_size};
decode_compact_size(<<255, N:64/little, _Rest/binary>>) when N > ?MAX_COMPACT_SIZE ->
    {error, oversized_compact_size};
decode_compact_size(<<255, N:64/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(_) ->
    {error, truncated_compact_size}.

encode_compact_size(N) when N < 253 ->
    <<N:8>>;
encode_compact_size(N) when N =< 16#ffff ->
    <<253, N:16/little>>;
encode_compact_size(N) when N =< 16#ffffffff ->
    <<254, N:32/little>>;
encode_compact_size(N) ->
    <<255, N:64/little>>.

%%% ===================================================================
%%% Internal: VARINT (Bitcoin Core serialize.h WriteVarInt/ReadVarInt)
%%%
%%% Note: this is a DIFFERENT encoding from CompactSize. See
%%% bitcoin-core/src/serialize.h around line 426. Used for `code` and the
%%% compressed-amount/script-size in Coin::Serialize.
%%% ===================================================================

%% encode_varint(N) -> binary().
%% Mirrors WriteVarInt in serialize.h. We compute the bytes least-significant
%% first into a buffer and then emit them in REVERSE order (most significant
%% first). The most-significant byte has bit7 clear; all earlier bytes have
%% bit7 set as a continuation marker.
-spec encode_varint(non_neg_integer()) -> binary().
encode_varint(N) when is_integer(N), N >= 0 ->
    %% Build the per-step bytes in the same order Core does, then emit them
    %% reversed.
    Bytes = build_varint_bytes(N, 0, []),
    iolist_to_binary(Bytes).

%% Tail-recursive: produce list of bytes in MSB-first order.
build_varint_bytes(N, Len, Acc) ->
    Byte0 = (N band 16#7F) bor (case Len of 0 -> 0; _ -> 16#80 end),
    Acc1 = [Byte0 | Acc],
    case N =< 16#7F of
        true ->
            Acc1;
        false ->
            build_varint_bytes((N bsr 7) - 1, Len + 1, Acc1)
    end.

%% decode_varint(Bin) -> {ok, N, Rest} | {error, _}.
-spec decode_varint(binary()) -> {ok, non_neg_integer(), binary()} | {error, atom()}.
decode_varint(Bin) ->
    decode_varint_loop(Bin, 0).

decode_varint_loop(<<Byte:8, Rest/binary>>, N) ->
    %% Bound check: same intent as Core's (n > max>>7) check; we use a
    %% generous 64-bit ceiling here since Erlang ints are arbitrary
    %% precision but the on-wire format is bounded by use site.
    case N > (16#FFFFFFFFFFFFFFFF bsr 7) of
        true -> {error, varint_overflow};
        false ->
            N1 = (N bsl 7) bor (Byte band 16#7F),
            case Byte band 16#80 of
                0 ->
                    {ok, N1, Rest};
                _ ->
                    decode_varint_loop(Rest, N1 + 1)
            end
    end;
decode_varint_loop(<<>>, _N) ->
    {error, truncated_varint}.

%%% ===================================================================
%%% Internal: AmountCompression (compressor.cpp CompressAmount)
%%% ===================================================================

-spec compress_amount(non_neg_integer()) -> non_neg_integer().
compress_amount(0) ->
    0;
compress_amount(N) when is_integer(N), N > 0 ->
    {N1, E} = strip_trailing_zeros(N, 0),
    case E < 9 of
        true ->
            D = N1 rem 10,
            true = (D >= 1) andalso (D =< 9),
            N2 = N1 div 10,
            1 + (N2 * 9 + D - 1) * 10 + E;
        false ->
            1 + (N1 - 1) * 10 + 9
    end.

strip_trailing_zeros(N, E) when E < 9, (N rem 10) =:= 0 ->
    strip_trailing_zeros(N div 10, E + 1);
strip_trailing_zeros(N, E) ->
    {N, E}.

-spec decompress_amount(non_neg_integer()) -> non_neg_integer().
decompress_amount(0) ->
    0;
decompress_amount(X) when is_integer(X), X > 0 ->
    X1 = X - 1,
    E = X1 rem 10,
    X2 = X1 div 10,
    N0 = case E of
        9 -> X2 + 1;
        _ ->
            D = (X2 rem 9) + 1,
            X3 = X2 div 9,
            X3 * 10 + D
    end,
    apply_exponent(N0, E).

apply_exponent(N, 0) -> N;
apply_exponent(N, E) when E > 0 -> apply_exponent(N * 10, E - 1).

%%% ===================================================================
%%% Internal: ScriptCompression (compressor.cpp CompressScript)
%%% ===================================================================

%% compress_script(Script) -> {special, Type, Payload} | raw.
%% Returns {special, Type, Payload} when the script matches one of the 6
%% special cases (where Type ∈ 0..5 maps to the script-size byte that
%% appears as VARINT prefix). Returns `raw` when the script must be written
%% as VARINT(size + 6) ++ raw bytes.
-spec compress_script(binary()) -> {special, non_neg_integer(), binary()} | raw.
%% P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
compress_script(<<16#76, 16#a9, 20, Hash:20/binary, 16#88, 16#ac>>) ->
    {special, 0, Hash};
%% P2SH: OP_HASH160 <20> <hash> OP_EQUAL
compress_script(<<16#a9, 20, Hash:20/binary, 16#87>>) ->
    {special, 1, Hash};
%% P2PK with compressed pubkey (33 bytes): <33> <02|03 X> OP_CHECKSIG
compress_script(<<33, Prefix:8, X:32/binary, 16#ac>>) when Prefix =:= 16#02; Prefix =:= 16#03 ->
    {special, Prefix, X};
%% P2PK with uncompressed pubkey (65 bytes): <65> <04 X Y> OP_CHECKSIG
%% Type byte = 0x04 | (Y_lsb & 1)  -> values 0x04 or 0x05
%%
%% Per compressor.cpp IsToPubKey, Core only emits the compressed form when
%% pubkey.IsFullyValid() is true (on-curve check). Our validate_pubkey/1
%% only checks structure (prefix + length), not on-curve. Real-world
%% mainnet P2PK outputs are all on-curve, so the structural check matches
%% Core in practice. A maliciously-crafted off-curve P2PK would round-trip
%% incorrectly here; that is a known TODO until validate_pubkey grows a
%% full ECPoint check.
compress_script(<<65, 16#04, X:32/binary, Y:32/binary, 16#ac>>) ->
    case beamchain_crypto:validate_pubkey(<<16#04, X/binary, Y/binary>>) of
        true ->
            YLsb = binary:last(Y) band 1,
            {special, 16#04 bor YLsb, X};
        false ->
            raw
    end;
compress_script(_) ->
    raw.

%% decompress_script(Type, Payload) -> {ok, Script} | {error, Reason}.
%% Type 0..5 with Payload 20 or 32 bytes; rebuild the original script.
%% For Type 4/5 we need to recover Y from X using the secp256k1 curve.
-spec decompress_script(non_neg_integer(), binary()) ->
    {ok, binary()} | {error, atom()}.
decompress_script(0, <<Hash:20/binary>>) ->
    {ok, <<16#76, 16#a9, 20, Hash/binary, 16#88, 16#ac>>};
decompress_script(1, <<Hash:20/binary>>) ->
    {ok, <<16#a9, 20, Hash/binary, 16#87>>};
decompress_script(Prefix, <<X:32/binary>>) when Prefix =:= 16#02; Prefix =:= 16#03 ->
    {ok, <<33, Prefix:8, X/binary, 16#ac>>};
decompress_script(Type, <<X:32/binary>>) when Type =:= 16#04; Type =:= 16#05 ->
    %% Recover Y from X using secp256k1 (y² = x³ + 7 mod p) and the parity
    %% bit (Type & 1). We feed pubkey_decompress/1 a 33-byte compressed
    %% pubkey: prefix 0x02 (Type 4) or 0x03 (Type 5) followed by X.
    %% This matches compressor.cpp DecompressScript cases 0x04/0x05.
    Prefix = (Type - 2),  %% 0x04 -> 0x02, 0x05 -> 0x03
    case beamchain_crypto:pubkey_decompress(<<Prefix:8, X/binary>>) of
        {ok, <<16#04, _:64/binary>> = Full} ->
            {ok, <<65, Full/binary, 16#ac>>};
        {ok, _Other} ->
            {error, decompress_pubkey_unexpected_form};
        {error, Reason} ->
            {error, {decompress_pubkey_failed, Reason}}
    end;
decompress_script(_, _) ->
    {error, bad_special_script}.

%%% ===================================================================
%%% Internal: HASH_SERIALIZED UTXO-set commitment (SHA256d via HashWriter)
%%%
%%% This is the "hashSerialized" commitment that
%%%   bitcoin-core/src/validation.cpp:5901-5914 (loadtxoutset strict gate)
%%%   bitcoin-core/src/kernel/coinstats.cpp:161  (HASH_SERIALIZED branch)
%%% select via `HashWriter` — i.e. SHA256d over the streamed TxOutSer
%%% bytes of every (outpoint, coin) in the UTXO set, walked in CCoinsView
%%% cursor order (txid lexicographic; vouts within a txid taken from a
%%% std::map<uint32_t, Coin> so naturally vout-ascending).
%%%
%%% The 32-byte stored hash in chainparams (uint256, internal byte order)
%%% is the GetHash() return — i.e. SHA256(SHA256(stream)).
%%%
%%% Per-coin bytes are produced by tx_out_ser/3 (see TxOutSer in
%%% kernel/coinstats.cpp:46-51):
%%%   COutPoint  := txid (32 bytes, internal byte order) || vout (uint32 LE)
%%%   uint32 LE  := (height << 1) | fCoinBase
%%%   CTxOut     := nValue (int64 LE) || CompactSize(scriptPubKey size) ||
%%%                 raw scriptPubKey bytes
%%%
%%% No special-form ScriptCompression here — that lives in the on-disk
%%% snapshot format (parse_coin/serialize_coin), not in TxOutSer.
%%% ===================================================================

%% Backwards-compatible alias — same body as compute_utxo_hash_from_list/1.
%% Kept so any caller still importing the `_legacy` name keeps linking.
-spec compute_utxo_hash_from_list_legacy([{binary(), non_neg_integer(),
                                           #utxo{}}]) -> binary().
compute_utxo_hash_from_list_legacy(Coins) ->
    compute_utxo_hash_from_list(Coins).

%% @doc Compute the HASH_SERIALIZED UTXO-set commitment (SHA256d) over a
%% list of {Txid, Vout, #utxo{}} tuples. Mirrors Core's
%% `ComputeUTXOStats(HASH_SERIALIZED, ...)` walk + GetHash().
%%
%% Order: groups by Txid lex (matches CCoinsView cursor), and within each
%% Txid emits vouts in ascending order (matches std::map<uint32_t, Coin>
%% iteration in ApplyHash, kernel/coinstats.cpp:87-94).
%%
%% Returns the 32-byte uint256 in INTERNAL byte order, byte-for-byte
%% equal to `CCoinsStats.hashSerialized` for an equivalent UTXO set.
-spec compute_utxo_hash_from_list([{binary(), non_neg_integer(),
                                    #utxo{}}]) -> binary().
compute_utxo_hash_from_list(Coins) when is_list(Coins) ->
    %% In-memory helper for tests / small fixtures. Production walks
    %% compute_utxo_hash_stream/0. Sort by (Txid lex, Vout ASC) — matches
    %% Core's std::map<uint32_t, Coin> ApplyHash order, not LE32 key order.
    Sorted = lists:sort(fun({Txid1, Vout1, _}, {Txid2, Vout2, _}) ->
        {Txid1, Vout1} =< {Txid2, Vout2}
    end, Coins),
    Ctx = lists:foldl(fun({Txid, Vout, Utxo}, C) ->
        hash_writer_update(C, tx_out_ser(Txid, Vout, Utxo))
    end, hash_writer_new(), Sorted),
    hash_writer_final(Ctx).

%% HashWriter (bitcoin-core/src/hash.h): incremental SHA256, GetHash() =
%% SHA256(SHA256_state). Same digest as hash256(concat(bytes)) but the
%% payload is never concatenated into one binary.
hash_writer_new() ->
    crypto:hash_init(sha256).

hash_writer_update(Ctx, Data) ->
    crypto:hash_update(Ctx, Data).

hash_writer_final(Ctx) ->
    Inner = crypto:hash_final(Ctx),
    crypto:hash(sha256, Inner).

%% @doc HASH_SERIALIZED over the on-disk chainstate CF, one txid group
%% at a time. Mirrors kernel/coinstats.cpp ComputeUTXOStats + ApplyHash
%% (std::map<uint32_t, Coin> so vouts are numeric, not LE32-lex) and
%% haskoin 5b59a06 computeUtxoHashFromDBPrefix.
%%
%% Caller must have flushed the write-behind cache (compute_utxo_hash/0
%% does; handle_call(compute_utxo_hash) must do_flush first to avoid
%% deadlock). Does NOT call chainstate:flush/0.
-spec compute_utxo_hash_stream() -> binary().
compute_utxo_hash_stream() ->
    {Hash, _Stats} = compute_utxo_stats(hash_serialized),
    Hash.

%% @doc Single cursor walk: tally Core's nTransactionOutputs / nBogoSize /
%% nTotalAmount / nTransactions, and optionally HASH_SERIALIZED or MuHash.
%% STREAMING-HASH: never materialises the coin set.
-spec compute_utxo_stats(hash_serialized | muhash | none) ->
    {binary() | undefined,
     #{txouts := non_neg_integer(),
       bogosize := non_neg_integer(),
       total_amount := integer(),
       transactions := non_neg_integer()}}.
compute_utxo_stats(HashType) ->
    Acc0 = #{hash => init_stats_hash(HashType),
             txouts => 0,
             bogosize => 0,
             total_amount => 0,
             transactions => 0},
    case fold_utxo_txid_groups(fun(Txid, Outs, Acc) ->
                                       stats_visit_group(HashType, Txid, Outs, Acc)
                               end, Acc0) of
        {ok, Acc, _Peak} ->
            Hash = finalize_stats_hash(HashType, maps:get(hash, Acc)),
            Stats = maps:with([txouts, bogosize, total_amount, transactions], Acc),
            {Hash, Stats};
        {error, Reason} ->
            logger:error("beamchain_snapshot: fold_utxo_txid_groups failed: ~p",
                         [Reason]),
            erlang:error({utxo_stats_walk_failed, Reason})
    end.

init_stats_hash(hash_serialized) -> hash_writer_new();
init_stats_hash(muhash) -> beamchain_muhash:new();
init_stats_hash(none) -> undefined.

finalize_stats_hash(hash_serialized, Ctx) -> hash_writer_final(Ctx);
finalize_stats_hash(muhash, Acc) -> beamchain_muhash:finalize(Acc);
finalize_stats_hash(none, _) -> undefined.

stats_visit_group(HashType, Txid, Outs, Acc) ->
    Acc1 = tally_group(Outs, Acc),
    hash_group(HashType, Txid, Outs, Acc1).

tally_group(Outs, Acc) ->
    lists:foldl(fun({_Vout, #utxo{script_pubkey = SPK, value = Value}}, A) ->
        %% Core GetBogoSize: 50 + scriptPubKey.size()
        %% (kernel/coinstats.cpp:36-42).
        A#{txouts := maps:get(txouts, A) + 1,
           bogosize := maps:get(bogosize, A) + 50 + byte_size(SPK),
           total_amount := maps:get(total_amount, A) + Value}
    end, Acc#{transactions := maps:get(transactions, Acc) + 1}, Outs).

hash_group(hash_serialized, Txid, Outs, Acc) ->
    Ctx = lists:foldl(fun({Vout, Utxo}, C) ->
        hash_writer_update(C, tx_out_ser(Txid, Vout, Utxo))
    end, maps:get(hash, Acc), Outs),
    Acc#{hash := Ctx};
hash_group(muhash, Txid, Outs, Acc) ->
    Mu = lists:foldl(fun({Vout, Utxo}, M) ->
        txoutset_muhash_apply(add, {Txid, Vout, Utxo}, M)
    end, maps:get(hash, Acc), Outs),
    Acc#{hash := Mu};
hash_group(none, _Txid, _Outs, Acc) ->
    Acc.

%% @doc Walk the chainstate CF grouped by txid. Fun is called once per
%% txid with vouts in ascending NUMERIC order (Core ApplyHash). Returns
%% `{ok, Acc, Peak}` where Peak is the widest single-txid group seen —
%% the RAM bound of this walk, not the size of the UTXO set.
-spec fold_utxo_txid_groups(fun((binary(), [{non_neg_integer(), #utxo{}}], Acc)
                                -> Acc),
                            Acc) ->
    {ok, Acc, non_neg_integer()} | {error, term()}.
fold_utxo_txid_groups(Fun, Acc0) when is_function(Fun, 3) ->
    case beamchain_db:fold_utxos(fun utxo_group_visit/2,
                                 {undefined, [], Acc0, Fun, 0}) of
        {error, _} = E ->
            E;
        {undefined, [], Acc, _Fun, Peak} ->
            {ok, Acc, Peak};
        {Txid, Outs, Acc, Fun, Peak} ->
            Sorted = lists:keysort(1, Outs),
            Acc1 = Fun(Txid, Sorted, Acc),
            {ok, Acc1, max(Peak, length(Sorted))};
        Other ->
            {error, {unexpected_utxo_fold_acc, Other}}
    end.

utxo_group_visit({Txid, Vout, Utxo}, {Txid, Outs, Acc, Fun, Peak}) ->
    {Txid, [{Vout, Utxo} | Outs], Acc, Fun, Peak};
utxo_group_visit({Txid, Vout, Utxo}, {undefined, [], Acc, Fun, Peak}) ->
    {Txid, [{Vout, Utxo}], Acc, Fun, Peak};
utxo_group_visit({Txid, Vout, Utxo}, {PrevTxid, Outs, Acc, Fun, Peak}) ->
    Sorted = lists:keysort(1, Outs),
    Acc1 = Fun(PrevTxid, Sorted, Acc),
    Peak1 = max(Peak, length(Sorted)),
    {Txid, [{Vout, Utxo}], Acc1, Fun, Peak1}.

%%% ===================================================================
%%% Internal: UTXO collection
%%% ===================================================================

%% Collect all UTXOs from the chainstate cache and RocksDB.
%%
%% We must walk the persisted chainstate column family — not just the ETS
%% cache — because the cache only holds UTXOs touched since the last flush.
%% Mirrors Core's `view->Cursor()` walk in
%% bitcoin-core/src/kernel/coinstats.cpp ComputeUTXOStats.
%%
%% The flush/0 call below promotes any dirty in-memory entries to the CF
%% atomically with the chain tip (see beamchain_chainstate:do_flush/1), so
%% by the time we open the iterator the on-disk view is the authoritative
%% snapshot of the UTXO set at the current tip.
collect_all_utxos() ->
    %% First flush cache to ensure all UTXOs are in RocksDB.
    beamchain_chainstate:flush(),

    %% Iterate the chainstate CF; collect into a list. Order does not
    %% matter for the caller (compute_utxo_hash_from_list/1 sorts and
    %% group_coins_by_txid/1 also sorts), so we accumulate in iterator
    %% order and let downstream sort.
    Result = beamchain_db:fold_utxos(
        fun(Coin, Acc) -> [Coin | Acc] end,
        []),
    case Result of
        Coins when is_list(Coins) ->
            Coins;
        {error, Reason} ->
            logger:error("beamchain_snapshot: fold_utxos failed: ~p",
                         [Reason]),
            []
    end.

%% Group coins by txid for efficient serialization
group_coins_by_txid(Coins) ->
    %% Sort by txid first
    Sorted = lists:sort(fun({Txid1, _, _}, {Txid2, _, _}) ->
        Txid1 =< Txid2
    end, Coins),

    %% Group consecutive coins with same txid
    group_consecutive(Sorted, []).

group_consecutive([], Acc) ->
    lists:reverse(Acc);
group_consecutive([{Txid, Vout, Utxo} | Rest], []) ->
    group_consecutive(Rest, [{Txid, [{Vout, Utxo}]}]);
group_consecutive([{Txid, Vout, Utxo} | Rest], [{Txid, Coins} | GroupAcc]) ->
    group_consecutive(Rest, [{Txid, [{Vout, Utxo} | Coins]} | GroupAcc]);
group_consecutive([{Txid, Vout, Utxo} | Rest], Acc) ->
    group_consecutive(Rest, [{Txid, [{Vout, Utxo}]} | Acc]).

%%% ===================================================================
%%% Internal: Serialization
%%% ===================================================================

serialize_grouped_coins(Grouped) ->
    Parts = lists:map(fun serialize_grouped_tx/1, Grouped),
    iolist_to_binary(Parts).

serialize_grouped_tx({Txid, Coins}) ->
    %% Sort by vout ascending to match Bitcoin Core's write_coins_to_file,
    %% which walks a std::map<uint32_t, Coin> (vout-ascending by construction).
    %% Reference: bitcoin-core/src/rpc/blockchain.cpp write_coins_to_file;
    %%            bitcoin-core/src/serialize.h WriteCompactSize.
    Ordered = lists:sort(fun({Vout1, _}, {Vout2, _}) -> Vout1 =< Vout2 end, Coins),
    CoinsCount = encode_compact_size(length(Ordered)),
    CoinsBin = lists:map(fun({Vout, Utxo}) ->
        VoutBin = encode_compact_size(Vout),
        CoinBin = serialize_coin(Utxo),
        [VoutBin, CoinBin]
    end, Ordered),
    [<<Txid:32/binary>>, CoinsCount, CoinsBin].

%% Serialize one Coin in Bitcoin Core format.
%% VARINT(code = (height << 1) | coinbase) ++
%% VARINT(CompressAmount(value)) ++
%% ScriptCompression(scriptPubKey)
serialize_coin(#utxo{value = Value, script_pubkey = Script,
                     is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    Code = (Height bsl 1) bor CoinbaseFlag,
    CodeBin = encode_varint(Code),
    AmountBin = encode_varint(compress_amount(Value)),
    ScriptBin = serialize_script(Script),
    <<CodeBin/binary, AmountBin/binary, ScriptBin/binary>>.

%% serialize_script(Script) -> binary().
%% Special script -> VARINT(type 0..5) ++ payload (no length prefix —
%% size is implied by type).
%% Otherwise -> VARINT(size + 6) ++ raw bytes.
serialize_script(Script) when is_binary(Script) ->
    case compress_script(Script) of
        {special, Type, Payload} ->
            <<(encode_varint(Type))/binary, Payload/binary>>;
        raw ->
            Size = byte_size(Script),
            <<(encode_varint(Size + ?N_SPECIAL_SCRIPTS))/binary, Script/binary>>
    end.
