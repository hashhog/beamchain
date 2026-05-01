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

-export([load_snapshot/1, verify_snapshot/2]).
-export([compute_utxo_hash/0, serialize_snapshot/2]).
-export([read_metadata/1]).

%% Internal helpers exported for unit tests.
-export([encode_compact_size/1, decode_compact_size/1,
         encode_varint/1, decode_varint/1,
         compress_amount/1, decompress_amount/1,
         compress_script/1, decompress_script/2,
         serialize_coin/1, parse_coin/1,
         serialize_metadata/3, parse_metadata/1,
         metadata_size/0]).

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
-spec load_snapshot(string()) ->
    {ok, #{base_hash => binary(), num_coins => non_neg_integer(),
           coins => [{binary(), non_neg_integer(), #utxo{}}]}} |
    {error, term()}.
load_snapshot(Path) ->
    case file:read_file(Path) of
        {ok, Data} ->
            parse_snapshot(Data);
        {error, Reason} ->
            {error, {file_read_failed, Reason}}
    end.

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
%% Checks block hash and UTXO hash (mirrors validation.cpp lines 5912-5915
%% where Core compares ComputeUTXOStats(...).hashSerialized to
%% au_data.hash_serialized after loading every coin).
-spec verify_snapshot(map(), atom()) -> ok | {error, term()}.
verify_snapshot(#{base_hash := BaseHash, coins := Coins} = _Snapshot, Network) ->
    %% Look up assumeutxo data by block hash
    case beamchain_chain_params:get_assumeutxo_by_hash(BaseHash, Network) of
        {ok, _Height, #{utxo_hash := ExpectedUtxoHash}} ->
            ComputedHash = compute_utxo_hash_from_list(Coins),
            case ComputedHash =:= ExpectedUtxoHash of
                true -> ok;
                false -> {error, {utxo_hash_mismatch,
                                  #{expected => ExpectedUtxoHash,
                                    computed => ComputedHash}}}
            end;
        not_found ->
            {error, {unknown_snapshot_base, BaseHash}}
    end.

%% @doc Compute the UTXO set hash from the current chainstate.
%% SHA256 of all UTXOs in deterministic order.
-spec compute_utxo_hash() -> binary().
compute_utxo_hash() ->
    %% Collect all UTXOs from chainstate in deterministic order
    %% This iterates through RocksDB in key order
    Coins = collect_all_utxos(),
    compute_utxo_hash_from_list(Coins).

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
%%% Internal: Parsing
%%% ===================================================================

parse_snapshot(Data) ->
    case parse_metadata(Data) of
        {ok, #{base_hash := BaseHash, num_coins := NumCoins,
               network_magic := _Magic}, Rest} ->
            case parse_coins(Rest, NumCoins, []) of
                {ok, Coins} ->
                    {ok, #{base_hash => BaseHash,
                           num_coins => NumCoins,
                           coins => Coins}};
                {error, Reason} ->
                    {error, Reason}
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

parse_coins(_Data, 0, Acc) ->
    {ok, lists:reverse(Acc)};
parse_coins(Data, Remaining, Acc) when Remaining > 0 ->
    case parse_txid_coins(Data) of
        {ok, TxidCoins, Rest, CoinsRead} ->
            parse_coins(Rest, Remaining - CoinsRead, TxidCoins ++ Acc);
        {error, Reason} ->
            {error, Reason}
    end.

%% Parse coins for a single txid
parse_txid_coins(<<Txid:32/binary, Rest/binary>>) ->
    case decode_compact_size(Rest) of
        {ok, CoinsPerTxid, Rest2} ->
            parse_txid_coin_entries(Rest2, Txid, CoinsPerTxid, []);
        {error, Reason} ->
            {error, Reason}
    end;
parse_txid_coins(_) ->
    {error, truncated_txid}.

parse_txid_coin_entries(Data, _Txid, 0, Acc) ->
    {ok, lists:reverse(Acc), Data, length(Acc)};
parse_txid_coin_entries(Data, Txid, Remaining, Acc) when Remaining > 0 ->
    case decode_compact_size(Data) of
        {ok, Vout, Rest} ->
            case parse_coin(Rest) of
                {ok, Utxo, Rest2} ->
                    Entry = {Txid, Vout, Utxo},
                    parse_txid_coin_entries(Rest2, Txid, Remaining - 1, [Entry | Acc]);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
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

decode_compact_size(<<N:8, Rest/binary>>) when N < 253 ->
    {ok, N, Rest};
decode_compact_size(<<253, N:16/little, Rest/binary>>) ->
    {ok, N, Rest};
decode_compact_size(<<254, N:32/little, Rest/binary>>) ->
    {ok, N, Rest};
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
%%% Internal: UTXO hash computation
%%% ===================================================================

%% Compute hash from list of {Txid, Vout, Utxo} tuples
compute_utxo_hash_from_list(Coins) ->
    %% Sort by outpoint (txid, vout) for deterministic order
    Sorted = lists:sort(fun({Txid1, Vout1, _}, {Txid2, Vout2, _}) ->
        {Txid1, Vout1} =< {Txid2, Vout2}
    end, Coins),

    %% Serialize each coin and hash in one shot via the NIF-backed
    %% beamchain_crypto:sha256/1 instead of streaming crypto:hash_init/update/final.
    %% The coin list is already fully materialized in memory, so accumulating
    %% the binaries does not increase peak memory usage.
    AllBins = lists:map(fun({Txid, Vout, Utxo}) ->
        serialize_coin_for_hash(Txid, Vout, Utxo)
    end, Sorted),
    beamchain_crypto:sha256(iolist_to_binary(AllBins)).

serialize_coin_for_hash(Txid, Vout, #utxo{value = Value, script_pubkey = Script,
                                          is_coinbase = IsCoinbase, height = Height}) ->
    CoinbaseFlag = case IsCoinbase of true -> 1; false -> 0 end,
    %% Format: txid || vout(32-bit) || value(64-bit) || height(32-bit) || coinbase(8-bit) || script
    <<Txid:32/binary, Vout:32/big, Value:64/little, Height:32/little,
      CoinbaseFlag:8, Script/binary>>.

%%% ===================================================================
%%% Internal: UTXO collection
%%% ===================================================================

%% Collect all UTXOs from the chainstate cache and RocksDB
collect_all_utxos() ->
    %% First flush cache to ensure all UTXOs are in RocksDB
    beamchain_chainstate:flush(),

    %% Iterate through all UTXOs in RocksDB
    case beamchain_db:get_meta(<<"utxo_iterator_not_impl">>) of
        _ ->
            %% TODO: Implement RocksDB iterator for chainstate CF
            %% For now, return empty - this will be implemented when needed
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
    %% Coins were prepended during grouping, so reverse for vout-asc output.
    Ordered = lists:reverse(Coins),
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
