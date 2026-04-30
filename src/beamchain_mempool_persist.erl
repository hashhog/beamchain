-module(beamchain_mempool_persist).

%% Bitcoin Core-compatible mempool.dat persistence.
%%
%% Format reference: bitcoin-core/src/node/mempool_persist.cpp
%% (MEMPOOL_DUMP_VERSION = 2). All multi-byte integers are little-endian.
%% The body of the file is XOR-obfuscated by an 8-byte key that lives
%% (unobfuscated) right after the 8-byte version header. The key is
%% serialized as a CompactSize length prefix + raw key bytes, which is
%% exactly how AutoFile / Obfuscation::Serialize writes a vector<byte>.
%%
%%   uint64_t version                        (LE, plaintext)
%%   compact_size key_len + bytes[key_len]   (plaintext, only if version==2)
%%   --- everything below is XOR'd by the 8-byte key, repeating ---
%%   uint64_t tx_count                       (LE)
%%   for each tx:
%%     CTransaction (with witness)           (encode_transaction/2)
%%     int64_t  time_added                   (LE, seconds since epoch)
%%     int64_t  nFeeDelta                    (LE)
%%   compact_size deltas_count
%%   for each delta:
%%     32-byte txid
%%     int64_t fee_delta                     (LE)
%%   compact_size unbroadcast_count
%%   for each:
%%     32-byte txid
%%
%% beamchain has no fee-delta priority map and no unbroadcast set today,
%% so we always serialize empty maps/sets for those two trailers. The
%% file is still byte-for-byte parseable by Bitcoin Core (and by us).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% No #mempool_entry{} include — that record lives inside
%% beamchain_mempool.erl as an implementation detail. We obtain entries
%% via beamchain_mempool:get_persistable_entries/0 instead.

-export([dump/0, dump/1,
         load/0, load/1,
         file_path/0]).

%% Internal exports for tests
-export([serialize_payload/1,
         deserialize_payload/1,
         apply_obfuscation/2,
         encode_compact_size/1,
         decode_compact_size/1]).

-define(MEMPOOL_FILE, "mempool.dat").
-define(MEMPOOL_DUMP_VERSION_NO_XOR_KEY, 1).
-define(MEMPOOL_DUMP_VERSION, 2).
-define(KEY_SIZE, 8).

%%% ===================================================================
%%% API
%%% ===================================================================

%% @doc Default dump path: <datadir>/mempool.dat.
-spec file_path() -> string().
file_path() ->
    DataDir = try beamchain_config:datadir()
              catch _:_ -> "/tmp"
              end,
    filename:join(DataDir, ?MEMPOOL_FILE).

%% @doc Dump the current mempool to <datadir>/mempool.dat.
-spec dump() -> {ok, non_neg_integer()} | {error, term()}.
dump() ->
    dump(file_path()).

-spec dump(file:filename_all()) -> {ok, non_neg_integer()} | {error, term()}.
dump(Path) ->
    Entries = safe_get_persistable_entries(),
    Count = length(Entries),
    Txs = [{Tx, Time, 0}             %% no fee-delta priority yet
           || {Tx, Time} <- Entries],
    Payload = #{
        txs           => Txs,
        deltas        => [],   %% empty mapDeltas (no PrioritiseTransaction yet)
        unbroadcast   => []    %% empty set (we don't track unbroadcast yet)
    },
    Body = serialize_payload(Payload),
    Key = random_key(),
    ObfBody = apply_obfuscation(Body, Key),

    Header = <<?MEMPOOL_DUMP_VERSION:64/little,
               (encode_compact_size(?KEY_SIZE))/binary,
               Key/binary>>,

    File = <<Header/binary, ObfBody/binary>>,

    Tmp = Path ++ ".new",
    ok = filelib:ensure_dir(Tmp),
    case file:write_file(Tmp, File) of
        ok ->
            case file:rename(Tmp, Path) of
                ok ->
                    logger:info("mempool_persist: dumped ~B txs to ~s "
                                "(~B bytes)",
                                [Count, Path, byte_size(File)]),
                    {ok, Count};
                {error, Reason} ->
                    _ = file:delete(Tmp),
                    logger:warning("mempool_persist: rename failed: ~p",
                                   [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            logger:warning("mempool_persist: write failed: ~p", [Reason]),
            {error, Reason}
    end.

%% @doc Load <datadir>/mempool.dat and re-submit transactions to the
%% running mempool. Each tx is re-validated through accept_to_memory_pool
%% so policy rules apply. Returns {ok, #{accepted, expired, failed,
%% already, total}}.
-spec load() -> {ok, map()} | {error, term()}.
load() ->
    load(file_path()).

-spec load(file:filename_all()) -> {ok, map()} | {error, term()}.
load(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            try
                Payload = parse_file(Bin),
                {ok, apply_loaded(Payload)}
            catch
                _:Reason:Stack ->
                    logger:warning("mempool_persist: failed to parse ~s: "
                                   "~p~n  ~p",
                                   [Path, Reason, Stack]),
                    {error, Reason}
            end;
        {error, enoent} ->
            {error, no_file};
        {error, Reason} ->
            logger:warning("mempool_persist: cannot read ~s: ~p",
                           [Path, Reason]),
            {error, Reason}
    end.

%%% ===================================================================
%%% Payload (de)serialization — pre-obfuscation
%%% ===================================================================

serialize_payload(#{txs := Txs, deltas := Deltas, unbroadcast := Unbroadcast}) ->
    TxCountBin = <<(length(Txs)):64/little>>,
    TxsBin = list_to_binary(
               [encode_tx_entry(Tx, Time, Fee) || {Tx, Time, Fee} <- Txs]),
    DeltasBin = encode_deltas(Deltas),
    UnbroadcastBin = encode_txid_set(Unbroadcast),
    <<TxCountBin/binary, TxsBin/binary,
      DeltasBin/binary, UnbroadcastBin/binary>>.

deserialize_payload(<<Count:64/little, Rest0/binary>>) ->
    {Txs, Rest1} = decode_n_tx_entries(Count, Rest0, []),
    {Deltas, Rest2} = decode_deltas(Rest1),
    {Unbroadcast, _Tail} = decode_txid_set(Rest2),
    %% _Tail may have trailing zeros if the file was rounded for I/O —
    %% Bitcoin Core does not pad, but we tolerate trailing bytes.
    #{txs => Txs, deltas => Deltas, unbroadcast => Unbroadcast}.

encode_tx_entry(Tx, Time, FeeDelta) ->
    TxBin = beamchain_serialize:encode_transaction(Tx),
    TimeBin = encode_int64_le(Time),
    FeeBin = encode_int64_le(FeeDelta),
    <<TxBin/binary, TimeBin/binary, FeeBin/binary>>.

decode_n_tx_entries(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
decode_n_tx_entries(N, Bin, Acc) ->
    {Tx, Rest1} = beamchain_serialize:decode_transaction(Bin),
    <<Time:64/signed-little, FeeDelta:64/signed-little, Rest2/binary>> = Rest1,
    decode_n_tx_entries(N - 1, Rest2, [{Tx, Time, FeeDelta} | Acc]).

encode_deltas(Deltas) ->
    CountBin = encode_compact_size(length(Deltas)),
    Body = list_to_binary(
             [<<Txid:32/binary, (encode_int64_le(Delta))/binary>>
              || {Txid, Delta} <- Deltas]),
    <<CountBin/binary, Body/binary>>.

decode_deltas(Bin) ->
    {Count, Rest0} = decode_compact_size(Bin),
    decode_n_deltas(Count, Rest0, []).

decode_n_deltas(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
decode_n_deltas(N, <<Txid:32/binary, Delta:64/signed-little, Rest/binary>>,
                Acc) ->
    decode_n_deltas(N - 1, Rest, [{Txid, Delta} | Acc]).

encode_txid_set(Txids) ->
    CountBin = encode_compact_size(length(Txids)),
    Body = list_to_binary([T || T <- Txids, byte_size(T) =:= 32]),
    <<CountBin/binary, Body/binary>>.

decode_txid_set(Bin) ->
    {Count, Rest0} = decode_compact_size(Bin),
    decode_n_txids(Count, Rest0, []).

decode_n_txids(0, Rest, Acc) ->
    {lists:reverse(Acc), Rest};
decode_n_txids(N, <<Txid:32/binary, Rest/binary>>, Acc) ->
    decode_n_txids(N - 1, Rest, [Txid | Acc]).

encode_int64_le(N) when is_integer(N) ->
    <<N:64/signed-little>>.

%%% ===================================================================
%%% CompactSize (matches AutoFile/Bitcoin Core, identical to the
%%% network-protocol varint we already have in beamchain_serialize).
%%% ===================================================================

encode_compact_size(N) ->
    beamchain_serialize:encode_varint(N).

decode_compact_size(Bin) ->
    beamchain_serialize:decode_varint(Bin).

%%% ===================================================================
%%% Top-level file framing
%%% ===================================================================

parse_file(<<Version:64/little, Rest0/binary>>)
  when Version =:= ?MEMPOOL_DUMP_VERSION_NO_XOR_KEY ->
    %% v1 file — no XOR key
    deserialize_payload(Rest0);
parse_file(<<Version:64/little, Rest0/binary>>)
  when Version =:= ?MEMPOOL_DUMP_VERSION ->
    {KeyLen, Rest1} = decode_compact_size(Rest0),
    KeyLen =:= ?KEY_SIZE
        orelse error({bad_obfuscation_key_size, KeyLen}),
    <<Key:?KEY_SIZE/binary, Body/binary>> = Rest1,
    Plain = apply_obfuscation(Body, Key),
    deserialize_payload(Plain);
parse_file(<<Version:64/little, _/binary>>) ->
    error({bad_mempool_version, Version}).

%%% ===================================================================
%%% Obfuscation: bytewise XOR with the 8-byte repeating key. This is
%%% byte-for-byte equivalent to Bitcoin Core's Obfuscation::operator()
%%% — we always start at key_offset=0 since the AutoFile resets when it
%%% calls SetObfuscation right after writing the version+key prefix.
%%% ===================================================================

apply_obfuscation(Bin, <<0,0,0,0,0,0,0,0>>) ->
    %% all-zero key: no-op (matches Obfuscation::operator bool() == false)
    Bin;
apply_obfuscation(Bin, Key) when byte_size(Key) =:= ?KEY_SIZE ->
    xor_bytes(Bin, Key, 0, <<>>).

xor_bytes(<<>>, _Key, _Off, Acc) ->
    Acc;
xor_bytes(<<B:8, Rest/binary>>, Key, Off, Acc) ->
    KeyByte = binary:at(Key, Off rem ?KEY_SIZE),
    xor_bytes(Rest, Key, Off + 1, <<Acc/binary, (B bxor KeyByte):8>>).

random_key() ->
    %% 8 random bytes; if all zeros, swap to 0x01 to keep the file marked
    %% as "obfuscated" (mirrors Core which seeds via FastRandomContext).
    case crypto:strong_rand_bytes(?KEY_SIZE) of
        <<0,0,0,0,0,0,0,0>> -> <<1,0,0,0,0,0,0,0>>;
        K -> K
    end.

%%% ===================================================================
%%% Application
%%% ===================================================================

%% Re-submit loaded transactions, dropping any older than the configured
%% mempool expiry. Mirrors Core's expired/already-there/failed counting.
apply_loaded(#{txs := Txs} = _Payload) ->
    Now = erlang:system_time(second),
    Cutoff = Now - (?MEMPOOL_EXPIRY_HOURS * 3600),
    Total = length(Txs),
    Init = #{accepted => 0, expired => 0, failed => 0, already => 0,
             total => Total},
    lists:foldl(
      fun({Tx, Time, _FeeDelta}, Acc) ->
              case Time =< Cutoff of
                  true ->
                      bump(expired, Acc);
                  false ->
                      try beamchain_mempool:accept_to_memory_pool(Tx) of
                          {ok, _Txid} ->
                              bump(accepted, Acc);
                          {error, already_in_mempool} ->
                              bump(already, Acc);
                          {error, _Other} ->
                              bump(failed, Acc)
                      catch
                          _:_ ->
                              bump(failed, Acc)
                      end
              end
      end, Init, Txs).

bump(K, M) -> maps:update_with(K, fun(V) -> V + 1 end, 1, M).

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% Pull entries from the running mempool. Returns [] if the gen_server
%% isn't up (e.g. during unit tests that drive this module directly).
safe_get_persistable_entries() ->
    try
        beamchain_mempool:get_persistable_entries()
    catch
        _:_ -> []
    end.
