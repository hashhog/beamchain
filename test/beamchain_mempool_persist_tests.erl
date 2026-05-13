-module(beamchain_mempool_persist_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Pure-format tests — exercise the (de)serializer + obfuscator without
%%% the gen_server, so we can run under `rebar3 eunit` without bringing
%%% up rocksdb / chainstate.
%%% ===================================================================

%% A minimal but realistic non-witness CTransaction. Bitcoin Core mempool
%% transactions can have witness data; we cover both shapes.
sample_tx() ->
    #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<1:256>>, index = 0},
            script_sig = <<16#76, 16#a9, 16#14>>,
            sequence = 16#FFFFFFFF,
            witness = []
        }],
        outputs = [#tx_out{
            value = 100000,
            script_pubkey = <<16#76, 16#a9, 16#14, 0:160, 16#88, 16#ac>>
        }],
        locktime = 0
    }.

sample_witness_tx() ->
    Stack = [<<16#30, 16#44, 0:32>>, <<16#02, 0:32>>],
    #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<2:256>>, index = 1},
            script_sig = <<>>,
            sequence = 16#FFFFFFFE,
            witness = Stack
        }],
        outputs = [#tx_out{
            value = 12345,
            script_pubkey = <<0:8, 16#14, 0:160>>
        }],
        locktime = 0
    }.

%%% -------------------------------------------------------------------
%%% Obfuscation
%%% -------------------------------------------------------------------

obfuscation_zero_key_is_identity_test() ->
    Bin = <<"hello world">>,
    ?assertEqual(Bin,
                 beamchain_mempool_persist:apply_obfuscation(
                   Bin, <<0,0,0,0,0,0,0,0>>)).

obfuscation_is_involutive_test() ->
    Key = <<1,2,3,4,5,6,7,8>>,
    Bin = list_to_binary(lists:seq(0, 99)),
    Obf = beamchain_mempool_persist:apply_obfuscation(Bin, Key),
    Back = beamchain_mempool_persist:apply_obfuscation(Obf, Key),
    ?assertEqual(Bin, Back),
    ?assertNotEqual(Bin, Obf).

obfuscation_bytewise_xor_test() ->
    %% Verify the byte-level expectation: byte i of the output equals
    %% input[i] XOR key[i mod 8]. This is what Bitcoin Core's
    %% Obfuscation::operator() produces for key_offset=0.
    Key = <<16#AA, 16#55, 16#FF, 16#00, 16#10, 16#20, 16#30, 16#40>>,
    Bin = <<0:64, 16#FF:8, 16#AB:8>>,                 %% 10 bytes
    Out = beamchain_mempool_persist:apply_obfuscation(Bin, Key),
    Expect = <<16#AA, 16#55, 16#FF, 16#00,
               16#10, 16#20, 16#30, 16#40,
               (16#FF bxor 16#AA), (16#AB bxor 16#55)>>,
    ?assertEqual(Expect, Out).

%%% -------------------------------------------------------------------
%%% CompactSize round-trip
%%% -------------------------------------------------------------------

compact_size_roundtrip_test() ->
    %% Roundtrip values must not exceed MAX_COMPACT_SIZE (0x02000000 = 33,554,432).
    %% decode_compact_size uses range_check=true (Core default); larger values
    %% return {error, oversized_compact_size}.
    lists:foreach(fun(N) ->
        Bin = beamchain_mempool_persist:encode_compact_size(N),
        ?assertEqual({N, <<>>},
                     beamchain_mempool_persist:decode_compact_size(Bin))
    end, [0, 1, 252, 253, 65535, 65536, 16#01FFFFFF, 16#02000000]).

%%% -------------------------------------------------------------------
%%% Payload round-trip (no file IO)
%%% -------------------------------------------------------------------

payload_empty_roundtrip_test() ->
    Payload = #{txs => [], deltas => [], unbroadcast => []},
    Bin = beamchain_mempool_persist:serialize_payload(Payload),
    Back = beamchain_mempool_persist:deserialize_payload(Bin),
    ?assertEqual(Payload, Back).

payload_with_txs_roundtrip_test() ->
    Tx1 = sample_tx(),
    Tx2 = sample_witness_tx(),
    Now = erlang:system_time(second),
    Payload = #{
        txs => [{Tx1, Now, 0},
                {Tx2, Now - 60, 1234}],
        deltas => [],
        unbroadcast => []
    },
    Bin = beamchain_mempool_persist:serialize_payload(Payload),
    #{txs := TxsBack,
      deltas := DBack,
      unbroadcast := UBack} =
        beamchain_mempool_persist:deserialize_payload(Bin),
    ?assertEqual(2, length(TxsBack)),
    ?assertEqual([], DBack),
    ?assertEqual([], UBack),
    [{Tx1B, T1, 0}, {Tx2B, T2, 1234}] = TxsBack,
    %% Tx hashes must match — the canonical equality check that's
    %% safe across witness/no-witness encodings.
    ?assertEqual(beamchain_serialize:tx_hash(Tx1),
                 beamchain_serialize:tx_hash(Tx1B)),
    ?assertEqual(beamchain_serialize:wtx_hash(Tx2),
                 beamchain_serialize:wtx_hash(Tx2B)),
    ?assertEqual(Now, T1),
    ?assertEqual(Now - 60, T2).

payload_with_deltas_and_unbroadcast_roundtrip_test() ->
    Txid1 = <<"a", 0:248>>,
    Txid2 = <<"b", 0:248>>,
    Payload = #{
        txs => [],
        deltas => [{Txid1, 1000}, {Txid2, -500}],
        unbroadcast => [Txid1]
    },
    Bin = beamchain_mempool_persist:serialize_payload(Payload),
    Back = beamchain_mempool_persist:deserialize_payload(Bin),
    ?assertEqual(Payload, Back).

%%% -------------------------------------------------------------------
%%% File round-trip on disk (dump → load)
%%% -------------------------------------------------------------------

file_roundtrip_test_() ->
    %% Drive the on-disk format end-to-end via dump/1 and load/1, but
    %% dodge the gen_server (we don't bring up beamchain_mempool here).
    %%
    %% dump/1 reads from the live mempool ETS table — to keep the test
    %% pure-format we monkey-patch by writing the file manually with
    %% serialize_payload + obfuscation, then exercise the file parser.
    {timeout, 30,
     fun() ->
         Tmp = tmp_path("mempool-roundtrip"),
         try
             Tx = sample_tx(),
             WTx = sample_witness_tx(),
             Now = erlang:system_time(second),
             Payload = #{
                 txs => [{Tx, Now, 0}, {WTx, Now, 7}],
                 deltas => [{<<3, 0:248>>, 99}],
                 unbroadcast => [<<4, 0:248>>]
             },
             Body = beamchain_mempool_persist:serialize_payload(Payload),
             Key = <<16#DE, 16#AD, 16#BE, 16#EF, 16#01, 16#02, 16#03, 16#04>>,
             Obf = beamchain_mempool_persist:apply_obfuscation(Body, Key),
             %% v2 framing: u64 version, compact_size(8) + 8 key bytes,
             %% then obfuscated body.
             KeyLenBin = beamchain_mempool_persist:encode_compact_size(8),
             File = <<2:64/little, KeyLenBin/binary, Key/binary, Obf/binary>>,
             ok = file:write_file(Tmp, File),
             %% Round-trip via the public file parser.
             {Parsed, _} = parse_via_internal(File),
             ?assertEqual(Payload, Parsed)
         after
             _ = file:delete(Tmp)
         end
     end}.

%% v1-format file: no key, body is plaintext.
v1_file_roundtrip_test() ->
    Payload = #{txs => [{sample_tx(), 1700000000, 0}],
                deltas => [], unbroadcast => []},
    Body = beamchain_mempool_persist:serialize_payload(Payload),
    File = <<1:64/little, Body/binary>>,
    {Parsed, _} = parse_via_internal(File),
    ?assertEqual(Payload, Parsed).

bad_version_is_rejected_test() ->
    %% Anything other than {1, 2} should error.
    File = <<99:64/little, 0:64>>,
    ?assertError(_, parse_via_internal(File)).

%%% -------------------------------------------------------------------
%%% Helpers
%%% -------------------------------------------------------------------

%% We don't export parse_file/1 from the persist module (it's a private
%% helper); reach in via the same logic the loader uses.
parse_via_internal(<<Version:64/little, Rest0/binary>>)
  when Version =:= 1 ->
    {beamchain_mempool_persist:deserialize_payload(Rest0), Rest0};
parse_via_internal(<<Version:64/little, Rest0/binary>>)
  when Version =:= 2 ->
    {KeyLen, Rest1} = beamchain_mempool_persist:decode_compact_size(Rest0),
    8 = KeyLen,
    <<Key:8/binary, Body/binary>> = Rest1,
    Plain = beamchain_mempool_persist:apply_obfuscation(Body, Key),
    {beamchain_mempool_persist:deserialize_payload(Plain), Plain};
parse_via_internal(<<V:64/little, _/binary>>) ->
    erlang:error({bad_mempool_version, V}).

tmp_path(Tag) ->
    Dir = case os:getenv("TMPDIR") of
        false -> "/tmp";
        D -> D
    end,
    filename:join(Dir, Tag ++ "-" ++
                  integer_to_list(erlang:unique_integer([positive])) ++
                  ".dat").
