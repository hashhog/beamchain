%%% Tests for the getorphantxs JSON-RPC method (Core v28 RPC-completeness gap).
%%%
%%% Mirrors Bitcoin Core rpc/mempool.cpp::getorphantxs →
%%% node/txorphanage.cpp::GetOrphanTransactions / OrphanToJSON.
%%%
%%% Proven-teeth: inserts a real orphan into the orphan pool (the public
%%% ?MEMPOOL_ORPHANS named ETS table, populated the same way the live node's
%%% insert_orphan_entry/6 does), then drives beamchain_rpc:rpc_getorphantxs/1
%%% directly (no cowboy listener) and asserts the exact field shape at
%%% verbosity 0 and 1, plus the verbosity-2 hex add-on and the
%%% out-of-range -> RPC_INVALID_PARAMETER (-8) error path.
-module(beamchain_getorphantxs_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Must match the table name + tuple shape used by beamchain_mempool's
%% insert_orphan_entry/6: {Wtxid, Tx, Expiry, Announcers, Weight}.
-define(MEMPOOL_ORPHANS, mempool_orphans).
-define(RPC_INVALID_PARAMETER, -8).

%%% ===================================================================
%%% Setup / teardown — only the orphans table is needed; get_all_orphans/0
%%% reads it directly (no gen_server).
%%% ===================================================================

setup() ->
    case ets:info(?MEMPOOL_ORPHANS) of
        undefined -> ok;
        _ -> ets:delete(?MEMPOOL_ORPHANS)
    end,
    ets:new(?MEMPOOL_ORPHANS, [set, public, named_table]),
    ok.

cleanup(_) ->
    case ets:info(?MEMPOOL_ORPHANS) of
        undefined -> ok;
        _ -> ets:delete(?MEMPOOL_ORPHANS)
    end,
    ok.

%%% ===================================================================
%%% Helpers
%%% ===================================================================

%% A witness transaction so bytes (total size) > vsize and weight is the
%% witness-discounted form — proves the size fields are real, not stubs.
make_witness_tx() ->
    TxIn = #tx_in{
        prev_out = #outpoint{hash = <<99:256>>, index = 0},
        script_sig = <<>>,
        sequence = 16#fffffffe,
        witness = [<<1, 2, 3, 4, 5, 6, 7, 8>>]
    },
    TxOut = #tx_out{value = 1000,
                    script_pubkey = <<16#00, 16#14, 0:160>>},  %% p2wpkh
    #transaction{version = 2, inputs = [TxIn], outputs = [TxOut],
                 locktime = 0}.

%% Insert one orphan exactly as the live insert_orphan_entry/6 stores it in
%% the primary table: {Wtxid, Tx, Expiry, Announcers, Weight}.
insert_orphan(Tx, Peer) ->
    Wtxid = beamchain_serialize:wtx_hash(Tx),
    Weight = beamchain_serialize:tx_weight(Tx),
    Expiry = erlang:system_time(second) + 1200,
    Announcers = ordsets:from_list([Peer]),
    ets:insert(?MEMPOOL_ORPHANS, {Wtxid, Tx, Expiry, Announcers, Weight}),
    {Wtxid, Weight}.

hashhex(Bin) ->
    beamchain_serialize:hex_encode(beamchain_serialize:reverse_bytes(Bin)).

%%% ===================================================================
%%% verbosity 0 — array of txid hex strings (Core pushes GetHash() = txid).
%%% ===================================================================

verbosity0_empty_pool_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
            ?assertEqual({ok, []}, beamchain_rpc:rpc_getorphantxs([0])),
            %% Default (no arg) == verbosity 0.
            ?assertEqual({ok, []}, beamchain_rpc:rpc_getorphantxs([]))
         end]
     end}.

verbosity0_returns_txid_hex_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
            Tx = make_witness_tx(),
            insert_orphan(Tx, 1234),
            {ok, List} = beamchain_rpc:rpc_getorphantxs([0]),
            ?assertEqual(1, length(List)),
            [Hex] = List,
            ?assert(is_binary(Hex)),
            %% Core v0 emits orphan.tx->GetHash() = the (non-witness) txid.
            ?assertEqual(hashhex(beamchain_serialize:tx_hash(Tx)), Hex)
         end]
     end}.

%%% ===================================================================
%%% verbosity 1 — array of objects with the Core OrphanToJSON shape.
%%% ===================================================================

verbosity1_field_shape_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
            Tx = make_witness_tx(),
            {_Wtxid, Weight} = insert_orphan(Tx, 1234),
            {ok, List} = beamchain_rpc:rpc_getorphantxs([1]),
            ?assertEqual(1, length(List)),
            [Obj] = List,
            ?assert(is_map(Obj)),
            %% Exactly Core's OrphanToJSON keys (no extras, no expiration).
            ?assertEqual(
               lists:sort([<<"txid">>, <<"wtxid">>, <<"bytes">>,
                           <<"vsize">>, <<"weight">>, <<"from">>]),
               lists:sort(maps:keys(Obj))),
            %% txid / wtxid are display-order hex of the right hashes.
            ?assertEqual(hashhex(beamchain_serialize:tx_hash(Tx)),
                         maps:get(<<"txid">>, Obj)),
            ?assertEqual(hashhex(beamchain_serialize:wtx_hash(Tx)),
                         maps:get(<<"wtxid">>, Obj)),
            %% bytes = total serialized size (with witness).
            ExpBytes = byte_size(beamchain_serialize:encode_transaction(Tx)),
            ?assertEqual(ExpBytes, maps:get(<<"bytes">>, Obj)),
            %% vsize / weight match the serializer's BIP-141 computation.
            ?assertEqual(beamchain_serialize:tx_vsize(Tx),
                         maps:get(<<"vsize">>, Obj)),
            ?assertEqual(Weight, maps:get(<<"weight">>, Obj)),
            ?assertEqual(beamchain_serialize:tx_weight(Tx),
                         maps:get(<<"weight">>, Obj)),
            %% Witness discount sanity: bytes (with witness) > vsize.
            ?assert(maps:get(<<"bytes">>, Obj) > maps:get(<<"vsize">>, Obj))
         end]
     end}.

verbosity1_from_array_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
            Tx = make_witness_tx(),
            insert_orphan(Tx, 4242),
            {ok, [Obj]} = beamchain_rpc:rpc_getorphantxs([1]),
            From = maps:get(<<"from">>, Obj),
            ?assert(is_list(From)),
            %% Single announcer -> 1-element array, numeric peer id (Core NodeId
            %% shape; we map the announcer term through phash2 -> integer).
            ?assertEqual(1, length(From)),
            [PeerId] = From,
            ?assert(is_integer(PeerId)),
            ?assertEqual(erlang:phash2(4242), PeerId)
         end]
     end}.

%%% ===================================================================
%%% verbosity 2 — verbosity-1 fields PLUS hex.
%%% ===================================================================

verbosity2_adds_hex_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
            Tx = make_witness_tx(),
            insert_orphan(Tx, 1),
            {ok, [Obj]} = beamchain_rpc:rpc_getorphantxs([2]),
            %% All verbosity-1 keys still present.
            ?assert(maps:is_key(<<"txid">>, Obj)),
            ?assert(maps:is_key(<<"from">>, Obj)),
            %% Plus the serialized hex (Core: EncodeHexTx).
            ?assert(maps:is_key(<<"hex">>, Obj)),
            ExpHex = beamchain_serialize:hex_encode(
                       beamchain_serialize:encode_transaction(Tx)),
            ?assertEqual(ExpHex, maps:get(<<"hex">>, Obj))
         end]
     end}.

%%% ===================================================================
%%% error path — verbosity out of 0..2 -> RPC_INVALID_PARAMETER (-8).
%%% ===================================================================

invalid_verbosity_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
        [fun() ->
            {error, Code, Msg} = beamchain_rpc:rpc_getorphantxs([3]),
            ?assertEqual(?RPC_INVALID_PARAMETER, Code),
            %% Core message: "Invalid verbosity value 3".
            ?assertEqual(<<"Invalid verbosity value 3">>, Msg)
         end,
         fun() ->
            {error, Code, _} = beamchain_rpc:rpc_getorphantxs([-1]),
            ?assertEqual(?RPC_INVALID_PARAMETER, Code)
         end]
     end}.
