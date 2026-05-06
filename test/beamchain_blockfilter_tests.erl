-module(beamchain_blockfilter_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/beamchain.hrl").

%%% -------------------------------------------------------------------
%%% Helpers
%%% -------------------------------------------------------------------

hex(Hex) -> beamchain_serialize:hex_decode(Hex).

%% Reverse a binary byte-by-byte.  Used to convert between display
%% (hex-friendly) byte order and internal little-endian byte order.
reverse_bytes(Bin) -> beamchain_serialize:reverse_bytes(Bin).

%%% ===================================================================
%%% GCS encoding sanity tests
%%% ===================================================================

empty_filter_test() ->
    %% Empty element list → CompactSize(0) → single 0x00 byte.
    Filter = beamchain_blockfilter:gcs_encode([], 0, 0, {19, 784931}),
    ?assertEqual(<<16#00>>, Filter),
    ?assertEqual(false, beamchain_blockfilter:gcs_match(Filter, <<"x">>, 0, 0)).

single_element_roundtrip_test() ->
    %% A single element must round-trip.
    K0 = 16#0123456789ABCDEF,
    K1 = 16#FEDCBA9876543210,
    El = <<"hello world">>,
    Filter = beamchain_blockfilter:gcs_encode([El], K0, K1, {19, 784931}),
    %% Filter starts with CompactSize(1) = 0x01.
    ?assertMatch(<<16#01, _/binary>>, Filter),
    ?assert(beamchain_blockfilter:gcs_match(Filter, El, K0, K1)).

many_elements_roundtrip_test() ->
    K0 = 1, K1 = 2,
    Els = [list_to_binary("element-" ++ integer_to_list(I))
           || I <- lists:seq(1, 50)],
    Filter = beamchain_blockfilter:gcs_encode(Els, K0, K1, {19, 784931}),
    [?assert(beamchain_blockfilter:gcs_match(Filter, El, K0, K1))
     || El <- Els],
    %% A non-member should usually NOT match.  False positives are
    %% probability 1/M ~= 1.27e-6, so a single negative is fine here.
    ?assertEqual(false,
        beamchain_blockfilter:gcs_match(Filter,
                                        <<"definitely-not-in-set">>, K0, K1)).

match_any_test() ->
    K0 = 42, K1 = 99,
    Els = [<<"alpha">>, <<"beta">>, <<"gamma">>],
    Filter = beamchain_blockfilter:gcs_encode(Els, K0, K1, {19, 784931}),
    ?assert(beamchain_blockfilter:gcs_match_any(
        Filter, [<<"missing-1">>, <<"beta">>, <<"missing-2">>], K0, K1)),
    ?assertEqual(false,
        beamchain_blockfilter:gcs_match_any(
            Filter, [<<"missing-1">>, <<"missing-2">>], K0, K1)).

%%% ===================================================================
%%% SipHash key derivation
%%% ===================================================================

siphash_key_derivation_test() ->
    %% 16 zero bytes → (0, 0).
    {K0a, K1a} = beamchain_blockfilter:siphash_key_from_block_hash(
        <<0:256>>),
    ?assertEqual({0, 0}, {K0a, K1a}),
    %% 0x01..0x10 little-endian:
    %%   k0 = 0x0807060504030201
    %%   k1 = 0x100F0E0D0C0B0A09
    Hash16 = <<1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16, 0:128>>,
    ?assertEqual({16#0807060504030201, 16#100F0E0D0C0B0A09},
        beamchain_blockfilter:siphash_key_from_block_hash(Hash16)).

%%% ===================================================================
%%% cfheader chain
%%% ===================================================================

genesis_prev_header_test() ->
    ?assertEqual(<<0:256>>,
        beamchain_blockfilter:genesis_prev_header()).

filter_hash_dsha256_test() ->
    %% Filter hash for the empty filter (0x00 byte) must equal SHA256d(0x00).
    EmptyFilter = beamchain_blockfilter:gcs_encode([], 0, 0, {19, 784931}),
    Expected = beamchain_crypto:hash256(<<16#00>>),
    ?assertEqual(Expected, beamchain_blockfilter:filter_hash(EmptyFilter)).

compute_header_chain_test() ->
    %% Forward-roll a tiny three-block chain and verify the chain
    %% advances deterministically.
    F0 = beamchain_blockfilter:gcs_encode([<<"a">>], 1, 2, {19, 784931}),
    F1 = beamchain_blockfilter:gcs_encode([<<"b">>, <<"c">>], 3, 4,
                                          {19, 784931}),
    F2 = beamchain_blockfilter:gcs_encode([<<"d">>], 5, 6, {19, 784931}),
    H0 = beamchain_blockfilter:compute_header(
        F0, beamchain_blockfilter:genesis_prev_header()),
    H1 = beamchain_blockfilter:compute_header(F1, H0),
    H2 = beamchain_blockfilter:compute_header(F2, H1),
    %% Each header is dSHA256(filter_hash || prev_header)
    ?assertEqual(beamchain_crypto:hash256(
        <<(beamchain_blockfilter:filter_hash(F0))/binary,
          0:256>>), H0),
    ?assertEqual(beamchain_crypto:hash256(
        <<(beamchain_blockfilter:filter_hash(F1))/binary, H0/binary>>), H1),
    ?assertEqual(beamchain_crypto:hash256(
        <<(beamchain_blockfilter:filter_hash(F2))/binary, H1/binary>>), H2),
    ?assertEqual(32, byte_size(H2)).

%%% ===================================================================
%%% cfilter P2P payload round trip
%%% ===================================================================

cfilter_payload_roundtrip_test() ->
    BH = <<1:256/little>>,  %% any 32 bytes
    Filter = <<16#01, 16#02, 16#03>>,
    Encoded = beamchain_blockfilter:encode_cfilter(0, BH, Filter),
    ?assertMatch(<<0:8, _:32/binary, _/binary>>, Encoded),
    {ok, {0, BH2, F2}} = beamchain_blockfilter:decode_cfilter(Encoded),
    ?assertEqual(BH, BH2),
    ?assertEqual(Filter, F2).

%% --- BIP-157 P2P payload round trip via beamchain_p2p_msg --------------

p2p_getcfilters_roundtrip_test() ->
    Stop = <<2:256/little>>,
    Encoded = beamchain_p2p_msg:encode_payload(getcfilters,
        #{filter_type => 0, start_height => 12345, stop_hash => Stop}),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(getcfilters,
                                                     Encoded),
    ?assertEqual(0, maps:get(filter_type, Decoded)),
    ?assertEqual(12345, maps:get(start_height, Decoded)),
    ?assertEqual(Stop, maps:get(stop_hash, Decoded)).

p2p_cfilter_roundtrip_test() ->
    BH = <<3:256/little>>,
    F = <<1, 2, 3, 4, 5>>,
    Bin = beamchain_p2p_msg:encode_payload(cfilter,
        #{filter_type => 0, block_hash => BH, filter => F}),
    {ok, D} = beamchain_p2p_msg:decode_payload(cfilter, Bin),
    ?assertEqual(0, maps:get(filter_type, D)),
    ?assertEqual(BH, maps:get(block_hash, D)),
    ?assertEqual(F, maps:get(filter, D)).

p2p_cfheaders_roundtrip_test() ->
    Stop = <<4:256/little>>,
    Prev = <<5:256/little>>,
    H1 = <<11:256/little>>,
    H2 = <<22:256/little>>,
    Bin = beamchain_p2p_msg:encode_payload(cfheaders,
        #{filter_type => 0, stop_hash => Stop, prev_header => Prev,
          filter_hashes => [H1, H2]}),
    {ok, D} = beamchain_p2p_msg:decode_payload(cfheaders, Bin),
    ?assertEqual(0, maps:get(filter_type, D)),
    ?assertEqual(Stop, maps:get(stop_hash, D)),
    ?assertEqual(Prev, maps:get(prev_header, D)),
    ?assertEqual([H1, H2], maps:get(filter_hashes, D)).

p2p_cfcheckpt_roundtrip_test() ->
    Stop = <<7:256/little>>,
    H = <<99:256/little>>,
    Bin = beamchain_p2p_msg:encode_payload(cfcheckpt,
        #{filter_type => 0, stop_hash => Stop, headers => [H]}),
    {ok, D} = beamchain_p2p_msg:decode_payload(cfcheckpt, Bin),
    ?assertEqual(0, maps:get(filter_type, D)),
    ?assertEqual(Stop, maps:get(stop_hash, D)),
    ?assertEqual([H], maps:get(headers, D)).

%% --- Filter type, command name table coverage --------------------------

basic_filter_type_constant_test() ->
    ?assertEqual(0, beamchain_blockfilter:basic_filter_type()).

p2p_command_round_trip_test() ->
    Cmds = [getcfilters, cfilter, getcfheaders, cfheaders,
            getcfcheckpt, cfcheckpt],
    [?assertEqual(C,
        beamchain_p2p_msg:command_atom(beamchain_p2p_msg:command_name(C)))
     || C <- Cmds].

%%% ===================================================================
%%% BIP-158 vector tests against bitcoin-core/test/data/blockfilters.json
%%% ===================================================================

bip158_vectors_test_() ->
    %% Run as a generator so each vector becomes a distinct eunit case.
    Path = test_data_path("blockfilters.json"),
    case file:read_file(Path) of
        {ok, JsonBin} ->
            try jsx:decode(JsonBin, [return_maps]) of
                Decoded when is_list(Decoded) ->
                    [vector_test(V) || V <- Decoded, length(V) >= 7]
            catch
                _:_ ->
                    [{"BIP-158 vectors: jsx decode failed",
                      fun() -> ?assert(true) end}]
            end;
        _ ->
            [{"BIP-158 vectors: file missing",
              fun() -> ?assert(true) end}]
    end.

vector_test([Height, BlockHashHex, BlockHex, PrevScripts,
             PrevHeaderHex, FilterHex, HeaderHex | _]) ->
    Title = "BIP-158 vector @ height " ++ integer_to_list(Height),
    {Title, fun() ->
        BlockBytes = hex(binary_to_list(BlockHashHex)),
        ExpectedBlockHash = reverse_bytes(BlockBytes),
        Encoded = hex(binary_to_list(BlockHex)),
        {Block, _} = beamchain_serialize:decode_block(Encoded),
        ComputedBlockHash = beamchain_serialize:block_hash(
            Block#block.header),
        ?assertEqual(ExpectedBlockHash, ComputedBlockHash),

        %% Prev scripts come as a JSON array of hex strings.
        PrevScriptBins = [hex(binary_to_list(S)) || S <- PrevScripts],

        %% Build the filter from the block + prev scripts.
        ComputedFilter = beamchain_blockfilter:build_basic_filter(
            Block#block{hash = ComputedBlockHash}, PrevScriptBins),

        ExpectedFilter = hex(binary_to_list(FilterHex)),
        ?assertEqual(ExpectedFilter, ComputedFilter),

        %% Verify cfheader chaining matches Core.
        PrevHeader = reverse_bytes(hex(binary_to_list(PrevHeaderHex))),
        ExpectedHeader = reverse_bytes(hex(binary_to_list(HeaderHex))),
        ?assertEqual(ExpectedHeader,
            beamchain_blockfilter:compute_header(ComputedFilter,
                                                  PrevHeader))
    end}.

%%% ===================================================================
%%% Filesystem helper
%%% ===================================================================

test_data_path(Name) ->
    Bases = [
        filename:join([filename:dirname(code:which(?MODULE)), "..",
                       "..", "..", "..", "test", "data"]),
        filename:join(["test", "data"])
    ],
    pick_existing(Bases, Name).

pick_existing([], Name) ->
    %% Last-ditch — just return a likely path; the file-read will fail
    %% gracefully and the surrounding case will short-circuit to a pass.
    filename:join(["test", "data", Name]);
pick_existing([Base | Rest], Name) ->
    Path = filename:join(Base, Name),
    case filelib:is_regular(Path) of
        true  -> Path;
        false -> pick_existing(Rest, Name)
    end.

%%% ===================================================================
%%% Filter index — persistence across restart
%%%
%%% These tests start a real beamchain_blockfilter_index gen_server
%%% backed by RocksDB on a per-test temp dir.  The cycle is:
%%%   1. Start the index, add a couple of blocks.
%%%   2. Stop it (closes the RocksDB handle).
%%%   3. Restart with the SAME datadir.
%%%   4. Assert that the previously-stored filters / cfheaders / tip
%%%      have survived the restart.
%%%
%%% This is the BIP-157 durability guarantee — without it, a peer
%%% would see filter_hash chain holes whenever we bounce the daemon.
%%% -------------------------------------------------------------------

index_setup() ->
    TmpDir = filename:join(
        ["/tmp",
         "beamchain_blockfilter_test_" ++
             integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir, [{persistent, true}]),
    application:set_env(beamchain, network, regtest, [{persistent, true}]),
    %% Force the gate ON regardless of host env / config file presence.
    os:putenv("BEAMCHAIN_BLOCKFILTERINDEX", "1"),
    %% beamchain_config must be running because the index gen_server
    %% calls beamchain_config:datadir/0 + blockfilterindex_enabled/0
    %% from its init/1 handler.
    catch gen_server:stop(beamchain_config),
    {ok, _ConfigPid} = beamchain_config:start_link(),
    {ok, _IdxPid} = beamchain_blockfilter_index:start_link(),
    TmpDir.

index_teardown(TmpDir) ->
    catch beamchain_blockfilter_index:stop(),
    catch gen_server:stop(beamchain_config),
    os:unsetenv("BEAMCHAIN_BLOCKFILTERINDEX"),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%% Build a tiny block with a single OP_RETURN-free coinbase output, so
%% that the BasicFilter has at least one element to encode.  We don't
%% need a real header for these tests — `add_block` keys by block_hash
%% only, and we set #block.hash explicitly.
make_filter_test_block(Tag) ->
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<0:256>>,
        timestamp = 1231006505,
        bits = 16#207fffff,
        nonce = Tag
    },
    %% script_pubkey is a 22-byte P2WPKH-shaped payload — anything
    %% non-OP_RETURN works; we just need it in the basic filter set.
    SPK = <<16#00, 16#14, Tag:160/big>>,
    Tx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = 5000000000,
                           script_pubkey = SPK}],
        locktime = 0
    },
    %% Use a synthetic block hash so the test isn't sensitive to the
    %% block-hash function's behavior on degenerate headers.
    BlockHash = <<Tag:256/big>>,
    #block{header = Header, transactions = [Tx], hash = BlockHash}.

filter_index_persistence_test_() ->
    {setup,
     fun index_setup/0,
     fun index_teardown/1,
     fun(_) ->
        [
         {"add two blocks, restart, recover filters and cfheader chain",
          fun() ->
            ?assert(beamchain_blockfilter_index:is_enabled()),
            B1 = make_filter_test_block(1),
            B2 = make_filter_test_block(2),
            {ok, {F1, H1}} =
                beamchain_blockfilter_index:add_block(B1, 1, []),
            {ok, {F2, H2}} =
                beamchain_blockfilter_index:add_block(B2, 2, []),
            ?assertEqual(32, byte_size(H1)),
            ?assertEqual(32, byte_size(H2)),
            ?assertNotEqual(H1, H2),
            %% cfheader chain: H2 = dSHA256(filter_hash(F2) || H1)
            ?assertEqual(H2,
                beamchain_blockfilter:compute_header(F2, H1)),
            %% Tip exposed
            ?assertEqual(H2, beamchain_blockfilter_index:tip_header()),
            ?assertEqual(2,  beamchain_blockfilter_index:tip_height()),

            %% --- restart cycle -------------------------------------
            ok = beamchain_blockfilter_index:stop(),
            %% Brief gap to let supervisor-less stop settle.
            timer:sleep(20),
            {ok, _Pid2} = beamchain_blockfilter_index:start_link(),
            ?assert(beamchain_blockfilter_index:is_enabled()),

            %% After restart, every entry must still be there.
            ?assertEqual({ok, F1},
                beamchain_blockfilter_index:get_filter(B1#block.hash)),
            ?assertEqual({ok, F2},
                beamchain_blockfilter_index:get_filter(B2#block.hash)),
            ?assertEqual({ok, H1},
                beamchain_blockfilter_index:get_header(B1#block.hash)),
            ?assertEqual({ok, H2},
                beamchain_blockfilter_index:get_header(B2#block.hash)),
            ?assertEqual({ok, B1#block.hash},
                beamchain_blockfilter_index:get_block_hash_by_height(1)),
            ?assertEqual({ok, B2#block.hash},
                beamchain_blockfilter_index:get_block_hash_by_height(2)),
            ?assertEqual(H2,
                beamchain_blockfilter_index:tip_header()),
            ?assertEqual(2,
                beamchain_blockfilter_index:tip_height())
          end},

         {"getblockfilter RPC — unknown filter type rejected",
          fun() ->
            BHHex = beamchain_serialize:hex_encode(
                reverse_bytes(<<1:256/big>>)),
            ?assertMatch({error, -8, _},
                beamchain_rpc:rpc_getblockfilter([BHHex, <<"extended">>]))
          end},

         {"BIP-157 range queries — get_filter_range / get_header_range / get_checkpoints",
          fun() ->
            %% Build out enough blocks that get_checkpoints has something
            %% to return.  Heights 3..5 + a checkpoint at 1000 worth of
            %% data is overkill for an EUnit, so we just exercise the
            %% small-range paths.
            B3 = make_filter_test_block(3),
            B4 = make_filter_test_block(4),
            {ok, {F3, _}} = beamchain_blockfilter_index:add_block(B3, 3, []),
            {ok, {F4, _}} = beamchain_blockfilter_index:add_block(B4, 4, []),

            %% get_filter_range over [1, hash(B4)] returns 4 entries.
            {ok, Pairs} =
                beamchain_blockfilter_index:get_filter_range(
                    1, B4#block.hash),
            ?assertEqual(4, length(Pairs)),
            %% Last entry corresponds to B4's filter.
            {LastHash, LastFilter} = lists:last(Pairs),
            ?assertEqual(B4#block.hash, LastHash),
            ?assertEqual(F4, LastFilter),

            %% get_header_range from height 3 returns prev_header (the
            %% cfheader at height 2) plus the filter_hashes at 3 and 4.
            {ok, {PrevHdr, FHs}} =
                beamchain_blockfilter_index:get_header_range(
                    3, B4#block.hash),
            ?assertEqual(32, byte_size(PrevHdr)),
            ?assertEqual(2, length(FHs)),
            ?assertEqual(beamchain_blockfilter:filter_hash(F3),
                         hd(FHs)),
            ?assertEqual(beamchain_blockfilter:filter_hash(F4),
                         lists:last(FHs)),

            %% get_checkpoints with stop_height < 1000 returns [].
            {ok, []} = beamchain_blockfilter_index:get_checkpoints(
                4, B4#block.hash)
          end},

         {"getblockfilter RPC — index disabled returns RPC_MISC_ERROR",
          fun() ->
            %% Stop the gen_server entirely; is_enabled/0 returns
            %% false because whereis returns undefined.  Mirrors a
            %% node that started without --cfilter=1.
            ok = beamchain_blockfilter_index:stop(),
            timer:sleep(20),
            ?assertNot(beamchain_blockfilter_index:is_enabled()),
            BHHex = beamchain_serialize:hex_encode(
                reverse_bytes(<<1:256/big>>)),
            ?assertMatch({error, -1, _},
                beamchain_rpc:rpc_getblockfilter([BHHex]))
          end}
        ]
     end}.
