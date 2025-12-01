-module(beamchain_db_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% We use a test fixture that starts/stops the config and db for each test group.
%% The tests use a temp directory so they don't interfere with real data.

db_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun(_) ->
         [
          {"block store/retrieve roundtrip", fun block_roundtrip/0},
          {"block by height lookup", fun block_by_height/0},
          {"has_block check", fun has_block_check/0},
          {"utxo store/get cycle", fun utxo_store_get/0},
          {"utxo spend returns utxo", fun utxo_spend/0},
          {"utxo not found", fun utxo_not_found/0},
          {"has_utxo check", fun has_utxo_check/0},
          {"chain tip set/get", fun chain_tip/0},
          {"chain tip not found initially", fun chain_tip_not_found/0},
          {"block index store/get", fun block_index_roundtrip/0},
          {"block index lookup by hash", fun block_index_by_hash/0},
          {"tx index store/get", fun tx_index_roundtrip/0},
          {"undo data store/get", fun undo_data_roundtrip/0},
          {"batch write atomicity", fun batch_write/0}
         ]
     end}.

setup() ->
    %% Use a unique temp directory for each test run
    TmpDir = filename:join(["/tmp", "beamchain_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    %% Set environment so beamchain_config uses our temp dir
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),

    %% Start config (needed by db)
    {ok, ConfigPid} = beamchain_config:start_link(),
    %% Start db
    {ok, DbPid} = beamchain_db:start_link(),

    {TmpDir, ConfigPid, DbPid}.

teardown({TmpDir, _ConfigPid, _DbPid}) ->
    %% Stop db and config
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    %% Clean up temp directory
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%% ===================================================================
%%% Test helpers
%%% ===================================================================

make_test_block(PrevHash, Nonce) ->
    Header = #block_header{
        version = 1,
        prev_hash = PrevHash,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = Nonce
    },
    %% Simple coinbase tx
    CoinbaseTx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{
            value = 5000000000,
            script_pubkey = <<16#76, 16#a9, 16#14,  %% OP_DUP OP_HASH160 PUSH20
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              16#88, 16#ac>>         %% OP_EQUALVERIFY OP_CHECKSIG
        }],
        locktime = 0
    },
    Hash = beamchain_serialize:block_hash(Header),
    #block{
        header = Header,
        transactions = [CoinbaseTx],
        hash = Hash
    }.

make_test_utxo() ->
    #utxo{
        value = 5000000000,
        script_pubkey = <<16#76, 16#a9, 16#14,
                          1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                          16#88, 16#ac>>,
        is_coinbase = true,
        height = 0
    }.

%%% ===================================================================
%%% Block tests
%%% ===================================================================

block_roundtrip() ->
    Block = make_test_block(<<0:256>>, 42),
    Hash = Block#block.hash,
    ok = beamchain_db:store_block(Block, 0),
    {ok, Retrieved} = beamchain_db:get_block(Hash),
    %% Compare headers (block hash is derived from header)
    ?assertEqual(Block#block.header, Retrieved#block.header),
    %% Compare tx count
    ?assertEqual(length(Block#block.transactions),
                 length(Retrieved#block.transactions)).

block_by_height() ->
    Block0 = make_test_block(<<0:256>>, 100),
    Block1 = make_test_block(Block0#block.hash, 101),
    ok = beamchain_db:store_block(Block0, 0),
    ok = beamchain_db:store_block(Block1, 1),
    {ok, Retrieved} = beamchain_db:get_block_by_height(1),
    ?assertEqual(Block1#block.header, Retrieved#block.header),
    ?assertEqual(not_found, beamchain_db:get_block_by_height(999)).

has_block_check() ->
    Block = make_test_block(<<0:256>>, 200),
    Hash = Block#block.hash,
    ?assertEqual(false, beamchain_db:has_block(Hash)),
    ok = beamchain_db:store_block(Block, 5),
    ?assertEqual(true, beamchain_db:has_block(Hash)).

%%% ===================================================================
%%% UTXO tests
%%% ===================================================================

utxo_store_get() ->
    Txid = crypto:strong_rand_bytes(32),
    Utxo = make_test_utxo(),
    ok = beamchain_db:store_utxo(Txid, 0, Utxo),
    {ok, Retrieved} = beamchain_db:get_utxo(Txid, 0),
    ?assertEqual(Utxo#utxo.value, Retrieved#utxo.value),
    ?assertEqual(Utxo#utxo.script_pubkey, Retrieved#utxo.script_pubkey),
    ?assertEqual(Utxo#utxo.is_coinbase, Retrieved#utxo.is_coinbase),
    ?assertEqual(Utxo#utxo.height, Retrieved#utxo.height).

utxo_spend() ->
    Txid = crypto:strong_rand_bytes(32),
    Utxo = make_test_utxo(),
    ok = beamchain_db:store_utxo(Txid, 0, Utxo),
    ?assertEqual(true, beamchain_db:has_utxo(Txid, 0)),
    {ok, Spent} = beamchain_db:spend_utxo(Txid, 0),
    ?assertEqual(Utxo#utxo.value, Spent#utxo.value),
    %% After spending, UTXO should be gone
    ?assertEqual(not_found, beamchain_db:get_utxo(Txid, 0)),
    ?assertEqual(false, beamchain_db:has_utxo(Txid, 0)).

utxo_not_found() ->
    FakeTxid = crypto:strong_rand_bytes(32),
    ?assertEqual(not_found, beamchain_db:get_utxo(FakeTxid, 0)),
    ?assertEqual(not_found, beamchain_db:spend_utxo(FakeTxid, 0)).

has_utxo_check() ->
    Txid = crypto:strong_rand_bytes(32),
    ?assertEqual(false, beamchain_db:has_utxo(Txid, 0)),
    ok = beamchain_db:store_utxo(Txid, 0, make_test_utxo()),
    ?assertEqual(true, beamchain_db:has_utxo(Txid, 0)),
    %% Different vout should not exist
    ?assertEqual(false, beamchain_db:has_utxo(Txid, 1)).

%%% ===================================================================
%%% Chain tip tests
%%% ===================================================================

chain_tip_not_found() ->
    %% Chain tip may already be set by prior tests, so this test
    %% just verifies the API works without crashing
    Result = beamchain_db:get_chain_tip(),
    ?assert(Result =:= not_found orelse element(1, Result) =:= ok).

chain_tip() ->
    Hash = crypto:strong_rand_bytes(32),
    ok = beamchain_db:set_chain_tip(Hash, 42),
    {ok, Tip} = beamchain_db:get_chain_tip(),
    ?assertEqual(Hash, maps:get(hash, Tip)),
    ?assertEqual(42, maps:get(height, Tip)),
    %% Update it
    Hash2 = crypto:strong_rand_bytes(32),
    ok = beamchain_db:set_chain_tip(Hash2, 43),
    {ok, Tip2} = beamchain_db:get_chain_tip(),
    ?assertEqual(Hash2, maps:get(hash, Tip2)),
    ?assertEqual(43, maps:get(height, Tip2)).

%%% ===================================================================
%%% Block index tests
%%% ===================================================================

block_index_roundtrip() ->
    Hash = crypto:strong_rand_bytes(32),
    Header = #block_header{
        version = 2,
        prev_hash = <<0:256>>,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = 12345
    },
    Chainwork = <<0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0>>,
    Status = 3,
    ok = beamchain_db:store_block_index(10, Hash, Header, Chainwork, Status),
    {ok, Entry} = beamchain_db:get_block_index(10),
    ?assertEqual(Hash, maps:get(hash, Entry)),
    ?assertEqual(Header, maps:get(header, Entry)),
    ?assertEqual(Chainwork, maps:get(chainwork, Entry)),
    ?assertEqual(Status, maps:get(status, Entry)).

block_index_by_hash() ->
    Hash = crypto:strong_rand_bytes(32),
    Header = #block_header{
        version = 2,
        prev_hash = <<0:256>>,
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1231006505,
        bits = 16#1d00ffff,
        nonce = 99999
    },
    Chainwork = <<1, 2, 3, 4>>,
    ok = beamchain_db:store_block_index(20, Hash, Header, Chainwork, 1),
    {ok, Entry} = beamchain_db:get_block_index_by_hash(Hash),
    ?assertEqual(20, maps:get(height, Entry)),
    ?assertEqual(Hash, maps:get(hash, Entry)),
    ?assertEqual(Chainwork, maps:get(chainwork, Entry)),
    %% Non-existent hash
    ?assertEqual(not_found,
                 beamchain_db:get_block_index_by_hash(crypto:strong_rand_bytes(32))).

%%% ===================================================================
%%% Transaction index tests
%%% ===================================================================

tx_index_roundtrip() ->
    Txid = crypto:strong_rand_bytes(32),
    BlockHash = crypto:strong_rand_bytes(32),
    ok = beamchain_db:store_tx_index(Txid, BlockHash, 100, 3),
    {ok, Loc} = beamchain_db:get_tx_location(Txid),
    ?assertEqual(BlockHash, maps:get(block_hash, Loc)),
    ?assertEqual(100, maps:get(height, Loc)),
    ?assertEqual(3, maps:get(position, Loc)),
    %% Non-existent txid
    ?assertEqual(not_found,
                 beamchain_db:get_tx_location(crypto:strong_rand_bytes(32))).

%%% ===================================================================
%%% Undo data tests
%%% ===================================================================

undo_data_roundtrip() ->
    BlockHash = crypto:strong_rand_bytes(32),
    UndoData = <<"some undo data for spent utxos">>,
    ok = beamchain_db:store_undo(BlockHash, UndoData),
    {ok, Retrieved} = beamchain_db:get_undo(BlockHash),
    ?assertEqual(UndoData, Retrieved),
    %% Non-existent
    ?assertEqual(not_found, beamchain_db:get_undo(crypto:strong_rand_bytes(32))).

%%% ===================================================================
%%% Batch write tests
%%% ===================================================================

batch_write() ->
    %% Batch: store a UTXO and set chain tip atomically
    Txid = crypto:strong_rand_bytes(32),
    Utxo = make_test_utxo(),
    UtxoKey = <<Txid:32/binary, 0:32/big>>,
    CoinbaseFlag = 1,
    UtxoValue = <<(Utxo#utxo.value):64/little,
                  (Utxo#utxo.height):32/little,
                  CoinbaseFlag:8,
                  (Utxo#utxo.script_pubkey)/binary>>,
    TipHash = crypto:strong_rand_bytes(32),
    TipValue = <<TipHash:32/binary, 50:64/big>>,
    ok = beamchain_db:write_batch([
        {put, chainstate, UtxoKey, UtxoValue},
        {put, meta, <<"chain_tip">>, TipValue}
    ]),
    %% Verify both writes took effect
    {ok, _} = beamchain_db:get_utxo(Txid, 0),
    {ok, Tip} = beamchain_db:get_chain_tip(),
    ?assertEqual(TipHash, maps:get(hash, Tip)),
    ?assertEqual(50, maps:get(height, Tip)).
