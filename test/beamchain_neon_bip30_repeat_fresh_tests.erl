-module(beamchain_neon_bip30_repeat_fresh_tests).

%% Finding 16 of the Gemini (Neon) audit of beamchain against Bitcoin Core
%% v31.1 (item verify-neon-beamchain-findings).
%%
%% Mainnet blocks 91842 and 91880 repeat the coinbase txids of 91812 and
%% 91722 while those are unspent (Core IsBIP30Repeat: BIP30 is not enforced
%% for them and the new coin overwrites the old). Core adds coinbase outputs
%% with possible_overwrite = true (AddCoins, coins.cpp), so the new coin is
%% never FRESH: a later spend deletes the outpoint from disk.
%%
%% beamchain added every coinbase output with add_utxo_fresh/3. When the
%% overwritten coin had been flushed and evicted from the cache, the
%% repeat's coin was marked FRESH, a spend before the next flush only
%% dropped it from the cache, and the flush left the OLD coin on disk: a
%% spent outpoint came back.
%%
%% The test makes a regtest-shaped repeat: block 102's coinbase is
%% byte-identical to block 1's, and block 102 is listed as a BIP30
%% exception in the params (BIP34 is pushed out of the way so the identical
%% coinbase is allowed, as it was on mainnet before BIP34).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_TRUE, <<16#51>>).

bip30_repeat_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun(_) -> {timeout, 180, {Name, F}} end || {Name, F} <-
         [{"F16: a spent BIP30-repeat coinbase does not come back after flush",
           fun repeat_coinbase_spend_does_not_resurrect/0},
          {"CONTROL: the same repeat block NOT listed as an exception is bad-txns-BIP30",
           fun control_unlisted_repeat_is_bip30/0},
          {"CONTROL: a normal coinbase is still added FRESH",
           fun control_normal_coinbase_still_fresh/0}]]}.

params() ->
    P = beamchain_chain_params:params(regtest),
    P#{bip34_height => 100000000}.

repeat_coinbase_spend_does_not_resurrect() ->
    {X, Repeat} = prepare_repeat(),
    Params = (params())#{bip30_exceptions => [{102, Repeat#block.hash}]},
    ?assertEqual(ok, connect(Repeat, 102, Params)),
    %% The repeat overwrote the coin: it is now the height-102 coin.
    ?assertMatch({ok, #utxo{height = 102}}, get_utxo(X)),
    %% Spend it before any flush (as a block at 202+ would), then flush.
    {ok, _} = in_chainstate(fun() -> beamchain_chainstate:spend_utxo(element(1, X), 0) end),
    ok = beamchain_chainstate:flush(),
    %% Core: the outpoint is gone. master: block 1's coin is back on disk.
    ?assertEqual(not_found, beamchain_db:get_utxo(element(1, X), 0)),
    ets:delete(beamchain_utxo_cache, X),
    ?assertEqual(not_found, beamchain_chainstate:get_utxo(element(1, X), 0)).

control_unlisted_repeat_is_bip30() ->
    {_X, Repeat} = prepare_repeat(),
    ?assertMatch({error, bad_txns_bip30}, connect(Repeat, 102, params())).

control_normal_coinbase_still_fresh() ->
    build_chain(101),
    {ok, Prev} = beamchain_db:get_block_index(101),
    Blk = mine_block(maps:get(hash, Prev), 102, [coinbase(102)], ts(102)),
    ?assertEqual(ok, connect(Blk, 102, params())),
    Cb = beamchain_serialize:tx_hash(hd(Blk#block.transactions)),
    ?assert(ets:member(beamchain_utxo_fresh, {Cb, 0})).

%%% --- helpers -----------------------------------------------------------

%% 101 blocks, flushed; block 1's coinbase output X is on disk only (as
%% maybe_evict_cache leaves a clean entry). Returns X and a mined block 102
%% whose coinbase is block 1's coinbase, byte for byte.
prepare_repeat() ->
    build_chain(101),
    ok = beamchain_chainstate:flush(),
    {ok, #{hash := H1}} = beamchain_db:get_block_index(1),
    {ok, #block{transactions = [Cb1 | _]}} = beamchain_db:get_block(H1),
    Txid = beamchain_serialize:tx_hash(Cb1),
    X = {Txid, 0},
    ?assertMatch({ok, #utxo{height = 1}}, beamchain_db:get_utxo(Txid, 0)),
    ets:delete(beamchain_utxo_cache, X),
    {ok, Prev} = beamchain_db:get_block_index(101),
    Repeat = mine_block(maps:get(hash, Prev), 102, [Cb1], ts(102)),
    {X, Repeat}.

connect(Block, Height, Params) ->
    {ok, PrevIndex} = beamchain_db:get_block_index(Height - 1),
    in_chainstate(fun() ->
        R = beamchain_validation:connect_block(Block, Height, PrevIndex, Params),
        %% connect_block/4 leaves its undo record for its caller
        %% (do_connect_block_inner) to erase; this test is that caller.
        erase(connect_block_undo),
        R
    end).

get_utxo({Txid, Vout}) -> beamchain_chainstate:get_utxo(Txid, Vout).

%% Run Fun inside the chainstate process (the coins-cache owner).
in_chainstate(Fun) ->
    Ref = make_ref(),
    Test = self(),
    sys:replace_state(beamchain_chainstate,
                      fun(S) -> Test ! {Ref, Fun()}, S end),
    receive {Ref, R} -> R after 30000 -> error(eval_timeout) end.

ts(Height) ->
    erlang:system_time(second) - 200 * 600 + Height * 600.

coinbase(Height) ->
    HeightBin = beamchain_validation:encode_bip34_height(Height),
    ScriptSig = <<HeightBin/binary, 2, "nf", 0:32>>,
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = ScriptSig, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 5000000000, script_pubkey = ?OP_TRUE}],
        locktime = 0}.

mine_block(PrevHash, Height, Txs, Ts) ->
    TxHashes = [beamchain_serialize:tx_hash(T) || T <- Txs],
    Root = beamchain_serialize:compute_merkle_root(TxHashes),
    H0 = #block_header{version = 16#20000000, prev_hash = PrevHash,
                       merkle_root = Root, timestamp = Ts,
                       bits = 16#207fffff, nonce = 0},
    H = grind(H0, 0),
    #block{header = H, transactions = Txs,
           hash = beamchain_serialize:block_hash(H), height = Height}.

grind(H0, N) when N < 1000000 ->
    H = H0#block_header{nonce = N},
    PowLimit = maps:get(pow_limit, beamchain_chain_params:params(regtest)),
    case beamchain_pow:check_pow(beamchain_serialize:block_hash(H),
                                 H#block_header.bits, PowLimit) of
        true -> H;
        false -> grind(H0, N + 1)
    end.

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        {ok, {TipHash, H0}} = beamchain_chainstate:get_tip(),
        H = H0 + 1,
        ok = beamchain_chainstate:connect_block(
               mine_block(TipHash, H, [coinbase(H)], ts(H)))
    end, lists:seq(TipH + 1, ToHeight)).

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_neon_bip30_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    application:set_env(beamchain, fatal_halt, false),
    os:unsetenv("BEAMCHAIN_DATADIR"),
    os:unsetenv("BEAMCHAIN_NETWORK"),
    catch beamchain_fault:clear_all(),
    catch beamchain_fatal:reset_for_test(),
    catch gen_server:stop(beamchain_mempool),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_chainstate_ets(),
    {ok, _} = beamchain_config:start_link(),
    {ok, _} = beamchain_db:start_link(),
    case whereis(beamchain_sig_cache) of
        undefined -> {ok, SP} = beamchain_sig_cache:start_link(), unlink(SP);
        _ -> ok
    end,
    {ok, Pid} = beamchain_chainstate:start_link(),
    unlink(Pid),
    TmpDir.

teardown(TmpDir) ->
    catch beamchain_fault:clear_all(),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    catch beamchain_fatal:reset_for_test(),
    delete_chainstate_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

delete_chainstate_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> catch ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta]).
