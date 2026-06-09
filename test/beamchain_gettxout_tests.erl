%%% ===================================================================
%%% gettxout result must ALWAYS emit bestblock + confirmations.
%%%
%%% Bug (W61 "node-state-dependent, strip" convention): beamchain's
%%% gettxout builder (format_utxo_result) stripped the bestblock +
%%% confirmations fields. But Bitcoin Core's gettxout
%%% (src/rpc/blockchain.cpp) ALWAYS pushes them, and they are
%%% deterministic at a known tip:
%%%   bestblock     = active-chain tip hash (CoinsTip().GetBestBlock())
%%%   confirmations = tip_height - coin_height + 1  (0 for mempool coins)
%%%
%%% Core pushKV order: bestblock, confirmations, value, scriptPubKey,
%%% coinbase. The builder returns an ordered proplist so jsx preserves
%%% that order.
%%% ===================================================================
-module(beamchain_gettxout_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(CHAIN_META, beamchain_chain_meta).

gettxout_fields_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun({_TmpDir, _ConfigPid, TipHashHex}) ->
         %% A trivial P2WPKH-ish scriptPubKey (OP_0 <20 bytes>); the exact
         %% type doesn't matter for the bestblock/confirmations assertions.
         Script = <<16#00, 16#14, 0:160>>,
         Value = 5000000000,

         ConfirmedCoinHeight = 100,
         Confirmed = beamchain_rpc:format_utxo_result(Value, Script, true,
                                                      ConfirmedCoinHeight),
         Mempool = beamchain_rpc:format_utxo_result(Value, Script, false,
                                                    mempool),
         [
          %% --- bestblock present + equals the active tip hash (display order)
          {"bestblock field present",
           fun() ->
               ?assertEqual(TipHashHex,
                            proplists:get_value(<<"bestblock">>, Confirmed))
           end},

          %% --- confirmations = tip_height - coin_height + 1
          %% tip is at height 113 (see setup), coin at 100 -> 14
          {"confirmations = tip_height - coin_height + 1",
           fun() ->
               ?assertEqual(14,
                            proplists:get_value(<<"confirmations">>, Confirmed))
           end},

          %% --- mempool coin reports confirmations = 0 (Core MEMPOOL_HEIGHT)
          {"mempool coin -> confirmations = 0",
           fun() ->
               ?assertEqual(0,
                            proplists:get_value(<<"confirmations">>, Mempool)),
               ?assertEqual(TipHashHex,
                            proplists:get_value(<<"bestblock">>, Mempool))
           end},

          %% --- existing fields preserved
          {"coinbase + value preserved",
           fun() ->
               ?assertEqual(true,
                            proplists:get_value(<<"coinbase">>, Confirmed)),
               ?assert(proplists:get_value(<<"value">>, Confirmed) =/= undefined),
               ?assert(proplists:get_value(<<"scriptPubKey">>, Confirmed)
                       =/= undefined)
           end},

          %% --- Core pushKV field order:
          %% bestblock, confirmations, value, scriptPubKey, coinbase
          {"field order matches Core pushKV order",
           fun() ->
               Keys = [K || {K, _V} <- Confirmed],
               ?assertEqual([<<"bestblock">>, <<"confirmations">>,
                             <<"value">>, <<"scriptPubKey">>, <<"coinbase">>],
                            Keys)
           end},

          %% --- encodes to JSON object (proplist round-trips through jsx)
          {"result encodes to a JSON object via jsx",
           fun() ->
               Json = jsx:encode(Confirmed),
               ?assert(is_binary(Json)),
               Decoded = jsx:decode(Json, [return_maps]),
               ?assert(maps:is_key(<<"bestblock">>, Decoded)),
               ?assert(maps:is_key(<<"confirmations">>, Decoded))
           end}
         ]
     end}.

%%% ===================================================================
%%% Fixture: seed CHAIN_META with a tip at height 113. format_utxo_result/4
%%% reads the tip via beamchain_chainstate:get_tip/0 (a direct ETS read) and
%%% the network via beamchain_config:network/0.
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_gettxout_test_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),

    {ok, ConfigPid} = beamchain_config:start_link(),

    case ets:info(?CHAIN_META) of
        undefined ->
            ets:new(?CHAIN_META, [set, public, named_table,
                                   {keypos, 1},
                                   {read_concurrency, true}]);
        _ ->
            ets:delete_all_objects(?CHAIN_META)
    end,

    %% Tip at height 113.
    {TipHash, _} = make_block_header(113, <<113:8>>),
    true = ets:insert(?CHAIN_META, {tip, TipHash, 113}),

    %% bestblock is emitted in display (reversed) byte order, matching
    %% Core's GetBlockHash().GetHex() and beamchain's getbestblockhash.
    TipHashHex = beamchain_serialize:hex_encode(
                   beamchain_serialize:reverse_bytes(TipHash)),

    {TmpDir, ConfigPid, TipHashHex}.

teardown({TmpDir, _ConfigPid, _Hex}) ->
    catch gen_server:stop(beamchain_config),
    catch ets:delete(?CHAIN_META),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

make_block_header(Height, Salt) ->
    Header = #block_header{
        version     = 1,
        prev_hash   = <<Height:32/big, 0:224>>,
        merkle_root = <<Salt/binary, 0:(32*8 - bit_size(Salt))>>,
        timestamp   = 1700000000 + Height,
        bits        = 16#1d00ffff,
        nonce       = Height
    },
    Hash = beamchain_serialize:block_hash(Header),
    {Hash, Header}.
