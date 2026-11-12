-module(beamchain_fundraw_immature_coinbase_tests).

%%% Automatic coin selection never picks an immature coinbase, as in Core.
%%%
%%% Core v31.1:
%%%   wallet/spend.cpp:357   AvailableCoins skips IsTxImmatureCoinBase(wtx)
%%%                          unless include_immature_coinbase (default false);
%%%                          every coin-selection caller (FundTransaction for
%%%                          fundrawtransaction / walletcreatefundedpsbt /
%%%                          send, CreateTransaction for sendtoaddress) goes
%%%                          through it.
%%%   wallet/wallet.cpp      a coinbase is immature while it has fewer than
%%%                          COINBASE_MATURITY+1 (101) confirmations.
%%%   wallet/rpc/spend.cpp   FundTransaction failure -> RPC_WALLET_ERROR (-4)
%%%                          "Insufficient funds".
%%%
%%% Fixture: the regtest shape "generatetoaddress 101 <wallet addr>": one
%%% 50 BTC coinbase at each height 1..101, tip 101. Only the height-1
%%% coinbase (101 confirmations) is spendable: 50 BTC.
%%%
%%% The coins are written into the real wallet UTXO ETS table (not a mock)
%%% so the same file runs unchanged against master, where fundrawtransaction
%%% read the raw table and funded a 75 BTC spend with immature coinbases.
%%%
%%% CONTROL: `rebar3 eunit --module=beamchain_fundraw_immature_coinbase_tests`

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(TIP, 101).
-define(UTXO_TABLE, beamchain_wallet_utxos).
-define(MOCKED, [beamchain_wallet, beamchain_wallet_sup,
                 beamchain_chainstate, beamchain_config]).

%%% ===================================================================
%%% fixture
%%% ===================================================================

p2wpkh(N) -> <<0, 20, N:160>>.

cb_txid(H) -> <<H:256>>.

setup() ->
    Created = case ets:whereis(?UTXO_TABLE) of
        undefined ->
            ets:new(?UTXO_TABLE, [named_table, set, public]),
            true;
        _ ->
            false
    end,
    Saved = ets:tab2list(?UTXO_TABLE),
    ets:delete_all_objects(?UTXO_TABLE),
    lists:foreach(
      fun(H) ->
          ets:insert(?UTXO_TABLE,
                     {{cb_txid(H), 0}, {5000000000, p2wpkh(H), H, true}})
      end, lists:seq(1, ?TIP)),
    try
        lists:foreach(fun(M) -> meck:new(M, [passthrough, no_link]) end,
                      ?MOCKED)
    catch C:R:St ->
        %% eunit skips cleanup when setup fails: undo the fixture here.
        cleanup({Created, Saved}),
        erlang:raise(C, R, St)
    end,
    WalletPid = self(),
    meck:expect(beamchain_wallet_sup, list_wallets, fun() -> [<<"w">>] end),
    meck:expect(beamchain_wallet_sup, get_wallet,
                fun(_) -> {ok, WalletPid} end),
    meck:expect(beamchain_wallet, list_locked_coins, fun(_) -> [] end),
    meck:expect(beamchain_wallet, get_change_address,
                fun(_, _) -> {ok, change_address()} end),
    meck:expect(beamchain_chainstate, get_tip_height, fun() -> {ok, ?TIP} end),
    meck:expect(beamchain_chainstate, get_tip,
                fun() -> {ok, {<<0:256>>, ?TIP}} end),
    meck:expect(beamchain_config, network, fun() -> regtest end),
    {Created, Saved}.

cleanup({Created, Saved}) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKED),
    case Created of
        true -> ets:delete(?UTXO_TABLE);
        false ->
            ets:delete_all_objects(?UTXO_TABLE),
            ets:insert(?UTXO_TABLE, Saved)
    end.

change_address() ->
    beamchain_address:script_to_address(p2wpkh(16#cccc), regtest).

dest_address() ->
    list_to_binary(beamchain_address:script_to_address(p2wpkh(16#dddd), regtest)).

%% createrawtransaction [<foreign input>] {dest: Sats}. The raw tx carries
%% one input the wallet does not own: beamchain cannot yet decode a ZERO-input
%% raw tx for funding (the 0x00 input count is read as the segwit marker;
%% Core's DecodeHexTx retries without witness), a separate defect. The
%% foreign input is not credited toward the target, so the selector must
%% still find the full output amount in wallet coins.
foreign_input() ->
    #tx_in{prev_out = #outpoint{hash = <<16#eeee:256>>, index = 0},
           script_sig = <<>>, sequence = 16#fffffffd, witness = []}.

raw_hex(Sats) ->
    Tx = #transaction{version = 2, inputs = [foreign_input()],
                      outputs = [#tx_out{value = Sats,
                                         script_pubkey = p2wpkh(16#dddd)}],
                      locktime = 0},
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(Tx)).

%% Core accepts fee_rate in sat/vB; set it so no fee estimator is consulted.
fund(Sats) ->
    case beamchain_rpc:rpc_fundrawtransaction(
           [raw_hex(Sats), #{<<"fee_rate">> => 1}], undefined) of
        {ok_raw_json, Bin} -> {ok, jsx:decode(Bin, [return_maps])};
        Other -> Other
    end.

input_heights(Hex) ->
    {Tx, <<>>} = beamchain_serialize:decode_transaction(
                   beamchain_serialize:hex_decode(Hex)),
    lists:sort([H || #tx_in{prev_out = #outpoint{hash = <<H:256>>}}
                     <- Tx#transaction.inputs, H =/= 16#eeee]).

%%% ===================================================================
%%% tests
%%% ===================================================================

fundraw_immature_coinbase_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     [{"fundrawtransaction above the mature balance is Insufficient funds",
       fun fundraw_over_mature_balance_is_insufficient/0},
      {"fundrawtransaction within the mature balance spends only height 1",
       fun fundraw_within_mature_balance_uses_mature_coin/0},
      {"the shared selectable set holds only the mature coinbase",
       fun selectable_set_is_mature_only/0},
      {"walletcreatefundedpsbt above the mature balance is refused (control)",
       fun wcfp_over_mature_balance_is_refused/0}]}.

%% 75 BTC > the single mature 50 BTC coinbase. Core: -4 Insufficient funds.
%% master funded it with immature coinbases (a premature-spend tx).
fundraw_over_mature_balance_is_insufficient() ->
    Result = fund(7500000000),
    case Result of
        {ok, #{<<"hex">> := Hex}} ->
            ?debugFmt("funded with coinbase heights ~p", [input_heights(Hex)]);
        _ -> ok
    end,
    ?assertEqual({error, -4, <<"Insufficient funds">>}, Result).

fundraw_within_mature_balance_uses_mature_coin() ->
    {ok, #{<<"hex">> := Hex}} = fund(1000000000),
    ?assertEqual([1], input_heights(Hex)).

selectable_set_is_mature_only() ->
    Coins = beamchain_wallet:get_selectable_utxos(),
    ?assertEqual([1], [U#utxo.height || {_, _, U} <- Coins]),
    %% Tip unknown: fail closed, no coinbase is offered.
    meck:expect(beamchain_chainstate, get_tip_height, fun() -> not_found end),
    try
        ?assertEqual([], beamchain_wallet:get_selectable_utxos())
    after
        meck:expect(beamchain_chainstate, get_tip_height,
                    fun() -> {ok, ?TIP} end)
    end.

wcfp_over_mature_balance_is_refused() ->
    Result = beamchain_rpc:rpc_walletcreatefundedpsbt(
               [[], [#{dest_address() => 75}], 0, #{<<"fee_rate">> => 1}],
               undefined),
    %% Pin the reason so a decode or parameter error cannot pass as the
    %% control. (beamchain answers -26 here where Core answers -4; that code
    %% difference is outside this item.)
    ?assertMatch({error, _, <<"Insufficient funds">>}, Result).
