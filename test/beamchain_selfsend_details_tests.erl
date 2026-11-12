-module(beamchain_selfsend_details_tests).

%%% gettransaction.details for a send-to-self (wallet-cause-D).
%%%
%%% Core CachedTxGetAmounts (wallet/receive.cpp), used by ListTransactions
%%% (wallet/rpc/transactions.cpp): when the wallet paid for the tx, change
%%% outputs are skipped, every other output is a "send" entry and every owned
%%% non-change output is also a "receive" entry. Paying 1 BTC to a second
%%% address of the same wallet gives [send -1, receive +1]; the change output
%%% is in neither. beamchain listed the change as a receive and omitted the
%%% receive leg of the self-payment.
%%%
%%% The wallet's real ETS tables and scan_block_for_wallet/4 are used; only the
%%% wallet-process lookup is mocked.
%%%
%%% RUN: rebar3 eunit --module=beamchain_selfsend_details_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(MOCKED, [beamchain_wallet_sup, beamchain_chainstate, beamchain_config]).
-define(TABLES, [beamchain_wallet_utxos, beamchain_wallet_scripts,
                 beamchain_wallet_history]).

spk(N) -> <<16#00, 16#14, (binary:copy(<<N>>, 20))/binary>>.

setup() ->
    lists:foreach(fun(T) ->
        catch ets:delete(T),
        ets:new(T, [named_table, set, public])
    end, ?TABLES),
    lists:foreach(fun(M) -> meck:new(M, [passthrough, no_link]) end, ?MOCKED),
    Pid = self(),
    meck:expect(beamchain_wallet_sup, list_wallets, fun() -> [<<"w">>] end),
    meck:expect(beamchain_wallet_sup, get_wallet, fun(_) -> {ok, Pid} end),
    meck:expect(beamchain_chainstate, get_tip_height, fun() -> {ok, 110} end),
    meck:expect(beamchain_config, network, fun() -> regtest end),
    %% owned: 1 (first receive), 2 (second receive), 3 (change chain)
    beamchain_wallet:register_wallet_script(spk(1), <<"a1">>),
    beamchain_wallet:register_wallet_script(spk(2), <<"a2">>),
    beamchain_wallet:register_wallet_script(spk(3), <<"a3">>),
    beamchain_wallet:register_change_script(spk(3)),
    ok.

cleanup(_) ->
    lists:foreach(fun(M) -> catch meck:unload(M) end, ?MOCKED),
    lists:foreach(fun(T) -> catch ets:delete(T) end, ?TABLES).

%% Fund the wallet with 50 BTC on spk(1), then spend it paying 1 BTC to Dest
%% and the rest to the change script. Returns the gettransaction result map.
spend_and_gettx(Dest) ->
    ets:delete_all_objects(beamchain_wallet_utxos),
    ets:delete_all_objects(beamchain_wallet_history),
    FundTxid = <<7:256>>,
    beamchain_wallet:add_wallet_utxo(FundTxid, 0, 5000000000, spk(1), 1),
    Spend = #transaction{
        version = 2,
        inputs = [#tx_in{prev_out = #outpoint{hash = FundTxid, index = 0},
                         script_sig = <<>>, sequence = 16#fffffffd,
                         witness = []}],
        outputs = [#tx_out{value = 100000000, script_pubkey = Dest},
                   #tx_out{value = 3999990000, script_pubkey = spk(3)}],
        locktime = 0},
    Hdr = #block_header{version = 1, prev_hash = <<0:256>>,
                        merkle_root = <<0:256>>, timestamp = 1700000000,
                        bits = 16#207fffff, nonce = 0},
    Block = #block{header = Hdr, transactions = [Spend]},
    %% scan_block_for_wallet treats the first tx as the coinbase, so put a
    %% dummy coinbase first.
    Cb = #transaction{version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = <<1,1>>, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = 0, script_pubkey = <<16#6a>>}],
        locktime = 0},
    ok = beamchain_wallet:scan_block_for_wallet(
           Block#block{transactions = [Cb, Spend]}, 100, <<9:256>>, 1700000000),
    [{Txid, _}] = beamchain_wallet:get_tx_history(),
    Disp = binary:encode_hex(binary:list_to_bin(
                               lists:reverse(binary:bin_to_list(Txid))),
                             lowercase),
    Resp = beamchain_rpc:dispatch(
             #{<<"jsonrpc">> => <<"1.0">>, <<"id">> => <<"t">>,
               <<"method">> => <<"gettransaction">>,
               <<"params">> => [Disp]}, undefined),
    Decoded = case Resp of
        {raw_json, B} -> jsx:decode(B, [return_maps]);
        M when is_map(M) -> M
    end,
    #{<<"error">> := null, <<"result">> := R} = Decoded,
    R.

cats(R) ->
    [{maps:get(<<"category">>, D), maps:get(<<"vout">>, D, undefined)}
     || D <- maps:get(<<"details">>, R)].

selfsend_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     [{"send-to-self lists send and receive for the paid output, never change",
       fun() ->
           R = spend_and_gettx(spk(2)),
           Details = maps:get(<<"details">>, R),
           Sends = [D || D <- Details, maps:get(<<"category">>, D) =:= <<"send">>],
           Recvs = [D || D <- Details, maps:get(<<"category">>, D) =:= <<"receive">>],
           ?assertEqual(2, length(Details)),
           ?assertEqual(1, length(Sends)),
           ?assertEqual(1, length(Recvs))
       end},
      {"control: send to a foreign script is one send, change is not a receive",
       fun() ->
           R = spend_and_gettx(spk(9)),
           Cats = [C || {C, _} <- cats(R)],
           ?assertEqual([<<"send">>], Cats)
       end}]}.
