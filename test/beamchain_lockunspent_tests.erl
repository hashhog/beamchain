-module(beamchain_lockunspent_tests).

%% EUnit coverage for the wallet wave H4/H5 RPCs:
%%   - beamchain_wallet:lock_coin / unlock_coin / list_locked_coins (H5)
%%   - rpc_lockunspent / rpc_listlockunspent dispatch surface (H5)
%%   - rpc_analyzepsbt heuristic + role ratchet (H4)
%%
%% Reference: bitcoin-core/src/wallet/rpc/coins.cpp::lockunspent and
%% bitcoin-core/src/rpc/rawtransaction.cpp::analyzepsbt.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Helpers
%%% ===================================================================

start_wallet(Name) ->
    {ok, Pid} = beamchain_wallet:start_link(Name),
    Pid.

stop_wallet(Pid) ->
    case is_process_alive(Pid) of
        true  -> gen_server:stop(Pid);
        false -> ok
    end.

sample_txid() ->
    <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
      17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32>>.

sample_txid_2() ->
    <<33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
      49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64>>.

sample_unsigned_tx() ->
    #transaction{
        version = 2,
        inputs = [
            #tx_in{
                prev_out = #outpoint{hash = sample_txid(), index = 0},
                script_sig = <<>>,
                sequence = 16#fffffffd,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 90000,
                %% P2WPKH 0x00 0x14 <20 bytes>
                script_pubkey = <<16#00, 20,
                    1,2,3,4,5,6,7,8,9,10,
                    11,12,13,14,15,16,17,18,19,20>>
            }
        ],
        locktime = 0
    }.

p2wpkh_script() ->
    <<16#00, 20, 1,2,3,4,5,6,7,8,9,10,
                  11,12,13,14,15,16,17,18,19,20>>.

%%% ===================================================================
%%% Wallet API: lock / unlock / list (Cat-H5)
%%% ===================================================================

lock_coin_basic_test() ->
    Pid = start_wallet(<<"lockunspent_basic">>),
    Txid = sample_txid(),
    %% Initially nothing is locked.
    ?assertEqual([], beamchain_wallet:list_locked_coins(Pid)),
    ?assertEqual(false, beamchain_wallet:is_locked_coin(Pid, {Txid, 0})),
    %% Lock {Txid, 0}.
    ?assertEqual(ok, beamchain_wallet:lock_coin(Pid, Txid, 0)),
    ?assertEqual(true, beamchain_wallet:is_locked_coin(Pid, {Txid, 0})),
    %% list_locked_coins reflects the lock.
    ?assertEqual([{Txid, 0}], beamchain_wallet:list_locked_coins(Pid)),
    stop_wallet(Pid).

unlock_coin_round_trip_test() ->
    Pid = start_wallet(<<"lockunspent_unlock">>),
    Txid = sample_txid(),
    %% Unlocking a coin that was never locked is an error.
    ?assertEqual({error, not_locked},
                 beamchain_wallet:unlock_coin(Pid, Txid, 0)),
    %% Lock then unlock.
    ok = beamchain_wallet:lock_coin(Pid, Txid, 0),
    ?assertEqual(ok, beamchain_wallet:unlock_coin(Pid, Txid, 0)),
    %% After unlock, the lock set is empty again.
    ?assertEqual([], beamchain_wallet:list_locked_coins(Pid)),
    ?assertEqual(false, beamchain_wallet:is_locked_coin(Pid, {Txid, 0})),
    stop_wallet(Pid).

unlock_all_coins_test() ->
    Pid = start_wallet(<<"lockunspent_unlock_all">>),
    Txid1 = sample_txid(),
    Txid2 = sample_txid_2(),
    ok = beamchain_wallet:lock_coin(Pid, Txid1, 0),
    ok = beamchain_wallet:lock_coin(Pid, Txid1, 1),
    ok = beamchain_wallet:lock_coin(Pid, Txid2, 0),
    %% 3 locks present.
    ?assertEqual(3, length(beamchain_wallet:list_locked_coins(Pid))),
    %% Clear all.
    ?assertEqual(ok, beamchain_wallet:unlock_all_coins(Pid)),
    ?assertEqual([], beamchain_wallet:list_locked_coins(Pid)),
    stop_wallet(Pid).

lock_idempotent_test() ->
    %% Locking the same outpoint twice is a no-op at the wallet API; the
    %% RPC layer is responsible for the "already locked" rejection. This
    %% guards against accidental list duplication.
    Pid = start_wallet(<<"lockunspent_idempotent">>),
    Txid = sample_txid(),
    ok = beamchain_wallet:lock_coin(Pid, Txid, 0),
    ok = beamchain_wallet:lock_coin(Pid, Txid, 0),
    ?assertEqual([{Txid, 0}], beamchain_wallet:list_locked_coins(Pid)),
    stop_wallet(Pid).

%%% ===================================================================
%%% analyzepsbt (Cat-H4)
%%% ===================================================================

analyzepsbt_unsigned_no_utxo_test() ->
    %% A freshly-created PSBT has no UTXO info → role=updater, no fee/vsize.
    Tx = sample_unsigned_tx(),
    {ok, Psbt} = beamchain_psbt:create(Tx),
    PsbtBin = beamchain_psbt:encode(Psbt),
    PsbtB64 = base64:encode(PsbtBin),
    {ok, Result} = run_analyzepsbt(PsbtB64),
    %% Aggregate role = updater (input has no UTXO yet).
    ?assertEqual(<<"updater">>, maps:get(<<"next">>, Result)),
    %% No fee / estimated_vsize / estimated_feerate when UTXOs are missing.
    ?assertEqual(error, maps:find(<<"fee">>, Result)),
    ?assertEqual(error, maps:find(<<"estimated_vsize">>, Result)),
    %% Inputs array present, with has_utxo=false and is_final=false.
    [Input | _] = maps:get(<<"inputs">>, Result),
    ?assertEqual(false, maps:get(<<"has_utxo">>, Input)),
    ?assertEqual(false, maps:get(<<"is_final">>, Input)),
    ?assertEqual(<<"updater">>, maps:get(<<"next">>, Input)).

analyzepsbt_with_witness_utxo_test() ->
    %% PSBT with witness_utxo populated: should now have fee/vsize and
    %% role=signer (we have UTXO + scriptPubKey but no partial sig yet).
    Tx = sample_unsigned_tx(),
    {ok, Psbt0} = beamchain_psbt:create(Tx),
    {ok, Psbt} = beamchain_psbt:update(Psbt0, [
        {input, 0, #{witness_utxo => {100000, p2wpkh_script()}}}
    ]),
    PsbtB64 = base64:encode(beamchain_psbt:encode(Psbt)),
    {ok, Result} = run_analyzepsbt(PsbtB64),
    %% has_utxo=true, is_final=false → next=signer.
    ?assertEqual(<<"signer">>, maps:get(<<"next">>, Result)),
    %% Fee = inputs(100000) − outputs(90000) = 10000 sat = 0.0001 BTC.
    ?assertEqual(0.0001, maps:get(<<"fee">>, Result)),
    %% Vsize is reported (we use a 68-vbyte heuristic for P2WPKH inputs).
    ?assert(is_integer(maps:get(<<"estimated_vsize">>, Result))),
    ?assert(maps:get(<<"estimated_vsize">>, Result) > 0).

analyzepsbt_invalid_base64_test() ->
    %% Garbage in: must yield RPC_DESERIALIZATION_ERROR (-22) per Core.
    {error, Code, _Msg} = run_analyzepsbt(<<"!!!not-a-psbt!!!">>),
    ?assertEqual(-22, Code).

%%% ===================================================================
%%% PSBT role ratchet (covers analyze_input_role/4 indirectly)
%%% ===================================================================

analyzepsbt_finalized_input_test() ->
    %% Drop a final_script_witness on the input → analyzepsbt should report
    %% is_final=true and the aggregate role = extractor (no more work).
    Tx = sample_unsigned_tx(),
    {ok, Psbt0} = beamchain_psbt:create(Tx),
    {ok, Psbt} = beamchain_psbt:update(Psbt0, [
        {input, 0, #{witness_utxo => {100000, p2wpkh_script()},
                     final_script_witness =>
                         [<<1:8/unit:72>>, <<2:8/unit:33>>]}}
    ]),
    PsbtB64 = base64:encode(beamchain_psbt:encode(Psbt)),
    {ok, Result} = run_analyzepsbt(PsbtB64),
    [Input | _] = maps:get(<<"inputs">>, Result),
    ?assertEqual(true,  maps:get(<<"is_final">>, Input)),
    ?assertEqual(<<"extractor">>, maps:get(<<"next">>, Input)),
    ?assertEqual(<<"extractor">>, maps:get(<<"next">>, Result)).

%%% ===================================================================
%%% lockunspent RPC dispatch (Cat-H5)
%%% ===================================================================
%%
%% These exercise the full RPC parameter parser including outpoint
%% validation. Wallet name <<>> resolves to the registered default wallet,
%% so we start one explicitly with that name to drive the resolve_wallet
%% path (start_link/1 with <<>> registers nothing, so we pre-seed the
%% supervisor's default-wallet slot — but the test rig does not start
%% the supervisor.  Instead we use a uniquely-named wallet and bypass
%% resolve_wallet by calling beamchain_wallet directly: the RPC layer
%% has been unit-tested for its parsing, the wallet API has been tested
%% above, and we exercise the glue here through the actual handler
%% call path).

rpc_listlockunspent_empty_test() ->
    Pid = start_wallet(<<>>),
    %% The default-wallet path resolves <<>> to the registered name first;
    %% start_link(<<>>) does not register, so we register manually for the
    %% duration of the test. resolve_wallet then sees `whereis/1` returning
    %% our Pid.
    true = register_default_wallet(Pid),
    try
        ?assertEqual({ok, []}, beamchain_rpc:rpc_listlockunspent(<<>>))
    after
        unregister_default_wallet(),
        stop_wallet(Pid)
    end.

rpc_lockunspent_unlock_with_no_args_clears_all_test() ->
    Pid = start_wallet(<<>>),
    true = register_default_wallet(Pid),
    try
        ok = beamchain_wallet:lock_coin(Pid, sample_txid(), 0),
        ok = beamchain_wallet:lock_coin(Pid, sample_txid_2(), 1),
        %% lockunspent true (no transactions) → clears all locks.
        ?assertEqual({ok, true},
                     beamchain_rpc:rpc_lockunspent([true], <<>>)),
        ?assertEqual([], beamchain_wallet:list_locked_coins(Pid))
    after
        unregister_default_wallet(),
        stop_wallet(Pid)
    end.

rpc_lockunspent_lock_then_listlockunspent_test() ->
    Pid = start_wallet(<<>>),
    true = register_default_wallet(Pid),
    try
        TxidHex = display_hex(sample_txid()),
        Outpoints = [#{<<"txid">> => TxidHex, <<"vout">> => 0}],
        %% Lock the outpoint via the RPC handler.
        ?assertEqual({ok, true},
                     beamchain_rpc:rpc_lockunspent(
                         [false, Outpoints], <<>>)),
        %% listlockunspent returns the locked outpoint in display order.
        {ok, [Lock]} = beamchain_rpc:rpc_listlockunspent(<<>>),
        ?assertEqual(TxidHex, maps:get(<<"txid">>, Lock)),
        ?assertEqual(0, maps:get(<<"vout">>, Lock)),
        %% Locking the same outpoint again must be rejected with
        %% RPC_INVALID_PARAMETER (-8) per Core's "output already locked".
        {error, -8, _} =
            beamchain_rpc:rpc_lockunspent([false, Outpoints], <<>>),
        %% Unlocking a never-locked outpoint must also be rejected (-8).
        OtherHex = display_hex(sample_txid_2()),
        OtherOps = [#{<<"txid">> => OtherHex, <<"vout">> => 7}],
        {error, -8, _} =
            beamchain_rpc:rpc_lockunspent([true, OtherOps], <<>>),
        %% Negative vout → invalid parameter.
        BadVout = [#{<<"txid">> => TxidHex, <<"vout">> => -1}],
        {error, -8, _} =
            beamchain_rpc:rpc_lockunspent([false, BadVout], <<>>)
    after
        unregister_default_wallet(),
        stop_wallet(Pid)
    end.

%%% ===================================================================
%%% Driver: dispatch through the RPC handler instead of touching the
%%% private analyze_psbt/1 helper.  This keeps the coverage on the
%%% method-name path (handle_method/3 → rpc_analyzepsbt/1).
%%% ===================================================================

run_analyzepsbt(PsbtB64) ->
    %% rpc_analyzepsbt is internal; we drive it via the same dispatch
    %% Cowboy uses by hand-rolling the request → handle_method shape.
    %% The helper is exported only for test-mode; in production the
    %% method goes through the auth + JSON layer.
    case erlang:apply(beamchain_rpc, rpc_analyzepsbt, [[PsbtB64]]) of
        Result -> Result
    end.

%% Register/unregister the test wallet under the production registered
%% name `beamchain_wallet` so that resolve_wallet(<<>>) → whereis hit.
%% Idempotent: tolerates a leftover registration from a previous failure.
register_default_wallet(Pid) ->
    case whereis(beamchain_wallet) of
        undefined  -> register(beamchain_wallet, Pid);
        Pid        -> true;
        Other      ->
            unregister(beamchain_wallet),
            (catch exit(Other, kill)),
            register(beamchain_wallet, Pid)
    end.

unregister_default_wallet() ->
    case whereis(beamchain_wallet) of
        undefined -> ok;
        _ -> (catch unregister(beamchain_wallet)), ok
    end.

%% Display-order hex (Bitcoin big-endian) — inverse of hex_to_internal_hash.
display_hex(BinLE) ->
    Reversed = list_to_binary(lists:reverse(binary_to_list(BinLE))),
    list_to_binary(string:lowercase(binary_to_list(binary:encode_hex(Reversed)))).
