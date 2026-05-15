-module(beamchain_fix63_tests).

%% FIX-63 — beamchain W118 BUG-5 walletprocesspsbt + W118 TP-2 #psbt
%% record consolidation.
%%
%% Part 1: walletprocesspsbt RPC was MISSING (audit W118 BUG-5 / W119 G5
%%         carry-forward). Wallet had sign_psbt + finalize_psbt internal
%%         helpers but no JSON-RPC envelope path — classic dead-helper-
%%         at-RPC-boundary. FIX-63 wires it via beamchain_rpc:
%%         rpc_walletprocesspsbt/2 producing the Core RPC shape
%%         {psbt, complete, hex?}.
%%
%% Part 2: -record(psbt, ...) was defined in BOTH beamchain_psbt.erl:79
%%         (7 fields) and beamchain_wallet.erl:1245 (4 fields). Records
%%         erase to tagged tuples at compile time; the two definitions
%%         produced incompatible layouts. Any #psbt{} from
%%         beamchain_psbt:create/1 handed to beamchain_wallet:
%%         add_witness_utxo/3 (which actually happens: see
%%         walletcreatefundedpsbt + bumpfee_emit_psbt) silently mis-read
%%         its fields — Psbt#psbt.inputs resolved to the 3rd tuple slot,
%%         which in the psbt-module shape is the xpubs map. Result: a
%%         crash or worse, silent stamp of `xpubs => list-of-input-maps`
%%         into the wrong slot during a re-pack. FIX-63 consolidates
%%         both modules onto include/beamchain_psbt.hrl.
%%
%% Field-set diff that closed (psbt-module shape was the superset):
%%   wallet (pre-fix, 4 fields):       {unsigned_tx, inputs, outputs}
%%   psbt-module (pre-fix, 7 fields):  {unsigned_tx, xpubs, version,
%%                                      global_unknown, inputs, outputs}
%% Wallet had no use for xpubs / version / global_unknown — they default
%% to empty in the canonical record, so the migration is field-additive.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").
-include("beamchain_psbt.hrl").

%%% ===================================================================
%%% Helpers
%%% ===================================================================

mk_utxo(Value, Script) ->
    #utxo{value = Value, script_pubkey = Script,
          is_coinbase = false, height = 1}.

%% Source-file path for grep-based assertions (canonical record header
%% lives in include/beamchain_psbt.hrl; src files should no longer
%% redefine `-record(psbt, ...)`).
beamchain_src_dir() ->
    %% code:which/1 → ./_build/default/lib/beamchain/ebin/<mod>.beam
    Beam = code:which(beamchain_wallet),
    Ebin = filename:dirname(Beam),
    Lib  = filename:dirname(Ebin),
    Src  = filename:join([Lib, "src"]),
    case filelib:is_dir(Src) of
        true -> Src;
        false -> "src"  %% fallback for in-repo eunit
    end.

read_src(File) ->
    Path = filename:join(beamchain_src_dir(), File),
    {ok, Bin} = file:read_file(Path),
    Bin.

count_substr(Bin, Sub) ->
    count_substr(Bin, Sub, 0).
count_substr(Bin, Sub, Acc) ->
    case binary:match(Bin, Sub) of
        nomatch -> Acc;
        {Pos, Len} ->
            Tail = binary:part(Bin, Pos + Len, byte_size(Bin) - Pos - Len),
            count_substr(Tail, Sub, Acc + 1)
    end.

%% Count occurrences of a record-definition pattern (`-record(<name>,`)
%% appearing at the start of a line (i.e. as actual Erlang code, NOT in
%% a comment). Counts `<NL>-record(<name>,` plus a possible occurrence
%% at byte 0 of the file.
count_record_def(Bin, NameAtom) ->
    Sub = iolist_to_binary([<<"\n-record(">>, atom_to_binary(NameAtom),
                            <<",">>]),
    %% Special-case: file might start with the record def (no preceding NL).
    Start = case binary:match(Bin, iolist_to_binary([
                <<"-record(">>, atom_to_binary(NameAtom), <<",">>])) of
        {0, _} -> 1;
        _      -> 0
    end,
    Start + count_substr(Bin, Sub).

%% Build a sample unsigned tx with one P2WPKH input.
sample_unsigned_tx(ScriptPubKey) ->
    #transaction{
        version = 2,
        inputs = [
            #tx_in{prev_out  = #outpoint{
                                  hash = <<1:256>>,
                                  index = 0
                                },
                   script_sig = <<>>,
                   sequence   = 16#fffffffd,
                   witness    = []}
        ],
        outputs = [
            #tx_out{value = 90000,
                    script_pubkey = ScriptPubKey}
        ],
        locktime = 0
    }.

%% Build a PSBT (via beamchain_psbt) with witness_utxo attached for
%% each input using the wallet's add_witness_utxo helper. This is the
%% production path used by walletcreatefundedpsbt + bumpfee_emit_psbt.
build_psbt_with_witness_utxo(Tx, Utxos) ->
    {ok, P0} = beamchain_psbt:create(Tx),
    Indexed = lists:zip(lists:seq(0, length(Utxos) - 1), Utxos),
    lists:foldl(fun({Idx, U}, Acc) ->
        beamchain_wallet:add_witness_utxo(Acc, Idx, U)
    end, P0, Indexed).

%%% ===================================================================
%%% Part 2 — TP-2 record consolidation tests
%%% ===================================================================

%% tp2_one_record_definition: assert `-record(psbt,` appears in EXACTLY
%% one source location (the canonical include header), NOT in src/*.erl.
tp2_one_record_definition_test_() ->
    {"TP-2: -record(psbt, ...) is defined in exactly one source file",
     [
      ?_test(begin
         %% src/beamchain_psbt.erl must NOT redefine the record.
         PsbtSrc = read_src("beamchain_psbt.erl"),
         ?assertEqual(0, count_record_def(PsbtSrc, psbt))
       end),
      ?_test(begin
         %% src/beamchain_wallet.erl must NOT redefine the record.
         WalletSrc = read_src("beamchain_wallet.erl"),
         ?assertEqual(0, count_record_def(WalletSrc, psbt))
       end),
      ?_test(begin
         %% The canonical definition must live in the include header.
         IncPath = filename:join([
             filename:dirname(beamchain_src_dir()),
             "include", "beamchain_psbt.hrl"]),
         case filelib:is_file(IncPath) of
             true ->
                 {ok, Bin} = file:read_file(IncPath),
                 ?assertEqual(1, count_record_def(Bin, psbt));
             false ->
                 %% Outside the source tree (release build path): skip.
                 ok
         end
       end)
     ]}.

%% tp2_field_count: a freshly-created #psbt{} value must have the 7-field
%% canonical shape. Pre-fix the wallet's definition was 4 fields; this
%% test pins the canonical layout so a regression that flips it back
%% would break here.
tp2_field_count_test_() ->
    {"TP-2: canonical #psbt{} record is a 7-tuple {psbt, ...}",
     [
      ?_test(begin
         Tx = sample_unsigned_tx(<<16#00, 20, 0:160>>),
         {ok, Psbt} = beamchain_psbt:create(Tx),
         ?assertEqual(7, tuple_size(Psbt)),
         ?assertEqual(psbt, element(1, Psbt))
       end)
     ]}.

%% tp2_cross_module_field_equivalence: a #psbt{} produced by
%% beamchain_psbt:create/1 must be readable by beamchain_wallet helpers
%% (this is the exact cross-module boundary that pre-fix mis-read its
%% fields). beamchain_wallet:add_witness_utxo/3 is the canonical
%% boundary-crosser — it is called by walletcreatefundedpsbt and
%% bumpfee_emit_psbt in production.
tp2_cross_module_field_equivalence_test_() ->
    {"TP-2: #psbt{} produced by psbt-module is readable by wallet helpers",
     [
      ?_test(begin
         Script = <<16#00, 20, 1,2,3,4,5,6,7,8,9,10,
                    11,12,13,14,15,16,17,18,19,20>>,
         Tx = sample_unsigned_tx(Script),
         Utxo = mk_utxo(100000, Script),
         %% Pre-fix path: created here, mutated through wallet helper.
         {ok, P0} = beamchain_psbt:create(Tx),
         P1 = beamchain_wallet:add_witness_utxo(P0, 0, Utxo),
         %% Recover the inputs list via the canonical field — must
         %% be the list of input maps, not the xpubs map (the pre-fix
         %% silent failure mode).
         Inputs = P1#psbt.inputs,
         ?assert(is_list(Inputs)),
         ?assertEqual(1, length(Inputs)),
         [Map] = Inputs,
         ?assert(is_map(Map)),
         ?assertEqual(Utxo, maps:get(utxo_record, Map))
       end)
     ]}.

%% tp2_field_round_trip: round-trip a #psbt{} through both modules and
%% confirm `xpubs` / `version` / `global_unknown` defaults survive.
tp2_field_round_trip_test_() ->
    {"TP-2: xpubs/version/global_unknown defaults preserved across "
     "psbt-module ↔ wallet boundary",
     [
      ?_test(begin
         Script = <<16#00, 20, 21,22,23,24,25,26,27,28,29,30,
                    31,32,33,34,35,36,37,38,39,40>>,
         Tx = sample_unsigned_tx(Script),
         Utxo = mk_utxo(50000, Script),
         {ok, P0} = beamchain_psbt:create(Tx),
         ?assertEqual(#{}, P0#psbt.xpubs),
         ?assertEqual(0,   P0#psbt.version),
         ?assertEqual(#{}, P0#psbt.global_unknown),
         %% Cross into wallet, then back into psbt-module read.
         P1 = beamchain_wallet:add_witness_utxo(P0, 0, Utxo),
         ?assertEqual(#{}, P1#psbt.xpubs),
         ?assertEqual(0,   P1#psbt.version),
         ?assertEqual(#{}, P1#psbt.global_unknown),
         Tx2 = beamchain_psbt:get_unsigned_tx(P1),
         ?assertEqual(Tx#transaction.version, Tx2#transaction.version)
       end)
     ]}.

%%% ===================================================================
%%% Part 1 — walletprocesspsbt RPC tests
%%% ===================================================================

%% G14a: rpc_walletprocesspsbt/2 is exported from beamchain_rpc — this
%% is the gate-flip assertion mirrored from W119 G5. Pre-fix the function
%% did not exist; post-fix it is unconditionally exported (see export
%% block in src/beamchain_rpc.erl).
walletprocesspsbt_exported_test_() ->
    {"WPP-1: rpc_walletprocesspsbt/2 is exported from beamchain_rpc",
     [
      ?_test(begin
         Exports = beamchain_rpc:module_info(exports),
         ?assert(lists:member({rpc_walletprocesspsbt, 2}, Exports))
       end)
     ]}.

%% WPP-2: parse_sighash_string parses all 7 BIP-143 / BIP-341 sighash
%% strings and rejects junk.
parse_sighash_string_test_() ->
    {"WPP-2: sighashtype string parser matches Bitcoin Core SighashFromStr",
     [
      ?_assertEqual({ok, 16#00},
                    beamchain_rpc:parse_sighash_string(<<"DEFAULT">>)),
      ?_assertEqual({ok, 16#01},
                    beamchain_rpc:parse_sighash_string(<<"ALL">>)),
      ?_assertEqual({ok, 16#02},
                    beamchain_rpc:parse_sighash_string(<<"NONE">>)),
      ?_assertEqual({ok, 16#03},
                    beamchain_rpc:parse_sighash_string(<<"SINGLE">>)),
      ?_assertEqual({ok, 16#81},
                    beamchain_rpc:parse_sighash_string(<<"ALL|ANYONECANPAY">>)),
      ?_assertEqual({ok, 16#82},
                    beamchain_rpc:parse_sighash_string(<<"NONE|ANYONECANPAY">>)),
      ?_assertEqual({ok, 16#83},
                    beamchain_rpc:parse_sighash_string(<<"SINGLE|ANYONECANPAY">>)),
      %% Case-insensitive: lower → upper passthrough.
      ?_assertEqual({ok, 16#01},
                    beamchain_rpc:parse_sighash_string(<<"all">>)),
      %% Garbage rejected.
      ?_test(begin
         R = beamchain_rpc:parse_sighash_string(<<"junk">>),
         ?assertMatch({error, _}, R)
       end)
     ]}.

%% WPP-3: handler param-shape validation — non-binary first arg rejected.
walletprocesspsbt_bad_params_test_() ->
    {"WPP-3: parameter shape validation",
     [
      ?_test(begin
         R = beamchain_rpc:rpc_walletprocesspsbt([], <<>>),
         ?assertMatch({error, _, _}, R)
       end),
      ?_test(begin
         %% Non-binary PSBT.
         R = beamchain_rpc:rpc_walletprocesspsbt([42], <<>>),
         ?assertMatch({error, _, _}, R)
       end),
      ?_test(begin
         %% Invalid base64.
         R = beamchain_rpc:rpc_walletprocesspsbt(
                 [<<"!!!not-base64!!!">>, true, <<"ALL">>, true, false], <<>>),
         %% Wallet must exist for the path to reach the base64 decoder.
         ensure_default_wallet(),
         R2 = beamchain_rpc:rpc_walletprocesspsbt(
                 [<<"!!!not-base64!!!">>, true, <<"ALL">>, true, false], <<>>),
         %% Both attempts should fail (either via wallet missing or
         %% base64 error) — the contract is "no silent success".
         ?assert(is_error(R) orelse is_ok(R) =:= false),
         ?assert(is_error(R2) orelse is_ok(R2) =:= false)
       end)
     ]}.

is_error({error, _, _})    -> true;
is_error({error, _})       -> true;
is_error({error, _, _, _}) -> true;
is_error(_)                -> false.

is_ok({ok, _})          -> true;
is_ok({ok_raw_json, _}) -> true;
is_ok(_)                -> false.

ensure_default_wallet() ->
    case whereis(beamchain_wallet) of
        undefined ->
            {ok, _Pid} = beamchain_wallet:start_link();
        _Pid ->
            ok
    end.

stop_default_wallet() ->
    case whereis(beamchain_wallet) of
        undefined -> ok;
        Pid ->
            gen_server:stop(Pid)
    end.

%% WPP-4: round-trip with sign=true + finalize=true on a P2WPKH input
%% that the wallet owns. Expect complete=true and hex present.
walletprocesspsbt_p2wpkh_roundtrip_test_() ->
    {setup,
     fun() ->
         %% Use a uniquely-seeded default wallet for this test.
         _ = stop_default_wallet(),
         {ok, Pid} = beamchain_wallet:start_link(),
         Seed = crypto:strong_rand_bytes(32),
         {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
         {ok, Addr} = beamchain_wallet:get_new_address(Pid, p2wpkh),
         {ok, Script} = beamchain_address:address_to_script(Addr, mainnet),
         Pid
     end,
     fun(_Pid) -> stop_default_wallet() end,
     fun(_Pid) ->
       [
        ?_test(begin
           {ok, Addr} = beamchain_wallet:get_new_address(p2wpkh),
           {ok, Script} = beamchain_address:address_to_script(Addr, mainnet),
           Utxo = mk_utxo(100000, Script),
           Tx = sample_unsigned_tx(Script),
           Psbt = build_psbt_with_witness_utxo(Tx, [Utxo]),
           PsbtBin = beamchain_psbt:encode(Psbt),
           PsbtB64 = base64:encode(PsbtBin),
           %% sign=true, sighash=ALL, bip32derivs=true, finalize=true
           R = beamchain_rpc:rpc_walletprocesspsbt(
                   [PsbtB64, true, <<"ALL">>, true, true], <<>>),
           %% Expect {ok, #{ <<"complete">> := true, ...}}.
           case R of
               {ok, Map} when is_map(Map) ->
                   ?assertEqual(true, maps:get(<<"complete">>, Map)),
                   ?assert(maps:is_key(<<"psbt">>, Map)),
                   ?assert(maps:is_key(<<"hex">>, Map)),
                   Hex = maps:get(<<"hex">>, Map),
                   ?assert(is_binary(Hex)),
                   ?assert(byte_size(Hex) > 0);
               Other ->
                   %% Surface the actual error for debugging — but the
                   %% gate is to FAIL on non-{ok, Map}, hence ?assert.
                   ?debugFmt("walletprocesspsbt unexpected return: ~p", [Other]),
                   ?assert(false)
           end
         end)
       ]
     end}.

%% WPP-5: locked-wallet path — wallet is encrypted + locked → expect
%% RPC -13 (RPC_WALLET_UNLOCK_NEEDED).
walletprocesspsbt_locked_wallet_test_() ->
    {setup,
     fun() ->
         _ = stop_default_wallet(),
         {ok, Pid} = beamchain_wallet:start_link(),
         Seed = crypto:strong_rand_bytes(32),
         {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
         ok = gen_server:call(Pid, {encryptwallet, <<"hunter2pw">>}),
         _ = gen_server:call(Pid, walletlock),
         Pid
     end,
     fun(_Pid) -> stop_default_wallet() end,
     fun(_Pid) ->
       [
        ?_test(begin
           ?assert(beamchain_wallet:is_locked()),
           %% Build a PSBT for any address — the lock check fires
           %% before key lookup.
           Script = <<16#00, 20, 1,2,3,4,5,6,7,8,9,10,11,12,13,
                       14,15,16,17,18,19,20>>,
           Utxo = mk_utxo(100000, Script),
           Tx = sample_unsigned_tx(Script),
           Psbt = build_psbt_with_witness_utxo(Tx, [Utxo]),
           PsbtBin = beamchain_psbt:encode(Psbt),
           PsbtB64 = base64:encode(PsbtBin),
           R = beamchain_rpc:rpc_walletprocesspsbt(
                   [PsbtB64, true, <<"ALL">>, true, true], <<>>),
           %% RPC error code -13.
           case R of
               {error, -13, _Msg} -> ok;
               Other ->
                   ?debugFmt("expected RPC -13 (wallet locked), got ~p", [Other]),
                   ?assert(false)
           end
         end)
       ]
     end}.

%% WPP-6: missing-key path — PSBT input scriptPubKey is NOT owned by the
%% wallet. With sign=true, walletprocesspsbt cannot produce a partial
%% sig for that input, so complete=false. Updater path still attaches
%% witness_utxo (Core behaviour: client gets back the input shape it
%% would need to forward to the right signer).
walletprocesspsbt_missing_key_test_() ->
    {setup,
     fun() ->
         _ = stop_default_wallet(),
         {ok, Pid} = beamchain_wallet:start_link(),
         Seed = crypto:strong_rand_bytes(32),
         {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
         Pid
     end,
     fun(_Pid) -> stop_default_wallet() end,
     fun(_Pid) ->
       [
        ?_test(begin
           %% Foreign P2WPKH scriptPubKey — wallet has never seen it.
           ForeignHash = crypto:hash(ripemd160,
                                     crypto:hash(sha256, <<"foreign">>)),
           ForeignScript = <<16#00, 20, ForeignHash/binary>>,
           Utxo = mk_utxo(50000, ForeignScript),
           Tx = sample_unsigned_tx(ForeignScript),
           Psbt = build_psbt_with_witness_utxo(Tx, [Utxo]),
           PsbtBin = beamchain_psbt:encode(Psbt),
           PsbtB64 = base64:encode(PsbtBin),
           R = beamchain_rpc:rpc_walletprocesspsbt(
                   [PsbtB64, true, <<"ALL">>, true, true], <<>>),
           case R of
               {ok, Map} when is_map(Map) ->
                   ?assertEqual(false, maps:get(<<"complete">>, Map)),
                   %% hex MUST NOT be present when complete=false.
                   ?assert(not maps:is_key(<<"hex">>, Map)),
                   %% PSBT base64 still returned so the caller can
                   %% forward to another signer.
                   ?assert(maps:is_key(<<"psbt">>, Map));
               Other ->
                   ?debugFmt("walletprocesspsbt missing-key unexpected: ~p",
                             [Other]),
                   ?assert(false)
           end
         end)
       ]
     end}.

%% WPP-7: sign=false → Updater-only path. No partial sig produced even
%% for wallet-owned inputs; complete=false, no hex.
walletprocesspsbt_sign_false_test_() ->
    {setup,
     fun() ->
         _ = stop_default_wallet(),
         {ok, Pid} = beamchain_wallet:start_link(),
         Seed = crypto:strong_rand_bytes(32),
         {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
         Pid
     end,
     fun(_Pid) -> stop_default_wallet() end,
     fun(_Pid) ->
       [
        ?_test(begin
           {ok, Addr} = beamchain_wallet:get_new_address(p2wpkh),
           {ok, Script} = beamchain_address:address_to_script(Addr, mainnet),
           Utxo = mk_utxo(100000, Script),
           Tx = sample_unsigned_tx(Script),
           Psbt = build_psbt_with_witness_utxo(Tx, [Utxo]),
           PsbtBin = beamchain_psbt:encode(Psbt),
           PsbtB64 = base64:encode(PsbtBin),
           %% sign=false → Updater only.
           R = beamchain_rpc:rpc_walletprocesspsbt(
                   [PsbtB64, false, <<"ALL">>, true, true], <<>>),
           case R of
               {ok, Map} when is_map(Map) ->
                   ?assertEqual(false, maps:get(<<"complete">>, Map)),
                   ?assert(not maps:is_key(<<"hex">>, Map)),
                   ?assert(maps:is_key(<<"psbt">>, Map));
               Other ->
                   ?debugFmt("walletprocesspsbt sign=false unexpected: ~p",
                             [Other]),
                   ?assert(false)
           end
         end)
       ]
     end}.

%% WPP-8: finalize=false → sign yes but do NOT assemble final tx hex,
%% even when all inputs are signable.
walletprocesspsbt_finalize_false_test_() ->
    {setup,
     fun() ->
         _ = stop_default_wallet(),
         {ok, Pid} = beamchain_wallet:start_link(),
         Seed = crypto:strong_rand_bytes(32),
         {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
         Pid
     end,
     fun(_Pid) -> stop_default_wallet() end,
     fun(_Pid) ->
       [
        ?_test(begin
           {ok, Addr} = beamchain_wallet:get_new_address(p2wpkh),
           {ok, Script} = beamchain_address:address_to_script(Addr, mainnet),
           Utxo = mk_utxo(100000, Script),
           Tx = sample_unsigned_tx(Script),
           Psbt = build_psbt_with_witness_utxo(Tx, [Utxo]),
           PsbtBin = beamchain_psbt:encode(Psbt),
           PsbtB64 = base64:encode(PsbtBin),
           R = beamchain_rpc:rpc_walletprocesspsbt(
                   [PsbtB64, true, <<"ALL">>, true, false], <<>>),
           case R of
               {ok, Map} when is_map(Map) ->
                   %% Signed but not finalized → no hex, complete=false
                   %% (we did not finalize so the "complete" flag means
                   %% "ready to extract", which is gated on finalize).
                   ?assertEqual(false, maps:get(<<"complete">>, Map)),
                   ?assert(not maps:is_key(<<"hex">>, Map)),
                   ?assert(maps:is_key(<<"psbt">>, Map));
               Other ->
                   ?debugFmt("walletprocesspsbt finalize=false unexpected: ~p",
                             [Other]),
                   ?assert(false)
           end
         end)
       ]
     end}.
