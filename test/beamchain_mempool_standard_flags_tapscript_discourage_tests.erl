%%% The mempool checks scripts with Core's three tapscript
%%% upgrade-discouragement flags.
%%%
%%% Item r3fix-beamchain-standard-flags-tapscript-discourage (R3 generating
%%% differential fuzzer, night 1, seed 739943, triage group G2: rows R34, R35,
%%% R37, R10, R12, R25).
%%%
%%% Core v31.1 src/policy/policy.h:118-131: STANDARD_SCRIPT_VERIFY_FLAGS
%%% includes SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
%%% SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS and
%%% SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE, and
%%% MemPoolAccept::PolicyScriptChecks (validation.cpp) runs every input under
%%% exactly that set. On failure the reject reason is
%%% "mempool-script-verify-flag-failed (<ScriptErrorString>)".
%%%
%%% beamchain's all_standard_flags/0 stopped at SCRIPT_VERIFY_TAPROOT, so
%%% OP_SUCCESSx leaves, unknown leaf versions and unknown-type tapscript
%%% pubkeys were admitted, and where the script failed anyway the reason
%%% named a later check instead of the discouraged upgrade.
%%%
%%% All of these spends are consensus-valid (the block-flag controls below),
%%% so the change is policy only: the same transactions still connect in a
%%% block.
%%%   rebar3 eunit --module=beamchain_mempool_standard_flags_tapscript_discourage_tests
-module(beamchain_mempool_standard_flags_tapscript_discourage_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(PRIV, <<7:256>>).
-define(OP_TRUE, <<16#51>>).
-define(CB_VALUE, 2500000000).
-define(FUND_VALUE, 100000000).
-define(SPEND_FEE, 10000).

%% The night-1 minimised case (row R34): one input whose witness is
%% [<50>, <c0 || G.x>], i.e. a script-path spend of the single leaf
%% OP_SUCCESS80 (leaf version 0xc0) under internal key G.
-define(MINIMISED_HEX,
        "02000000000101e24a07866680a8c78c0fe5661ad7b22d2fff0dd824cd5c59377bbed3"
        "b03374040000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5c"
        "ed7a1a000945432e83e1551e6f721ee9c00b8cc3326002015021c079be667ef9dcbbac"
        "55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000").

-define(REASON(Text),
        <<"mempool-script-verify-flag-failed (", Text, ")">>).
-define(OP_SUCCESS_TEXT, "OP_SUCCESSx reserved for soft-fork upgrades").
-define(LEAF_VERSION_TEXT, "Taproot version reserved for soft-fork upgrades").
-define(PUBKEYTYPE_TEXT, "Public key version reserved for soft-fork upgrades").

%% {Name, LeafVersion, LeafHex}. The leaves need no witness arguments.
%% "51 02 0000 ac" is <1> <0000> CHECKSIG: a non-empty signature against a
%% 2-byte (unknown type) pubkey, which pushes true without the flag.
cases() ->
    [{op_success80,      16#c0, "50"},                 % R34 (minimised)
     {leaf_version_c2,   16#c2, "51"},                 % R35
     {pubkeytype,        16#c0, "51020000ac"},         % R37
     {pubkeytype_weight, 16#c0, "51020000ac00ac"},     % R10 shape
     {pubkeytype_clean,  16#c0, "51020000ac51"},       % R12 shape
     {pubkeytype_emptypk,16#c0, "51020000ac0000ac"},   % R25 shape
     {control_tapscript, 16#c0, "51"}].                % plain OP_TRUE leaf

standard_flags_tapscript_discourage_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun({_TmpDir, Ctx}) ->
         [{timeout, 120, {Title, fun() -> F(Ctx) end}}
          || {Title, F} <-
             [{"FIX R34: OP_SUCCESS80 leaf (the night-1 minimised witness) "
               "is refused with DISCOURAGE_OP_SUCCESS",
               fun op_success80_refused/1},
              {"FIX R35: unknown leaf version 0xc2 is refused with "
               "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
               fun leaf_version_refused/1},
              {"FIX R37: unknown tapscript pubkey type is refused with "
               "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
               fun pubkeytype_refused/1},
              {"FIX R10: unknown pubkey type is reported before the "
               "validation-weight failure",
               fun pubkeytype_before_weight/1},
              {"FIX R12: unknown pubkey type is reported before CLEANSTACK",
               fun pubkeytype_before_cleanstack/1},
              {"FIX R25: unknown pubkey type is reported before the "
               "empty-pubkey failure",
               fun pubkeytype_before_empty_pubkey/1},
              {"FIX: sendrawtransaction refuses the OP_SUCCESS spend too",
               fun sendraw_op_success_refused/1},
              {"CONTROL: a plain tapscript spend is still accepted",
               fun control_tapscript_accepted/1},
              {"CONTROL: the discouraged spends are consensus-valid "
               "(block flags)",
               fun consensus_valid_under_block_flags/1},
              {"CONTROL: a block holding the discouraged spends connects",
               fun block_with_discouraged_spends_connects/1}]]
     end}.

%%% --- tests -------------------------------------------------------------

op_success80_refused(Ctx) ->
    %% The fixture's witness is byte-for-byte the minimised case's witness.
    {Min, _} = beamchain_serialize:decode_transaction(
                 binary:decode_hex(list_to_binary(?MINIMISED_HEX))),
    [#tx_in{witness = MinWitness}] = Min#transaction.inputs,
    ?assertEqual(MinWitness, witness(maps:get(op_success80, Ctx))),
    assert_refused(op_success80, ?REASON(?OP_SUCCESS_TEXT), Ctx).

leaf_version_refused(Ctx) ->
    assert_refused(leaf_version_c2, ?REASON(?LEAF_VERSION_TEXT), Ctx).

pubkeytype_refused(Ctx) ->
    assert_refused(pubkeytype, ?REASON(?PUBKEYTYPE_TEXT), Ctx).

pubkeytype_before_weight(Ctx) ->
    assert_refused(pubkeytype_weight, ?REASON(?PUBKEYTYPE_TEXT), Ctx).

pubkeytype_before_cleanstack(Ctx) ->
    assert_refused(pubkeytype_clean, ?REASON(?PUBKEYTYPE_TEXT), Ctx).

pubkeytype_before_empty_pubkey(Ctx) ->
    assert_refused(pubkeytype_emptypk, ?REASON(?PUBKEYTYPE_TEXT), Ctx).

sendraw_op_success_refused(Ctx) ->
    Tx = spend_tx(maps:get(op_success80, Ctx)),
    Res = beamchain_rpc:rpc_sendrawtransaction([hex(Tx)]),
    ?assertMatch({error, -26, _}, Res),
    {error, -26, Msg} = Res,
    Reason = ?REASON(?OP_SUCCESS_TEXT),
    ?assertMatch(<<Reason:(byte_size(Reason))/binary, _/binary>>, Msg),
    ?assertNot(in_pool(Tx)).

control_tapscript_accepted(Ctx) ->
    Tx = spend_tx(maps:get(control_tapscript, Ctx)),
    Row = tma(Tx),
    ?assertEqual(true, maps:get(<<"allowed">>, Row)).

consensus_valid_under_block_flags(Ctx) ->
    Flags = beamchain_script:flags_for_height(900000, mainnet),
    lists:foreach(
      fun(Name) ->
          #{spk := Spk} = C = maps:get(Name, Ctx),
          ?assertEqual({Name, ok},
                       {Name, beamchain_script:verify_script_error(
                                <<>>, Spk, witness(C), Flags, #{})})
      end,
      [op_success80, leaf_version_c2, pubkeytype]).

block_with_discouraged_spends_connects(Ctx) ->
    Txs = [spend_tx(maps:get(N, Ctx))
           || N <- [op_success80, leaf_version_c2, pubkeytype]],
    {ok, {_, H0}} = beamchain_chainstate:get_tip(),
    ?assertEqual(ok, beamchain_chainstate:connect_block(next_block(Txs))),
    ?assertMatch({ok, {_, H}} when H =:= H0 + 1,
                 beamchain_chainstate:get_tip()).

%%% --- helpers -----------------------------------------------------------

assert_refused(Name, Reason, Ctx) ->
    Tx = spend_tx(maps:get(Name, Ctx)),
    Row = tma(Tx),
    ?assertEqual({Name, false}, {Name, maps:get(<<"allowed">>, Row)}),
    ?assertEqual({Name, Reason},
                 {Name, maps:get(<<"reject-reason">>, Row, missing)}),
    ?assertNot(in_pool(Tx)).

tma(Tx) ->
    {ok, [Row]} = beamchain_rpc:handle_method(<<"testmempoolaccept">>,
                                              [[hex(Tx)]], undefined),
    Row.

%% Internal key G (secp256k1 generator x), as in the minimised case.
internal_key() ->
    <<16#79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798:256>>.

p2tr_leaf(LeafVer, LeafHex) ->
    Leaf = binary:decode_hex(list_to_binary(LeafHex)),
    LeafLen = byte_size(Leaf),
    true = LeafLen < 16#fd,
    P = internal_key(),
    LeafHash = beamchain_crypto:tagged_hash(
                 <<"TapLeaf">>, <<LeafVer, LeafLen, Leaf/binary>>),
    Tweak = beamchain_crypto:tagged_hash(<<"TapTweak">>,
                                         <<P/binary, LeafHash/binary>>),
    {ok, Q, Parity} = beamchain_crypto:xonly_pubkey_tweak_add(P, Tweak),
    #{leaf => Leaf,
      control => <<(LeafVer bor Parity), P/binary>>,
      spk => <<16#51, 16#20, Q/binary>>}.

witness(#{leaf := Leaf, control := Control}) -> [Leaf, Control].

spend_tx(#{outpoint := {Txid, Vout}} = C) ->
    In = #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                script_sig = <<>>, sequence = 16#fffffffe,
                witness = witness(C)},
    #transaction{version = 2, inputs = [In],
                 outputs = [#tx_out{value = ?FUND_VALUE - ?SPEND_FEE,
                                    script_pubkey = p2wpkh_spk()}],
                 locktime = 0}.

%% Fund one P2TR output per case in a mined block.
fund(Cases) ->
    Leaves = [{Name, p2tr_leaf(V, Hex)} || {Name, V, Hex} <- Cases],
    Cb = coinbase_txid_at(2),
    Outs = [{?FUND_VALUE, maps:get(spk, L)} || {_, L} <- Leaves],
    F = sign_p2wpkh(Cb, 1, ?CB_VALUE, Outs),
    ok = beamchain_chainstate:connect_block(next_block([F])),
    FTxid = txid(F),
    {Ctx, _} = lists:foldl(
                 fun({Name, L}, {Acc, I}) ->
                     {Acc#{Name => L#{outpoint => {FTxid, I}}}, I + 1}
                 end, {#{}, 0}, Leaves),
    Ctx.

setup() ->
    TmpDir = chain_setup(),
    build_chain(110),
    Ctx = fund(cases()),
    build_chain(111),
    catch gen_server:stop(beamchain_mempool),
    {ok, MP} = beamchain_mempool:start_link(),
    unlink(MP),
    {TmpDir, Ctx}.

teardown({TmpDir, _}) ->
    chain_teardown(TmpDir).

txid(Tx) -> beamchain_serialize:tx_hash(Tx).

in_pool(Tx) -> beamchain_mempool:has_tx(txid(Tx)).

hex(T) ->
    beamchain_serialize:hex_encode(beamchain_serialize:encode_transaction(T)).

chain_setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_stdflags_tapdisc_" ++
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

chain_teardown(TmpDir) ->
    catch beamchain_fault:clear_all(),
    catch gen_server:stop(beamchain_mempool),
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

pub() ->
    {ok, Pub} = beamchain_crypto:pubkey_from_privkey(?PRIV),
    Pub.

p2wpkh_spk() ->
    <<16#00, 20, (beamchain_crypto:hash160(pub()))/binary>>.

%% Recent timestamps (the last blocks are inside 24 h) so the node can
%% leave IBD; strictly increasing so MTP never blocks a block.
ts(Height) ->
    erlang:system_time(second) - 200 * 600 + Height * 600.

coinbase(Height, Tag) ->
    HeightBin = beamchain_validation:encode_bip34_height(Height),
    TagBin = iolist_to_binary(Tag),
    ScriptSig = <<HeightBin/binary, (byte_size(TagBin)):8,
                  TagBin/binary, 0:32>>,
    #transaction{
        version = 1,
        inputs = [#tx_in{prev_out = #outpoint{hash = <<0:256>>,
                                              index = 16#ffffffff},
                         script_sig = ScriptSig, sequence = 16#ffffffff,
                         witness = []}],
        outputs = [#tx_out{value = ?CB_VALUE, script_pubkey = ?OP_TRUE},
                   #tx_out{value = ?CB_VALUE, script_pubkey = p2wpkh_spk()}],
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

%% A block on the tip holding Txs. When any tx carries a witness the
%% coinbase gets Core's BIP-141 commitment output.
next_block(Txs) ->
    {ok, {TipHash, TipH}} = beamchain_chainstate:get_tip(),
    H = TipH + 1,
    Cb0 = coinbase(H, <<"g2">>),
    Cb = case lists:any(fun has_witness/1, Txs) of
             false -> Cb0;
             true -> add_witness_commitment(Cb0, Txs)
         end,
    mine_block(TipHash, H, [Cb | Txs], ts(H)).

has_witness(#transaction{inputs = Ins}) ->
    lists:any(fun(#tx_in{witness = W}) -> W =/= [] end, Ins).

add_witness_commitment(Cb0, Txs) ->
    Nonce = <<0:256>>,
    WTxids = [<<0:256>> | [beamchain_serialize:wtx_hash(T) || T <- Txs]],
    Commitment = beamchain_serialize:compute_witness_commitment(WTxids, Nonce),
    Out = #tx_out{value = 0,
                  script_pubkey = <<16#6a, 16#24, 16#aa, 16#21, 16#a9, 16#ed,
                                    Commitment/binary>>},
    [CbIn] = Cb0#transaction.inputs,
    Cb0#transaction{inputs = [CbIn#tx_in{witness = [Nonce]}],
                    outputs = Cb0#transaction.outputs ++ [Out]}.

build_chain(ToHeight) ->
    {ok, {_, TipH}} = beamchain_chainstate:get_tip(),
    lists:foreach(fun(_) ->
        ok = beamchain_chainstate:connect_block(next_block([]))
    end, lists:seq(TipH + 1, ToHeight)).

coinbase_txid_at(Height) ->
    {ok, #{hash := Hash}} = beamchain_db:get_block_index(Height),
    {ok, #block{transactions = [Cb | _]}} = beamchain_db:get_block(Hash),
    beamchain_serialize:tx_hash(Cb).

%% Spend a P2WPKH output into Outputs ({Value, Spk}).
sign_p2wpkh(Txid, Vout, Amount, Outputs) ->
    Pub = pub(),
    In = #tx_in{prev_out = #outpoint{hash = Txid, index = Vout},
                script_sig = <<>>, sequence = 16#fffffffe, witness = []},
    Tx0 = #transaction{version = 2, inputs = [In],
                       outputs = [#tx_out{value = V, script_pubkey = S}
                                  || {V, S} <- Outputs],
                       locktime = 0},
    ScriptCode = <<16#76, 16#a9, 20, (beamchain_crypto:hash160(Pub))/binary,
                   16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(Tx0, 0, ScriptCode, Amount,
                                                  ?SIGHASH_ALL),
    {ok, Der} = beamchain_crypto:ecdsa_sign(SigHash, ?PRIV),
    Tx0#transaction{inputs = [In#tx_in{witness = [<<Der/binary, ?SIGHASH_ALL>>,
                                                  Pub]}]}.
