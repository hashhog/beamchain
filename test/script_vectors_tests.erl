-module(script_vectors_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Bitcoin Core script_tests.json test harness
%%% ===================================================================

%% Path relative to project root (test/data/ is committed to the repo).
-define(SCRIPT_TESTS_PATH, "test/data/script_tests.json").

%%% -------------------------------------------------------------------
%%% Hex utilities
%%% -------------------------------------------------------------------

hex_to_bin(Hex) ->
    beamchain_serialize:hex_decode(Hex).

%%% -------------------------------------------------------------------
%%% Script assembly parser
%%% -------------------------------------------------------------------

%% Opcode name (without OP_ prefix) -> byte value
opcode_byte(Name) ->
    case Name of
        "0" -> 16#00; "FALSE" -> 16#00;
        "1NEGATE" -> 16#4f;
        "RESERVED" -> 16#50;
        "1" -> 16#51; "TRUE" -> 16#51;
        "2" -> 16#52; "3" -> 16#53; "4" -> 16#54; "5" -> 16#55;
        "6" -> 16#56; "7" -> 16#57; "8" -> 16#58; "9" -> 16#59;
        "10" -> 16#5a; "11" -> 16#5b; "12" -> 16#5c; "13" -> 16#5d;
        "14" -> 16#5e; "15" -> 16#5f; "16" -> 16#60;
        "NOP" -> 16#61; "VER" -> 16#62;
        "IF" -> 16#63; "NOTIF" -> 16#64;
        "VERIF" -> 16#65; "VERNOTIF" -> 16#66;
        "ELSE" -> 16#67; "ENDIF" -> 16#68;
        "VERIFY" -> 16#69; "RETURN" -> 16#6a;
        "TOALTSTACK" -> 16#6b; "FROMALTSTACK" -> 16#6c;
        "2DROP" -> 16#6d; "2DUP" -> 16#6e; "3DUP" -> 16#6f;
        "2OVER" -> 16#70; "2ROT" -> 16#71; "2SWAP" -> 16#72;
        "IFDUP" -> 16#73; "DEPTH" -> 16#74;
        "DROP" -> 16#75; "DUP" -> 16#76;
        "NIP" -> 16#77; "OVER" -> 16#78;
        "PICK" -> 16#79; "ROLL" -> 16#7a;
        "ROT" -> 16#7b; "SWAP" -> 16#7c; "TUCK" -> 16#7d;
        "CAT" -> 16#7e; "SUBSTR" -> 16#7f; "LEFT" -> 16#80; "RIGHT" -> 16#81;
        "SIZE" -> 16#82;
        "INVERT" -> 16#83; "AND" -> 16#84; "OR" -> 16#85; "XOR" -> 16#86;
        "EQUAL" -> 16#87; "EQUALVERIFY" -> 16#88;
        "RESERVED1" -> 16#89; "RESERVED2" -> 16#8a;
        "1ADD" -> 16#8b; "1SUB" -> 16#8c;
        "2MUL" -> 16#8d; "2DIV" -> 16#8e;
        "NEGATE" -> 16#8f; "ABS" -> 16#90;
        "NOT" -> 16#91; "0NOTEQUAL" -> 16#92;
        "ADD" -> 16#93; "SUB" -> 16#94;
        "MUL" -> 16#95; "DIV" -> 16#96; "MOD" -> 16#97;
        "LSHIFT" -> 16#98; "RSHIFT" -> 16#99;
        "BOOLAND" -> 16#9a; "BOOLOR" -> 16#9b;
        "NUMEQUAL" -> 16#9c; "NUMEQUALVERIFY" -> 16#9d;
        "NUMNOTEQUAL" -> 16#9e;
        "LESSTHAN" -> 16#9f; "GREATERTHAN" -> 16#a0;
        "LESSTHANOREQUAL" -> 16#a1; "GREATERTHANOREQUAL" -> 16#a2;
        "MIN" -> 16#a3; "MAX" -> 16#a4; "WITHIN" -> 16#a5;
        "RIPEMD160" -> 16#a6; "SHA1" -> 16#a7; "SHA256" -> 16#a8;
        "HASH160" -> 16#a9; "HASH256" -> 16#aa;
        "CODESEPARATOR" -> 16#ab;
        "CHECKSIG" -> 16#ac; "CHECKSIGVERIFY" -> 16#ad;
        "CHECKMULTISIG" -> 16#ae; "CHECKMULTISIGVERIFY" -> 16#af;
        "NOP1" -> 16#b0;
        "CHECKLOCKTIMEVERIFY" -> 16#b1; "NOP2" -> 16#b1;
        "CHECKSEQUENCEVERIFY" -> 16#b2; "NOP3" -> 16#b2;
        "NOP4" -> 16#b3; "NOP5" -> 16#b4; "NOP6" -> 16#b5;
        "NOP7" -> 16#b6; "NOP8" -> 16#b7; "NOP9" -> 16#b8; "NOP10" -> 16#b9;
        "CHECKSIGADD" -> 16#ba;
        "INVALIDOPCODE" -> 16#ff;
        _ -> undefined
    end.

%% Encode a script number (CScriptNum format)
encode_script_num(0) -> <<>>;
encode_script_num(N) when N > 0 -> encode_script_num_pos(N, <<>>);
encode_script_num(N) when N < 0 -> encode_script_num_neg(-N, <<>>).

encode_script_num_pos(0, Acc) ->
    %% Check if high bit of last byte is set
    Bytes = binary_to_list(Acc),
    case Bytes of
        [] -> <<>>;
        _ ->
            Last = lists:last(Bytes),
            case Last band 16#80 of
                0 -> Acc;
                _ -> <<Acc/binary, 16#00>>
            end
    end;
encode_script_num_pos(N, Acc) ->
    Byte = N band 16#ff,
    encode_script_num_pos(N bsr 8, <<Acc/binary, Byte>>).

encode_script_num_neg(0, Acc) ->
    Bytes = binary_to_list(Acc),
    case Bytes of
        [] -> <<>>;
        _ ->
            Last = lists:last(Bytes),
            case Last band 16#80 of
                0 ->
                    %% Set the sign bit on last byte
                    Init = lists:sublist(Bytes, length(Bytes) - 1),
                    list_to_binary(Init ++ [Last bor 16#80]);
                _ ->
                    <<Acc/binary, 16#80>>
            end
    end;
encode_script_num_neg(N, Acc) ->
    Byte = N band 16#ff,
    encode_script_num_neg(N bsr 8, <<Acc/binary, Byte>>).

%% Push data with appropriate opcode
push_data(Data) when byte_size(Data) >= 1, byte_size(Data) =< 16#4b ->
    Len = byte_size(Data),
    <<Len, Data/binary>>;
push_data(Data) when byte_size(Data) =< 16#ff ->
    Len = byte_size(Data),
    <<16#4c, Len, Data/binary>>;
push_data(Data) when byte_size(Data) =< 16#ffff ->
    Len = byte_size(Data),
    <<16#4d, Len:16/little, Data/binary>>;
push_data(Data) ->
    Len = byte_size(Data),
    <<16#4e, Len:32/little, Data/binary>>.

%% Assemble a single ASM token to bytes
assemble_token(Token) ->
    %% Strip OP_ prefix if present
    Name = case Token of
        "OP_" ++ Rest -> Rest;
        _ -> Token
    end,
    case Name of
        %% Hex data: 0xNN...
        "0x" ++ Hex ->
            hex_to_bin(Hex);
        %% Quoted string
        [$' | QuotedRest] ->
            Str = case lists:last(QuotedRest) of
                $' -> lists:sublist(QuotedRest, length(QuotedRest) - 1);
                _  -> QuotedRest
            end,
            case Str of
                [] -> <<16#00>>;
                _  -> push_data(list_to_binary(Str))
            end;
        _ ->
            case opcode_byte(Name) of
                undefined ->
                    %% Try as decimal number
                    try
                        N = list_to_integer(Name),
                        if
                            N =:= 0 -> <<16#00>>;
                            N =:= -1 -> <<16#4f>>;
                            N >= 1, N =< 16 -> <<(16#50 + N)>>;
                            true ->
                                Data = encode_script_num(N),
                                push_data(Data)
                        end
                    catch _:_ ->
                        io:format(standard_error, "WARNING: Unknown token: ~s~n", [Token]),
                        <<>>
                    end;
                Byte ->
                    <<Byte>>
            end
    end.

%% Assemble ASM string to raw script binary
assemble_script(AsmStr) ->
    Trimmed = string:trim(AsmStr),
    case Trimmed of
        "" -> <<>>;
        _ ->
            Tokens = string:tokens(Trimmed, " "),
            list_to_binary([assemble_token(T) || T <- Tokens])
    end.

%%% -------------------------------------------------------------------
%%% Flag parsing
%%% -------------------------------------------------------------------

parse_flags(FlagsStr) ->
    Trimmed = string:trim(FlagsStr),
    case Trimmed of
        "" -> 0;
        "NONE" -> 0;
        _ ->
            Flags = string:tokens(Trimmed, ","),
            lists:foldl(fun(Flag, Acc) ->
                F = string:trim(Flag),
                Acc bor flag_value(F)
            end, 0, Flags)
    end.

flag_value("P2SH") -> ?SCRIPT_VERIFY_P2SH;
flag_value("STRICTENC") -> ?SCRIPT_VERIFY_STRICTENC;
flag_value("DERSIG") -> ?SCRIPT_VERIFY_DERSIG;
flag_value("LOW_S") -> ?SCRIPT_VERIFY_LOW_S;
flag_value("NULLDUMMY") -> ?SCRIPT_VERIFY_NULLDUMMY;
flag_value("SIGPUSHONLY") -> ?SCRIPT_VERIFY_SIGPUSHONLY;
flag_value("MINIMALDATA") -> ?SCRIPT_VERIFY_MINIMALDATA;
flag_value("DISCOURAGE_UPGRADABLE_NOPS") -> ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
flag_value("CLEANSTACK") -> ?SCRIPT_VERIFY_CLEANSTACK;
flag_value("CHECKLOCKTIMEVERIFY") -> ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
flag_value("CHECKSEQUENCEVERIFY") -> ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
flag_value("WITNESS") -> ?SCRIPT_VERIFY_WITNESS;
flag_value("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM") -> ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
flag_value("MINIMALIF") -> ?SCRIPT_VERIFY_MINIMALIF;
flag_value("NULLFAIL") -> ?SCRIPT_VERIFY_NULLFAIL;
flag_value("WITNESS_PUBKEYTYPE") -> ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;
flag_value("CONST_SCRIPTCODE") -> ?SCRIPT_VERIFY_CONST_SCRIPTCODE;
flag_value("TAPROOT") -> ?SCRIPT_VERIFY_TAPROOT;
flag_value("DISCOURAGE_OP_SUCCESS") -> ?SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS;
flag_value("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION") -> ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;
flag_value("DISCOURAGE_UPGRADABLE_PUBKEYTYPE") -> ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;
flag_value("NONE") -> 0;
flag_value(Unknown) ->
    io:format(standard_error, "WARNING: Unknown flag: ~s~n", [Unknown]),
    0.

%%% -------------------------------------------------------------------
%%% Bitcoin Core crediting/spending transaction construction
%%%
%%% Matches CTransaction BuildCreditingTransaction / BuildSpendingTransaction
%%% from Bitcoin Core's src/test/script_tests.cpp:
%%%   - Crediting tx: version=1, locktime=0, one input (null prevout
%%%     hash=0, index=0xFFFFFFFF, scriptSig=OP_0 OP_0, seq=0xFFFFFFFF),
%%%     one output (value=0, scriptPubKey=test's scriptPubKey).
%%%   - Spending tx: version=1, locktime=0, one input (prevout=txid of
%%%     crediting tx : 0, scriptSig=test's scriptSig, seq=0xFFFFFFFF),
%%%     one output (value=0, scriptPubKey=empty).
%%% -------------------------------------------------------------------

make_crediting_tx(ScriptPubKey) ->
    make_crediting_tx(ScriptPubKey, 0).

make_crediting_tx(ScriptPubKey, Amount) ->
    #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<16#00, 16#00>>,  %% OP_0 OP_0
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{value = Amount, script_pubkey = ScriptPubKey}],
        locktime = 0,
        txid = undefined,
        wtxid = undefined
    }.

make_spending_tx(CreditingTx, ScriptSig) ->
    make_spending_tx(CreditingTx, ScriptSig, []).

make_spending_tx(CreditingTx, ScriptSig, Witness) ->
    CreditTxId = beamchain_serialize:tx_hash(CreditingTx),
    %% Bitcoin Core: spending tx output value = crediting tx output value
    [CreditOutput] = CreditingTx#transaction.outputs,
    OutputValue = CreditOutput#tx_out.value,
    #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = CreditTxId, index = 0},
            script_sig = ScriptSig,
            sequence = 16#ffffffff,
            witness = Witness
        }],
        outputs = [#tx_out{value = OutputValue, script_pubkey = <<>>}],
        locktime = 0,
        txid = undefined,
        wtxid = undefined
    }.

%% Build a real sig checker using the tuple form {Tx, InputIndex, Amount}.
%% The script interpreter extracts the scriptCode from its internal state
%% and computes real sighashes via beamchain_script:sighash_legacy/4.
%% It then calls beamchain_crypto:ecdsa_verify_cached/3 for ECDSA verification.
make_sig_checker(SpendingTx) ->
    {SpendingTx, 0, 0}.

make_sig_checker(SpendingTx, Amount) ->
    {SpendingTx, 0, Amount}.

%% Ensure the sig_cache ETS tables exist so ecdsa_verify_cached doesn't crash.
%% In production these are created by the beamchain_sig_cache gen_server.
ensure_sig_cache() ->
    %% Seed the startup nonce in persistent_term if not already present.
    %% In production this is done by beamchain_sig_cache:init/1.
    case persistent_term:get(beamchain_sig_cache_nonce, undefined) of
        undefined ->
            persistent_term:put(beamchain_sig_cache_nonce,
                                crypto:strong_rand_bytes(32));
        _ -> ok
    end,
    try ets:info(beamchain_sig_cache_tab, size) of
        undefined ->
            ets:new(beamchain_sig_cache_tab, [set, public, named_table,
                                               {read_concurrency, true}]),
            ets:new(beamchain_sig_cache_order, [ordered_set, public, named_table]);
        _ ->
            ok
    catch
        _:_ ->
            ets:new(beamchain_sig_cache_tab, [set, public, named_table,
                                               {read_concurrency, true}]),
            ets:new(beamchain_sig_cache_order, [ordered_set, public, named_table])
    end.

%%% -------------------------------------------------------------------
%%% Taproot placeholder resolution
%%% -------------------------------------------------------------------

%% The secp256k1 generator point x-coordinate (used as internal key)
-define(TAPROOT_INTERNAL_KEY,
    <<16#79, 16#BE, 16#66, 16#7E, 16#F9, 16#DC, 16#BB, 16#AC,
      16#55, 16#A0, 16#62, 16#95, 16#CE, 16#87, 16#0B, 16#07,
      16#02, 16#9B, 16#FC, 16#DB, 16#2D, 16#CE, 16#28, 16#D9,
      16#59, 16#F2, 16#81, 16#5B, 16#16, 16#F8, 16#17, 16#98>>).

%% Check if a witness array contains taproot placeholders
has_taproot_placeholders(WitArray, PubStr) ->
    HasWitPlaceholder = lists:any(fun(Item) ->
        is_binary(Item) andalso
        binary:match(Item, <<"#">>) =/= nomatch
    end, WitArray),
    HasPubPlaceholder = string:find(PubStr, "#") =/= nomatch,
    HasWitPlaceholder orelse HasPubPlaceholder.

%% Resolve taproot placeholders in a witness test vector.
%% Returns {ResolvedWitBins, ResolvedPubAsm}.
resolve_taproot_placeholders(WitHexItems, PubAsm) ->
    %% Find the #SCRIPT# item and extract its ASM
    {ScriptBin, ResolvedWitItems} = resolve_witness_items(WitHexItems),
    %% Compute tapleaf hash: tagged_hash("TapLeaf", 0xc0 || compact_size(len) || script)
    ScriptLen = byte_size(ScriptBin),
    CompactLen = beamchain_serialize:encode_varint(ScriptLen),
    LeafData = <<16#c0, CompactLen/binary, ScriptBin/binary>>,
    LeafHash = beamchain_crypto:tagged_hash(<<"TapLeaf">>, LeafData),
    %% Single leaf: merkle root = leaf hash
    MerkleRoot = LeafHash,
    %% Compute tweak: tagged_hash("TapTweak", internal_key || merkle_root)
    TweakHash = beamchain_crypto:tagged_hash(
        <<"TapTweak">>,
        <<?TAPROOT_INTERNAL_KEY/binary, MerkleRoot/binary>>),
    %% Compute tweaked output key via secp256k1 NIF
    {ok, OutputKey, Parity} = beamchain_crypto:xonly_pubkey_tweak_add(
        ?TAPROOT_INTERNAL_KEY, TweakHash),
    %% Build control block: (0xc0 | parity) || internal_key (33 bytes)
    LeafVersionByte = 16#c0 bor (Parity band 1),
    ControlBlock = <<LeafVersionByte, ?TAPROOT_INTERNAL_KEY/binary>>,
    %% Replace #CONTROLBLOCK# in witness items
    FinalWitItems = lists:map(fun(Item) ->
        case Item of
            controlblock_placeholder -> ControlBlock;
            _ -> Item
        end
    end, ResolvedWitItems),
    %% Replace #TAPROOTOUTPUT# in scriptPubKey ASM
    %% Prefix with 0x so the ASM assembler recognizes it as hex data
    OutputKeyHex = "0x" ++ binary_to_list(beamchain_serialize:hex_encode(OutputKey)),
    ResolvedPubAsm = re:replace(PubAsm, "#TAPROOTOUTPUT#", OutputKeyHex,
                                [{return, list}, global]),
    {FinalWitItems, ResolvedPubAsm}.

%% Process witness hex items, resolving #SCRIPT# and marking #CONTROLBLOCK#.
%% Returns {ScriptBin, ResolvedItems} where ScriptBin is the assembled script
%% and ResolvedItems has binaries for normal items, the script binary for
%% #SCRIPT# items, and the atom controlblock_placeholder for #CONTROLBLOCK#.
resolve_witness_items(WitHexItems) ->
    resolve_witness_items(WitHexItems, undefined, []).

resolve_witness_items([], ScriptBin, Acc) ->
    {ScriptBin, lists:reverse(Acc)};
resolve_witness_items([Item | Rest], ScriptBin, Acc) ->
    ItemStr = binary_to_list(Item),
    case ItemStr of
        "#SCRIPT# " ++ AsmStr ->
            %% Assemble the ASM into script bytes
            Script = assemble_script(AsmStr),
            resolve_witness_items(Rest, Script, [Script | Acc]);
        "#CONTROLBLOCK#" ->
            resolve_witness_items(Rest, ScriptBin, [controlblock_placeholder | Acc]);
        _ ->
            %% Normal hex witness item
            Bin = hex_to_bin(ItemStr),
            resolve_witness_items(Rest, ScriptBin, [Bin | Acc])
    end.

%%% -------------------------------------------------------------------
%%% Main test
%%% -------------------------------------------------------------------

script_vectors_test_() ->
    {timeout, 300, fun run_script_vectors/0}.

run_script_vectors() ->
    %% Ensure sig_cache ETS tables exist for ecdsa_verify_cached
    ensure_sig_cache(),
    {ok, JsonBin} = file:read_file(?SCRIPT_TESTS_PATH),
    Vectors = jsx:decode(JsonBin, [return_maps]),

    Results = lists:foldl(fun(Entry, Acc) ->
        case Entry of
            L when is_list(L) ->
                N = length(L),
                %% Witness tests have a sub-list as first element
                IsWitness = N >= 1 andalso is_list(hd(L)),
                if
                    IsWitness andalso (N =:= 5 orelse N =:= 6) ->
                        %% Witness format: [[wit_hex1, wit_hex2, ..., amount],
                        %%                  scriptSig, scriptPubKey, flags, expected]
                        %% or with comment at position 6.
                        %% Amount is LAST element of the sub-array.
                        WitArray = hd(L),
                        PubStr = binary_to_list(lists:nth(3, L)),
                        HasPlaceholders = has_taproot_placeholders(WitArray, PubStr),
                        AmountRaw = lists:last(WitArray),
                        WitHexItems = lists:droplast(WitArray),
                        SigAsm = binary_to_list(lists:nth(2, L)),
                        FlagsStr = binary_to_list(lists:nth(4, L)),
                        Expected = binary_to_list(lists:nth(5, L)),
                        Comment = case N of
                            6 -> binary_to_list(lists:nth(6, L));
                            _ -> ""
                        end,
                        AmountSat = parse_amount(AmountRaw),
                        case HasPlaceholders of
                            true ->
                                %% Resolve taproot placeholders
                                {WitnessBins, ResolvedPubAsm} =
                                    resolve_taproot_placeholders(WitHexItems, PubStr),
                                run_one_witness_test(SigAsm, ResolvedPubAsm, FlagsStr,
                                                     Expected, Comment, WitnessBins,
                                                     AmountSat, Acc);
                            false ->
                                PubAsm = PubStr,
                                WitnessBins = [hex_to_bin(binary_to_list(W)) || W <- WitHexItems],
                                run_one_witness_test(SigAsm, PubAsm, FlagsStr, Expected,
                                                     Comment, WitnessBins, AmountSat, Acc)
                        end;
                    IsWitness ->
                        %% Unknown witness format, skip
                        maps:update_with(skip, fun(V) -> V + 1 end, Acc);
                    N =:= 1; N =:= 2; N =:= 3 ->
                        %% Comment or malformed, skip
                        Acc;
                    N >= 6 ->
                        %% Unknown format, skip
                        maps:update_with(skip, fun(V) -> V + 1 end, Acc);
                    N =:= 4; N =:= 5 ->
                        SigAsm = binary_to_list(lists:nth(1, L)),
                        PubAsm = binary_to_list(lists:nth(2, L)),
                        FlagsStr = binary_to_list(lists:nth(3, L)),
                        Expected = binary_to_list(lists:nth(4, L)),
                        Comment = case N of
                            5 -> binary_to_list(lists:nth(5, L));
                            _ -> ""
                        end,
                        run_one_test(SigAsm, PubAsm, FlagsStr, Expected, Comment, Acc);
                    true ->
                        Acc
                end;
            _ ->
                Acc
        end
    end, #{pass => 0, fail => 0, error => 0, skip => 0, total => 0,
           witness_pass => 0, witness_fail => 0, witness_error => 0,
           witness_total => 0}, Vectors),

    io:format(standard_error, "~n=== Script Test Vector Results ===~n", []),
    io:format(standard_error, "Non-witness tests: ~p~n", [maps:get(total, Results)]),
    io:format(standard_error, "  PASS:  ~p~n", [maps:get(pass, Results)]),
    io:format(standard_error, "  FAIL:  ~p~n", [maps:get(fail, Results)]),
    io:format(standard_error, "  ERROR: ~p~n", [maps:get(error, Results)]),
    io:format(standard_error, "Witness tests: ~p~n", [maps:get(witness_total, Results)]),
    io:format(standard_error, "  PASS:  ~p~n", [maps:get(witness_pass, Results)]),
    io:format(standard_error, "  FAIL:  ~p~n", [maps:get(witness_fail, Results)]),
    io:format(standard_error, "  ERROR: ~p~n", [maps:get(witness_error, Results)]),
    io:format(standard_error, "  Skipped: ~p~n", [maps:get(skip, Results)]),

    TotalFail = maps:get(fail, Results) + maps:get(witness_fail, Results),
    TotalError = maps:get(error, Results) + maps:get(witness_error, Results),
    ?assertEqual(0, TotalFail),
    ?assertEqual(0, TotalError),
    ok.

%% Parse amount from JSON: can be integer or float (BTC, multiply by 1e8)
parse_amount(V) when is_integer(V) -> V;
parse_amount(V) when is_float(V) -> round(V * 100000000).

run_one_test(SigAsm, PubAsm, FlagsStr, Expected, Comment, Acc) ->
    Acc1 = maps:update_with(total, fun(V) -> V + 1 end, Acc),
    try
        ScriptSig = assemble_script(SigAsm),
        ScriptPubKey = assemble_script(PubAsm),
        Flags = parse_flags(FlagsStr),

        %% Build proper crediting and spending transactions
        %% matching Bitcoin Core's BuildCreditingTransaction/BuildSpendingTransaction
        CreditingTx = make_crediting_tx(ScriptPubKey),
        SpendingTx = make_spending_tx(CreditingTx, ScriptSig),
        Checker = make_sig_checker(SpendingTx),

        Result = beamchain_script:verify_script(ScriptSig, ScriptPubKey, [], Flags, Checker),
        GotOk = (Result =:= true),
        ExpectedOk = (Expected =:= "OK"),

        case GotOk =:= ExpectedOk of
            true ->
                maps:update_with(pass, fun(V) -> V + 1 end, Acc1);
            false ->
                io:format("FAIL: expected=~s got=~p sig=[~s] pub=[~s] flags=~s ~s~n",
                          [Expected, Result, SigAsm, PubAsm, FlagsStr, Comment]),
                maps:update_with(fail, fun(V) -> V + 1 end, Acc1)
        end
    catch
        Class:Reason ->
            ExpectedOk2 = (Expected =:= "OK"),
            case ExpectedOk2 of
                false ->
                    %% Expected failure and got exception, count as pass
                    maps:update_with(pass, fun(V) -> V + 1 end, Acc1);
                true ->
                    io:format("ERROR: ~p:~p sig=[~s] pub=[~s] flags=~s ~s~n",
                              [Class, Reason, SigAsm, PubAsm, FlagsStr, Comment]),
                    maps:update_with(error, fun(V) -> V + 1 end, Acc1)
            end
    end.

run_one_witness_test(SigAsm, PubAsm, FlagsStr, Expected, Comment,
                     WitnessBins, AmountSat, Acc) ->
    Acc1 = maps:update_with(witness_total, fun(V) -> V + 1 end, Acc),
    try
        ScriptSig = assemble_script(SigAsm),
        ScriptPubKey = assemble_script(PubAsm),
        Flags = parse_flags(FlagsStr),

        %% Build crediting tx with the correct amount
        CreditingTx = make_crediting_tx(ScriptPubKey, AmountSat),
        %% Build spending tx with witness data on the input
        SpendingTx = make_spending_tx(CreditingTx, ScriptSig, WitnessBins),
        %% Sig checker needs the amount for BIP143 sighash
        Checker = make_sig_checker(SpendingTx, AmountSat),

        Result = beamchain_script:verify_script(
            ScriptSig, ScriptPubKey, WitnessBins, Flags, Checker),
        GotOk = (Result =:= true),
        ExpectedOk = (Expected =:= "OK"),

        case GotOk =:= ExpectedOk of
            true ->
                maps:update_with(witness_pass, fun(V) -> V + 1 end, Acc1);
            false ->
                io:format("WITNESS FAIL: expected=~s got=~p sig=[~s] pub=[~s] flags=~s ~s~n",
                          [Expected, Result, SigAsm, PubAsm, FlagsStr, Comment]),
                maps:update_with(witness_fail, fun(V) -> V + 1 end, Acc1)
        end
    catch
        Class:Reason ->
            ExpectedOk2 = (Expected =:= "OK"),
            case ExpectedOk2 of
                false ->
                    %% Expected failure and got exception, count as pass
                    maps:update_with(witness_pass, fun(V) -> V + 1 end, Acc1);
                true ->
                    io:format("WITNESS ERROR: ~p:~p sig=[~s] pub=[~s] flags=~s ~s~n",
                              [Class, Reason, SigAsm, PubAsm, FlagsStr, Comment]),
                    maps:update_with(witness_error, fun(V) -> V + 1 end, Acc1)
            end
    end.
