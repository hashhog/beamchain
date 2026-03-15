-module(beamchain_miniscript_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Test Keys (compressed pubkeys for testing)
%%% ===================================================================

-define(KEY1, <<16#02, 16#c6, 16#04, 16#7f, 16#94, 16#41, 16#ed, 16#7d,
                16#6d, 16#30, 16#45, 16#40, 16#6e, 16#95, 16#c0, 16#7c,
                16#d8, 16#5c, 16#77, 16#8e, 16#4b, 16#8c, 16#ef, 16#3c,
                16#a7, 16#ab, 16#ac, 16#09, 16#b9, 16#5c, 16#70, 16#9e,
                16#e5>>).

-define(KEY2, <<16#02, 16#f9, 16#30, 16#8a, 16#01, 16#92, 16#58, 16#c3,
                16#10, 16#49, 16#34, 16#4f, 16#85, 16#f8, 16#9d, 16#52,
                16#29, 16#b5, 16#31, 16#c8, 16#45, 16#83, 16#6f, 16#99,
                16#b0, 16#86, 16#01, 16#f1, 16#13, 16#bc, 16#e0, 16#36,
                16#f9>>).

-define(KEY3, <<16#03, 16#ff, 16#f9, 16#7b, 16#d5, 16#75, 16#5e, 16#ee,
                16#a4, 16#20, 16#45, 16#3a, 16#14, 16#35, 16#52, 16#35,
                16#d3, 16#82, 16#f6, 16#47, 16#2f, 16#85, 16#68, 16#a1,
                16#8b, 16#2f, 16#05, 16#7a, 16#14, 16#60, 16#29, 16#75,
                16#56>>).

-define(HASH32, <<16#e3, 16#b0, 16#c4, 16#42, 16#98, 16#fc, 16#1c, 16#14,
                  16#9a, 16#fb, 16#f4, 16#c8, 16#99, 16#6f, 16#b9, 16#24,
                  16#27, 16#ae, 16#41, 16#e4, 16#64, 16#9b, 16#93, 16#4c,
                  16#a4, 16#95, 16#99, 16#1b, 16#78, 16#52, 16#b8, 16#55>>).

-define(HASH20, <<16#e9, 16#c3, 16#dd, 16#0c, 16#07, 16#aa, 16#c7, 16#6e,
                  16#74, 16#e5, 16#fa, 16#90, 16#df, 16#ed, 16#d0, 16#a4,
                  16#70, 16#29, 16#07, 16#33>>).

%%% ===================================================================
%%% Basic Parsing Tests
%%% ===================================================================

parse_pk_k_test_() ->
    [
        {"parse c:pk_k (B type at top level)",
         fun() ->
             Key = ?KEY1,
             Hex = binary_to_hex(Key),
             %% pk_k is K type, needs c: wrapper to be B type for top level
             Str = "c:pk_k(" ++ Hex ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({wrap_c, {pk_k, Key}}, AST)
         end},
        {"parse pk (shorthand for c:pk_k)",
         fun() ->
             Key = ?KEY1,
             Hex = binary_to_hex(Key),
             Str = "pk(" ++ Hex ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({wrap_c, {pk_k, Key}}, AST)
         end}
    ].

parse_hash_test_() ->
    [
        {"parse sha256",
         fun() ->
             Hash = ?HASH32,
             Hex = binary_to_hex(Hash),
             Str = "sha256(" ++ Hex ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({sha256, Hash}, AST)
         end},
        {"parse hash256",
         fun() ->
             Hash = ?HASH32,
             Hex = binary_to_hex(Hash),
             Str = "hash256(" ++ Hex ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({hash256, Hash}, AST)
         end},
        {"parse ripemd160",
         fun() ->
             Hash = ?HASH20,
             Hex = binary_to_hex(Hash),
             Str = "ripemd160(" ++ Hex ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({ripemd160, Hash}, AST)
         end},
        {"parse hash160",
         fun() ->
             Hash = ?HASH20,
             Hex = binary_to_hex(Hash),
             Str = "hash160(" ++ Hex ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({hash160, Hash}, AST)
         end}
    ].

parse_timelock_test_() ->
    [
        {"parse older",
         fun() ->
             Str = "older(144)",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({older, 144}, AST)
         end},
        {"parse after",
         fun() ->
             Str = "after(500000)",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({after_, 500000}, AST)
         end}
    ].

parse_wrapper_test_() ->
    [
        {"parse and_v with v wrapper",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             %% and_v(v:pk(K1), pk(K2)) is B type
             Str = "and_v(v:pk(" ++ Hex1 ++ "),pk(" ++ Hex2 ++ "))",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             Expected = {and_v, {wrap_v, {wrap_c, {pk_k, Key1}}}, {wrap_c, {pk_k, Key2}}},
             ?assertEqual(Expected, AST)
         end},
        {"parse d wrapper with Vz type (just_1)",
         fun() ->
             %% d:v:1 creates a dissatisfiable B type
             %% just_1 -> B type, v:1 -> V type with z=true
             %% Actually: v:1 is invalid (1 is B, not V)
             %% Let's use older which is Bz, wrap with v to get Vz
             Str = "d:v:older(1)",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({wrap_d, {wrap_v, {older, 1}}}, AST)
         end}
    ].

parse_combinator_test_() ->
    [
        {"parse or_i",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             Str = "or_i(pk(" ++ Hex1 ++ "),pk(" ++ Hex2 ++ "))",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             Expected = {or_i,
                         {wrap_c, {pk_k, Key1}},
                         {wrap_c, {pk_k, Key2}}},
             ?assertEqual(Expected, AST)
         end},
        {"parse and_v",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             Str = "and_v(v(pk(" ++ Hex1 ++ ")),pk(" ++ Hex2 ++ "))",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             Expected = {and_v,
                         {wrap_v, {wrap_c, {pk_k, Key1}}},
                         {wrap_c, {pk_k, Key2}}},
             ?assertEqual(Expected, AST)
         end}
    ].

parse_multi_test_() ->
    [
        {"parse multi",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Key3 = ?KEY3,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             Hex3 = binary_to_hex(Key3),
             Str = "multi(2," ++ Hex1 ++ "," ++ Hex2 ++ "," ++ Hex3 ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({multi, 2, [Key1, Key2, Key3]}, AST)
         end},
        {"parse multi_a",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             Str = "multi_a(1," ++ Hex1 ++ "," ++ Hex2 ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             ?assertEqual({multi_a, 1, [Key1, Key2]}, AST)
         end}
    ].

parse_thresh_test_() ->
    [
        {"parse or_b with two Bd subs",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             %% or_b requires Bd and Wd (second must be W type)
             %% Use s:pk to get W type for second sub
             Str = "or_b(pk(" ++ Hex1 ++ "),s:pk(" ++ Hex2 ++ "))",
             {ok, AST} = beamchain_miniscript:from_string(Str),
             Expected = {or_b, {wrap_c, {pk_k, Key1}}, {wrap_s, {wrap_c, {pk_k, Key2}}}},
             ?assertEqual(Expected, AST)
         end}
    ].

%%% ===================================================================
%%% Type System Tests
%%% ===================================================================

type_pk_k_test_() ->
    [
        {"pk_k has type K",
         fun() ->
             AST = {pk_k, ?KEY1},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('K', Type)
         end},
        {"c:pk_k has type B",
         fun() ->
             AST = {wrap_c, {pk_k, ?KEY1}},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('B', Type)
         end}
    ].

type_hash_test_() ->
    [
        {"sha256 has type B",
         fun() ->
             AST = {sha256, ?HASH32},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('B', Type)
         end},
        {"sha256 has property d (dissatisfiable)",
         fun() ->
             AST = {sha256, ?HASH32},
             Props = beamchain_miniscript:get_properties(AST),
             ?assert(maps:get(d, Props))
         end}
    ].

type_timelock_test_() ->
    [
        {"older has type B",
         fun() ->
             AST = {older, 144},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('B', Type)
         end},
        {"older is forced (f=true)",
         fun() ->
             AST = {older, 144},
             Props = beamchain_miniscript:get_properties(AST),
             ?assert(maps:get(f, Props))
         end},
        {"older has correct timelock flag (h for height)",
         fun() ->
             AST = {older, 144},  %% Height-based (bit 22 not set)
             Props = beamchain_miniscript:get_properties(AST),
             ?assert(maps:get(h, Props)),
             ?assertNot(maps:get(g, Props))
         end},
        {"older time-based has g flag",
         fun() ->
             %% Bit 22 (0x400000) set = time-based
             N = 144 bor 16#400000,
             AST = {older, N},
             Props = beamchain_miniscript:get_properties(AST),
             ?assert(maps:get(g, Props)),
             ?assertNot(maps:get(h, Props))
         end}
    ].

type_wrapper_test_() ->
    [
        {"v wrapper converts B to V",
         fun() ->
             Inner = {wrap_c, {pk_k, ?KEY1}},  %% B type
             AST = {wrap_v, Inner},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('V', Type)
         end},
        {"a wrapper converts B to W",
         fun() ->
             Inner = {wrap_c, {pk_k, ?KEY1}},  %% B type
             AST = {wrap_a, Inner},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('W', Type)
         end}
    ].

type_combinator_test_() ->
    [
        {"and_v with V and B gives B",
         fun() ->
             X = {wrap_v, {wrap_c, {pk_k, ?KEY1}}},  %% V type
             Y = {wrap_c, {pk_k, ?KEY2}},  %% B type
             AST = {and_v, X, Y},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('B', Type)
         end},
        {"or_i with two B gives B",
         fun() ->
             X = {wrap_c, {pk_k, ?KEY1}},  %% B type
             Y = {wrap_c, {pk_k, ?KEY2}},  %% B type
             AST = {or_i, X, Y},
             Type = beamchain_miniscript:get_type(AST),
             ?assertEqual('B', Type)
         end}
    ].

type_check_test_() ->
    [
        {"type check accepts valid B-type at top level",
         fun() ->
             AST = {wrap_c, {pk_k, ?KEY1}},
             Result = beamchain_miniscript:type_check(AST),
             ?assertMatch({ok, _}, Result)
         end},
        {"type check rejects K-type at top level",
         fun() ->
             AST = {pk_k, ?KEY1},  %% K type
             Result = beamchain_miniscript:type_check(AST),
             ?assertMatch({error, {invalid_top_level_type, 'K'}}, Result)
         end}
    ].

%%% ===================================================================
%%% Compilation Tests
%%% ===================================================================

compile_pk_test_() ->
    [
        {"compile pk_k",
         fun() ->
             Key = ?KEY1,
             AST = {pk_k, Key},
             Script = beamchain_miniscript:compile(AST),
             %% Should be: <33> <key>
             Expected = <<33, Key/binary>>,
             ?assertEqual(Expected, Script)
         end},
        {"compile c:pk_k (pk)",
         fun() ->
             Key = ?KEY1,
             AST = {wrap_c, {pk_k, Key}},
             Script = beamchain_miniscript:compile(AST),
             %% Should be: <33> <key> OP_CHECKSIG
             Expected = <<33, Key/binary, 16#ac>>,
             ?assertEqual(Expected, Script)
         end}
    ].

compile_hash_test_() ->
    [
        {"compile sha256",
         fun() ->
             Hash = ?HASH32,
             AST = {sha256, Hash},
             Script = beamchain_miniscript:compile(AST),
             %% OP_SIZE OP_PUSHNUM_32 OP_EQUALVERIFY OP_SHA256 <32> <hash> OP_EQUAL
             Expected = <<16#82, 16#01, 32, 16#88, 16#a8, 32, Hash/binary, 16#87>>,
             ?assertEqual(Expected, Script)
         end}
    ].

compile_older_test_() ->
    [
        {"compile older small number",
         fun() ->
             AST = {older, 10},
             Script = beamchain_miniscript:compile(AST),
             %% OP_10 OP_CHECKSEQUENCEVERIFY
             Expected = <<16#5a, 16#b2>>,  %% OP_10 = 0x5a
             ?assertEqual(Expected, Script)
         end},
        {"compile older larger number",
         fun() ->
             AST = {older, 144},
             Script = beamchain_miniscript:compile(AST),
             %% Need push of 144 (0x90) as CScriptNum
             %% 144 = 0x90, needs sign byte since high bit set
             %% CScriptNum: little-endian, so <<144, 0>>
             Expected = <<16#02, 16#90, 16#00, 16#b2>>,  %% PUSH2 0x0090 OP_CSV
             ?assertEqual(Expected, Script)
         end}
    ].

compile_multi_test_() ->
    [
        {"compile multi",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             AST = {multi, 1, [Key1, Key2]},
             Script = beamchain_miniscript:compile(AST),
             %% OP_1 <key1> <key2> OP_2 OP_CHECKMULTISIG
             Expected = <<16#51,  %% OP_1
                          33, Key1/binary,
                          33, Key2/binary,
                          16#52,  %% OP_2
                          16#ae>>,  %% OP_CHECKMULTISIG
             ?assertEqual(Expected, Script)
         end}
    ].

compile_or_i_test_() ->
    [
        {"compile or_i",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             AST = {or_i,
                    {wrap_c, {pk_k, Key1}},
                    {wrap_c, {pk_k, Key2}}},
             Script = beamchain_miniscript:compile(AST),
             %% OP_IF <key1> OP_CHECKSIG OP_ELSE <key2> OP_CHECKSIG OP_ENDIF
             Expected = <<16#63,  %% OP_IF
                          33, Key1/binary, 16#ac,  %% <key1> OP_CHECKSIG
                          16#67,  %% OP_ELSE
                          33, Key2/binary, 16#ac,  %% <key2> OP_CHECKSIG
                          16#68>>,  %% OP_ENDIF
             ?assertEqual(Expected, Script)
         end}
    ].

compile_and_v_test_() ->
    [
        {"compile and_v",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             AST = {and_v,
                    {wrap_v, {wrap_c, {pk_k, Key1}}},
                    {wrap_c, {pk_k, Key2}}},
             Script = beamchain_miniscript:compile(AST),
             %% <key1> OP_CHECKSIGVERIFY <key2> OP_CHECKSIG
             %% v: wrapper merges CHECKSIG -> CHECKSIGVERIFY
             Expected = <<33, Key1/binary, 16#ad,  %% <key1> OP_CHECKSIGVERIFY
                          33, Key2/binary, 16#ac>>,  %% <key2> OP_CHECKSIG
             ?assertEqual(Expected, Script)
         end}
    ].

%%% ===================================================================
%%% Script Size Tests
%%% ===================================================================

script_size_test_() ->
    [
        {"pk script size",
         fun() ->
             AST = {wrap_c, {pk_k, ?KEY1}},
             Size = beamchain_miniscript:script_size(AST),
             ?assertEqual(35, Size)  %% 1 (push) + 33 (key) + 1 (CHECKSIG)
         end},
        {"multi script size",
         fun() ->
             AST = {multi, 2, [?KEY1, ?KEY2, ?KEY3]},
             Size = beamchain_miniscript:script_size(AST),
             %% 1 (OP_2) + 3*(1+33) + 1 (OP_3) + 1 (CHECKMULTISIG)
             Expected = 1 + 3 * 34 + 1 + 1,
             ?assertEqual(Expected, Size)
         end}
    ].

%%% ===================================================================
%%% Witness Size Tests
%%% ===================================================================

witness_size_test_() ->
    [
        {"pk witness size",
         fun() ->
             AST = {wrap_c, {pk_k, ?KEY1}},
             MaxSize = beamchain_miniscript:max_witness_size(AST),
             ?assertEqual(73, MaxSize)  %% DER sig max ~72 + 1 sighash byte
         end}
    ].

%%% ===================================================================
%%% Satisfaction Tests
%%% ===================================================================

satisfy_pk_test_() ->
    [
        {"satisfy pk with signature",
         fun() ->
             Key = ?KEY1,
             Sig = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                     17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
                     33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
                     49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,
                     65,66,67,68,69,70,71,1>>,  %% 71-byte sig + sighash
             AST = {wrap_c, {pk_k, Key}},
             Env = #{sigs => #{Key => Sig}},
             {ok, Witness} = beamchain_miniscript:satisfy(AST, Env),
             ?assertEqual([Sig], Witness)
         end},
        {"satisfy pk without signature fails",
         fun() ->
             Key = ?KEY1,
             AST = {wrap_c, {pk_k, Key}},
             Env = #{sigs => #{}},
             Result = beamchain_miniscript:satisfy(AST, Env),
             ?assertEqual({error, unsatisfiable}, Result)
         end}
    ].

satisfy_or_i_test_() ->
    [
        {"satisfy or_i with first branch",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Sig1 = <<1:576>>,  %% 72-byte sig
             AST = {or_i,
                    {wrap_c, {pk_k, Key1}},
                    {wrap_c, {pk_k, Key2}}},
             Env = #{sigs => #{Key1 => Sig1}},
             {ok, Witness} = beamchain_miniscript:satisfy(AST, Env),
             %% Should include sig and branch selector (1 for IF)
             ?assert(lists:member(Sig1, Witness)),
             ?assert(lists:member(<<1>>, Witness))
         end},
        {"satisfy or_i with second branch",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Sig2 = <<2:576>>,
             AST = {or_i,
                    {wrap_c, {pk_k, Key1}},
                    {wrap_c, {pk_k, Key2}}},
             Env = #{sigs => #{Key2 => Sig2}},
             {ok, Witness} = beamchain_miniscript:satisfy(AST, Env),
             %% Should include sig and branch selector (empty for ELSE)
             ?assert(lists:member(Sig2, Witness)),
             ?assert(lists:member(<<>>, Witness))
         end}
    ].

satisfy_hash_test_() ->
    [
        {"satisfy sha256 with preimage",
         fun() ->
             Hash = ?HASH32,
             Preimage = <<"secret preimage data here!!!">>,
             AST = {sha256, Hash},
             Env = #{preimages => #{{sha256, Hash} => Preimage}},
             {ok, Witness} = beamchain_miniscript:satisfy(AST, Env),
             ?assertEqual([Preimage], Witness)
         end}
    ].

satisfy_multi_test_() ->
    [
        {"satisfy multi 2-of-3",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Key3 = ?KEY3,
             Sig1 = <<1:576>>,
             Sig2 = <<2:576>>,
             AST = {multi, 2, [Key1, Key2, Key3]},
             Env = #{sigs => #{Key1 => Sig1, Key2 => Sig2}},
             {ok, Witness} = beamchain_miniscript:satisfy(AST, Env),
             %% Should have dummy + 2 sigs
             ?assertEqual(3, length(Witness)),
             ?assertEqual(<<>>, hd(Witness))  %% Dummy element
         end}
    ].

%%% ===================================================================
%%% Round-trip Tests (parse -> compile -> parse)
%%% ===================================================================

roundtrip_test_() ->
    [
        {"roundtrip pk",
         fun() ->
             Key = ?KEY1,
             Hex = binary_to_hex(Key),
             Original = "pk(" ++ Hex ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Original),
             Str = beamchain_miniscript:to_string(AST),
             %% Parse the regenerated string
             {ok, AST2} = beamchain_miniscript:from_string(Str),
             ?assertEqual(AST, AST2)
         end},
        {"roundtrip multi",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             Original = "multi(1," ++ Hex1 ++ "," ++ Hex2 ++ ")",
             {ok, AST} = beamchain_miniscript:from_string(Original),
             Str = beamchain_miniscript:to_string(AST),
             {ok, AST2} = beamchain_miniscript:from_string(Str),
             ?assertEqual(AST, AST2)
         end},
        {"roundtrip or_i",
         fun() ->
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Hex1 = binary_to_hex(Key1),
             Hex2 = binary_to_hex(Key2),
             Original = "or_i(pk(" ++ Hex1 ++ "),pk(" ++ Hex2 ++ "))",
             {ok, AST} = beamchain_miniscript:from_string(Original),
             Str = beamchain_miniscript:to_string(AST),
             {ok, AST2} = beamchain_miniscript:from_string(Str),
             ?assertEqual(AST, AST2)
         end}
    ].

%%% ===================================================================
%%% Complex Miniscript Tests
%%% ===================================================================

complex_miniscript_test_() ->
    [
        {"or_i alternative: 2-of-3 OR single key",
         fun() ->
             %% or_i(multi(2,k1,k2,k3), pk(k1))
             %% This is "2 of 3 keys OR key1"
             Key1 = ?KEY1,
             Key2 = ?KEY2,
             Key3 = ?KEY3,
             AST = {or_i,
                 {multi, 2, [Key1, Key2, Key3]},
                 {wrap_c, {pk_k, Key1}}
             },
             %% This should compile and type-check
             {ok, Type} = beamchain_miniscript:type_check(AST),
             ?assertEqual('B', maps:get(type, Type)),
             _Script = beamchain_miniscript:compile(AST),
             ok
         end}
    ].

%%% ===================================================================
%%% Helper Functions
%%% ===================================================================

binary_to_hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).
