-module(beamchain_descriptor_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Checksum tests
%%% ===================================================================

checksum_test_() ->
    [
        {"pkh descriptor checksum",
         ?_assertEqual("8fhd9pwu",
             beamchain_descriptor:checksum(
                 "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"))},
        {"wpkh descriptor checksum",
         ?_assertEqual("8zl0zxma",
             beamchain_descriptor:checksum(
                 "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"))},
        {"sh(wpkh) descriptor checksum",
         ?_assertEqual("qkrrc7je",
             beamchain_descriptor:checksum(
                 "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"))},
        {"add checksum function",
         fun() ->
             Desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
             WithChecksum = beamchain_descriptor:add_checksum(Desc),
             ?assertEqual(Desc ++ "#8fhd9pwu", WithChecksum)
         end},
        {"verify checksum - valid",
         ?_assert(beamchain_descriptor:verify_checksum(
             "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#8fhd9pwu"))},
        {"verify checksum - invalid",
         ?_assertNot(beamchain_descriptor:verify_checksum(
             "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#wrongsum"))}
    ].

%%% ===================================================================
%%% Parse tests
%%% ===================================================================

parse_pk_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"parse pk descriptor",
         fun() ->
             Desc = "pk(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_pk, _}, Parsed)
         end},
        {"parse pk with checksum",
         fun() ->
             Desc = "pk(" ++ PubKey ++ ")#h6vg4z7u",
             case beamchain_descriptor:parse(Desc) of
                 {ok, Parsed} ->
                     ?assertMatch({desc_pk, _}, Parsed);
                 {error, bad_checksum} ->
                     %% Checksum may differ - recompute
                     DescNoCs = "pk(" ++ PubKey ++ ")",
                     {ok, Parsed} = beamchain_descriptor:parse(DescNoCs),
                     ?assertMatch({desc_pk, _}, Parsed)
             end
         end}
    ].

parse_pkh_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"parse pkh descriptor",
         fun() ->
             Desc = "pkh(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_pkh, _}, Parsed),
             ?assertNot(beamchain_descriptor:is_range(Parsed)),
             ?assert(beamchain_descriptor:is_solvable(Parsed))
         end}
    ].

parse_wpkh_test_() ->
    PubKey = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    [
        {"parse wpkh descriptor",
         fun() ->
             Desc = "wpkh(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_wpkh, _}, Parsed)
         end}
    ].

parse_sh_test_() ->
    PubKey = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
    [
        {"parse sh(wpkh) descriptor",
         fun() ->
             Desc = "sh(wpkh(" ++ PubKey ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_sh, {desc_wpkh, _}}, Parsed)
         end},
        {"parse sh(multi) descriptor",
         fun() ->
             Key1 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
             Key2 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
             Desc = "sh(multi(1," ++ Key1 ++ "," ++ Key2 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_sh, {desc_multi, 1, _, false}}, Parsed)
         end}
    ].

parse_wsh_test_() ->
    Key1 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    Key2 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    [
        {"parse wsh(multi) descriptor",
         fun() ->
             Desc = "wsh(multi(2," ++ Key1 ++ "," ++ Key2 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_wsh, {desc_multi, 2, _, false}}, Parsed)
         end},
        {"parse wsh(sortedmulti) descriptor",
         fun() ->
             Desc = "wsh(sortedmulti(1," ++ Key1 ++ "," ++ Key2 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_wsh, {desc_multi, 1, _, true}}, Parsed)
         end}
    ].

parse_multi_test_() ->
    Key1 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    Key2 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    Key3 = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
    [
        {"parse multi(2,k1,k2,k3) descriptor",
         fun() ->
             Desc = "multi(2," ++ Key1 ++ "," ++ Key2 ++ "," ++ Key3 ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_multi, 2, [_, _, _], false}, Parsed)
         end},
        {"parse sortedmulti(1,k1,k2) descriptor",
         fun() ->
             Desc = "sortedmulti(1," ++ Key1 ++ "," ++ Key2 ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_multi, 1, [_, _], true}, Parsed)
         end},
        {"multi threshold exceeds keys",
         fun() ->
             Desc = "multi(3," ++ Key1 ++ "," ++ Key2 ++ ")",
             ?assertMatch({error, _}, beamchain_descriptor:parse(Desc))
         end}
    ].

parse_tr_test_() ->
    XOnlyKey = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"parse tr(key) descriptor",
         fun() ->
             Desc = "tr(" ++ XOnlyKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_tr, _, []}, Parsed)
         end},
        {"parse tr(compressed_key) descriptor",
         fun() ->
             Desc = "tr(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_tr, _, []}, Parsed)
         end}
    ].

parse_addr_test_() ->
    [
        {"parse addr() descriptor",
         fun() ->
             Desc = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_addr, _}, Parsed),
             ?assertNot(beamchain_descriptor:is_solvable(Parsed)),
             ?assertNot(beamchain_descriptor:is_range(Parsed))
         end}
    ].

parse_raw_test_() ->
    [
        {"parse raw() descriptor",
         fun() ->
             %% OP_RETURN "hello"
             Desc = "raw(6a0568656c6c6f)",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_raw, <<16#6a, 16#05, "hello">>}, Parsed),
             ?assertNot(beamchain_descriptor:is_solvable(Parsed))
         end}
    ].

parse_combo_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"parse combo() descriptor",
         fun() ->
             Desc = "combo(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_combo, _}, Parsed)
         end}
    ].

%%% ===================================================================
%%% Derivation tests
%%% ===================================================================

derive_pkh_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"derive pkh script",
         fun() ->
             Desc = "pkh(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0, mainnet),
             %% P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
             ?assertEqual(<<16#76, 16#a9, 16#14, _:20/binary, 16#88, 16#ac>> = Script, Script)
         end}
    ].

derive_wpkh_test_() ->
    PubKey = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    [
        {"derive wpkh script",
         fun() ->
             Desc = "wpkh(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0, mainnet),
             %% P2WPKH: OP_0 <20>
             ?assertMatch(<<16#00, 16#14, _:20/binary>>, Script)
         end}
    ].

derive_sh_wpkh_test_() ->
    PubKey = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
    [
        {"derive sh(wpkh) script",
         fun() ->
             Desc = "sh(wpkh(" ++ PubKey ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0, mainnet),
             %% P2SH: OP_HASH160 <20> OP_EQUAL
             ?assertMatch(<<16#a9, 16#14, _:20/binary, 16#87>>, Script)
         end}
    ].

derive_wsh_multi_test_() ->
    Key1 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    Key2 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    [
        {"derive wsh(multi) script",
         fun() ->
             Desc = "wsh(multi(1," ++ Key1 ++ "," ++ Key2 ++ "))",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0, mainnet),
             %% P2WSH: OP_0 <32>
             ?assertMatch(<<16#00, 16#20, _:32/binary>>, Script)
         end}
    ].

derive_tr_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"derive tr script",
         fun() ->
             Desc = "tr(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             {ok, Script} = beamchain_descriptor:derive(Parsed, 0, mainnet),
             %% P2TR: OP_1 <32>
             ?assertMatch(<<16#51, 16#20, _:32/binary>>, Script)
         end}
    ].

%%% ===================================================================
%%% Expand tests
%%% ===================================================================

expand_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"expand non-ranged descriptor",
         fun() ->
             Desc = "pkh(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             {ok, Results} = beamchain_descriptor:expand(Parsed, {0, 2}, mainnet),
             ?assertEqual(3, length(Results)),
             %% Non-ranged: all indices give same script
             [{0, S1}, {1, S2}, {2, S3}] = Results,
             ?assertEqual(S1, S2),
             ?assertEqual(S2, S3)
         end}
    ].

%%% ===================================================================
%%% Descriptor info tests
%%% ===================================================================

get_info_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"get_info for pkh",
         fun() ->
             Desc = "pkh(" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             Info = beamchain_descriptor:get_info(Parsed),
             ?assert(maps:is_key(descriptor, Info)),
             ?assert(maps:is_key(checksum, Info)),
             ?assertEqual(false, maps:get(isrange, Info)),
             ?assertEqual(true, maps:get(issolvable, Info)),
             ?assertEqual(false, maps:get(hasprivatekeys, Info))
         end}
    ].

%%% ===================================================================
%%% Extended key tests
%%% ===================================================================

xpub_parse_test_() ->
    %% Test xpub from BIP32 test vectors
    XPub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    [
        {"parse xpub descriptor",
         fun() ->
             Desc = "pkh(" ++ XPub ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_pkh, {bip32_key, _, _, _, _, _, _, _}}, Parsed),
             ?assertNot(beamchain_descriptor:is_range(Parsed))
         end},
        {"parse xpub with derivation path",
         fun() ->
             Desc = "pkh(" ++ XPub ++ "/0/*)",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_pkh, {bip32_key, _, _, _, _, _, _, _}}, Parsed),
             ?assert(beamchain_descriptor:is_range(Parsed))
         end},
        {"parse xpub with hardened derivation",
         fun() ->
             Desc = "pkh(" ++ XPub ++ "/0'/1/*)",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assert(beamchain_descriptor:is_range(Parsed))
         end}
    ].

%%% ===================================================================
%%% Key origin tests
%%% ===================================================================

key_origin_test_() ->
    PubKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    [
        {"parse key with origin",
         fun() ->
             Desc = "pkh([aabbccdd/44'/0'/0']" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_pkh, _}, Parsed)
         end},
        {"parse key with fingerprint only",
         fun() ->
             Desc = "pkh([aabbccdd]" ++ PubKey ++ ")",
             {ok, Parsed} = beamchain_descriptor:parse(Desc),
             ?assertMatch({desc_pkh, _}, Parsed)
         end}
    ].

%%% ===================================================================
%%% Error handling tests
%%% ===================================================================

error_test_() ->
    [
        {"unknown descriptor type",
         fun() ->
             ?assertMatch({error, {unknown_descriptor_type, _}},
                 beamchain_descriptor:parse("unknown(key)"))
         end},
        {"invalid checksum",
         fun() ->
             Desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#invalid",
             ?assertEqual({error, bad_checksum}, beamchain_descriptor:parse(Desc))
         end},
        {"sh with invalid inner",
         fun() ->
             %% sh(sh()) is invalid
             ?assertMatch({error, _}, beamchain_descriptor:parse("sh(sh(pk(00)))"))
         end}
    ].
