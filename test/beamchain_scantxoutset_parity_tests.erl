-module(beamchain_scantxoutset_parity_tests).

%%% scantxoutset parity with Bitcoin Core v31.1.
%%%
%%% InferDescriptor strings (with BIP-380 checksum), key origins, ranges,
%%% and RPC error codes. Expectations are computed from Core's rules
%%% (hash160 fingerprint, descriptor checksum, TaprootBuilder::Insert),
%%% not from beamchain's scan implementation.
%%%
%%%   rebar3 eunit --module=beamchain_scantxoutset_parity_tests

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

-define(PK_C, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").
-define(PK_HI, "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556").
-define(PK_A34, "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd").
-define(X1, "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd").
-define(X2, "669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0").
-define(X3, "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115").
-define(XPUB, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").
-define(XPUB_A, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL").
-define(XPUB_B, "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y").
-define(WIF, "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").
-define(MULTI_BODY,
        "sh(multi(2,[00000000/111'/222]" ?XPUB_A "," ?XPUB_B "/0))").

parity_test_() ->
    {setup, fun setup/0, fun teardown/1,
     fun(_Dir) ->
         [{timeout, 60, T} || T <- error_tests() ++ success_tests()]
     end}.

%%% ===================================================================
%%% Error cases (Core codes and messages)
%%% ===================================================================

error_tests() ->
    [{"missing scanobjects is -1 after the reserver check",
      fun missing_scanobjects/0},
     {"scan already in progress wins over a missing scanobjects param",
      fun in_progress_before_missing/0},
     {"idle status is null and abort is false",
      fun idle_status_abort/0}
     | [{Name, fun() -> assert_err(Params, Code, Msg) end}
        || {Name, Params, Code, Msg} <- error_table()]].

error_table() ->
    Pk = ?PK_C,
    Xpub = ?XPUB,
    Body = ?MULTI_BODY,
    [
     {"integer scan object",
      [<<"start">>, [1]], -8,
      <<"Scan object needs to be either a string or an object">>},
     {"bool scan object",
      [<<"start">>, [true]], -8,
      <<"Scan object needs to be either a string or an object">>},
     {"null scan object",
      [<<"start">>, [null]], -8,
      <<"Scan object needs to be either a string or an object">>},
     {"object without desc",
      [<<"start">>, [#{<<"range">> => [5, 4]}]], -8,
      <<"Descriptor needs to be provided in scan object">>},
     {"desc is not a string",
      [<<"start">>, [#{<<"desc">> => 1}]], -3,
      <<"JSON value of type number is not of expected type string">>},
     {"checksum mismatch from a changed payload",
      [<<"start">>, [bin(string:slice(Body, 0, 9) ++ "3" ++
                         string:slice(Body, 10) ++ "#tjg09x5t")]], -5,
      <<"Provided checksum 'tjg09x5t' does not match computed checksum 'd4x0uxyv'">>},
     {"checksum mismatch",
      [<<"start">>, [bin(Body ++ "#tjq09x4t")]], -5,
      <<"Provided checksum 'tjq09x4t' does not match computed checksum 'tjg09x5t'">>},
     {"empty checksum",
      [<<"start">>, [bin(Body ++ "#")]], -5,
      <<"Expected 8 character checksum, not 0 characters">>},
     {"short checksum",
      [<<"start">>, [bin(Body ++ "#tjg09x5")]], -5,
      <<"Expected 8 character checksum, not 7 characters">>},
     {"long checksum",
      [<<"start">>, [bin(Body ++ "#tjg09x5tq")]], -5,
      <<"Expected 8 character checksum, not 9 characters">>},
     {"multiple hash symbols",
      [<<"start">>, [bin(Body ++ "##tjq09x4t")]], -5,
      <<"Multiple '#' symbols">>},
     {"invalid payload character",
      [<<"start">>, [<<"raw(", 195, 156, ")">>]], -5,
      <<"Invalid characters in payload">>},
     {"checksum length is checked before invalid characters",
      [<<"start">>, [<<"raw(", 195, 156, ")#">>]], -5,
      <<"Expected 8 character checksum, not 0 characters">>},
     {"unknown function",
      [<<"start">>, [<<"foo(bar)">>]], -5,
      <<"\'foo(bar)\' is not a valid descriptor function">>},
     {"bare hex is not a descriptor",
      [<<"start">>, [<<"51">>]], -5,
      <<"\'51\' is not a valid descriptor function">>},
     {"short pubkey",
      [<<"start">>, [<<"wpkh(02)">>]], -5,
      <<"wpkh(): Pubkey \'02\' is invalid">>},
     {"key is not valid",
      [<<"start">>, [<<"wpkh(zzzz)">>]], -5,
      <<"wpkh(): key \'zzzz\' is not valid">>},
     {"no key",
      [<<"start">>, [<<"pkh()">>]], -5,
      <<"pkh(): No key provided">>},
     {"whitespace in key",
      [<<"start">>, [<<"pk(ab )">>]], -5,
      <<"pk(): Key \'ab \' is invalid due to whitespace">>},
     {"combo only at top",
      [<<"start">>, [bin("sh(combo(" ++ Pk ++ "))")]], -5,
      <<"Can only have combo() at top level">>},
     {"wpkh nesting",
      [<<"start">>, [bin("wsh(wpkh(" ++ Pk ++ "))")]], -5,
      <<"Can only have wpkh() at top level or inside sh()">>},
     {"sh nesting",
      [<<"start">>, [bin("sh(sh(pk(" ++ Pk ++ ")))")]], -5,
      <<"Can only have sh() at top level">>},
     {"wsh nesting",
      [<<"start">>, [bin("wsh(wsh(pk(" ++ Pk ++ ")))")]], -5,
      <<"Can only have wsh() at top level or inside sh()">>},
     {"multi inside tr",
      [<<"start">>, [bin("tr(" ++ ?X1 ++ ",multi(1," ++ Pk ++ "))")]], -5,
      <<"Can only have multi/sortedmulti at top level, in sh(), or in wsh()">>},
     {"tr nesting",
      [<<"start">>, [bin("sh(tr(" ++ ?X1 ++ "))")]], -5,
      <<"Can only have tr at top level">>},
     {"rawtr nesting",
      [<<"start">>, [bin("sh(rawtr(" ++ ?X1 ++ "))")]], -5,
      <<"Can only have rawtr at top level">>},
     {"addr nesting",
      [<<"start">>, [<<"sh(addr(asdf))">>]], -5,
      <<"Can only have addr() at top level">>},
     {"raw nesting",
      [<<"start">>, [<<"sh(raw(51))">>]], -5,
      <<"Can only have raw() at top level">>},
     {"function needed in sh",
      [<<"start">>, [bin("sh(" ++ Pk ++ ")")]], -5,
      <<"A function is needed within P2SH">>},
     {"function needed in wsh",
      [<<"start">>, [bin("wsh(" ++ Pk ++ ")")]], -5,
      <<"A function is needed within P2WSH">>},
     {"bad multi threshold",
      [<<"start">>, [bin("multi(a," ++ Pk ++ "," ++ ?PK_HI ++ ")")]], -5,
      <<"Multi threshold \'a\' is not valid">>},
     {"signed multi threshold",
      [<<"start">>, [bin("multi(+1," ++ Pk ++ "," ++ ?PK_HI ++ ")")]], -5,
      <<"Multi threshold \'+1\' is not valid">>},
     {"zero multi threshold",
      [<<"start">>, [bin("multi(0," ++ Pk ++ "," ++ ?PK_HI ++ ")")]], -5,
      <<"Multisig threshold cannot be 0, must be at least 1">>},
     {"threshold above key count",
      [<<"start">>, [bin("multi(3," ++ Pk ++ "," ++ ?PK_HI ++ ")")]], -5,
      <<"Multisig threshold cannot be larger than the number of keys; threshold is 3 but only 2 keys specified">>},
     {"bare multisig key cap",
      [<<"start">>, [bin("multi(1," ++ Pk ++ "," ++ Pk ++ "," ++ Pk ++ "," ++ Pk ++ ")")]], -5,
      <<"Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys">>},
     {"multisig with no keys",
      [<<"start">>, [<<"multi(123)">>]], -5,
      <<"Cannot have 0 keys in multisig; must have between 1 and 20 keys, inclusive">>},
     {"multi expected comma",
      [<<"start">>, [<<"multi(0)()">>]], -5,
      <<"Multi: expected ',', got ')'">>},
     {"p2sh script too large",
      [<<"start">>, [bin(p2sh_too_large(Pk))]], -5,
      <<"P2SH script is too large, 547 bytes is larger than 520 bytes">>},
     {"addr invalid",
      [<<"start">>, [<<"addr(asdf)">>]], -5,
      <<"Address is not valid">>},
     {"raw not hex",
      [<<"start">>, [<<"raw(asdf)">>]], -5,
      <<"Raw script is not hex">>},
     {"rawtr two keys",
      [<<"start">>, [bin("rawtr(" ++ ?X1 ++ "," ++ ?X2 ++ ")")]], -5,
      <<"rawtr(): only one key expected.">>},
     {"short fingerprint",
      [<<"start">>, [bin("wpkh([1234567]" ++ Pk ++ ")")]], -5,
      <<"wpkh(): Fingerprint is not 4 bytes (7 characters instead of 8 characters)">>},
     {"fingerprint not hex",
      [<<"start">>, [bin("wpkh([zzzzzzzz]" ++ Pk ++ ")")]], -5,
      <<"wpkh(): Fingerprint \'zzzzzzzz\' is not hex">>},
     {"origin missing bracket",
      [<<"start">>, [bin("wpkh(abcd]" ++ Pk ++ ")")]], -5,
      <<"wpkh(): Key origin start \'[ character expected but not found, got \'a\' instead">>},
     {"multiple origin closers",
      [<<"start">>, [bin("wpkh([aaaaaaaa][aaaaaaaa]" ++ Pk ++ ")")]], -5,
      <<"wpkh(): Multiple \']\' characters found for a single pubkey">>},
     {"path out of range",
      [<<"start">>, [bin("wpkh(" ++ Xpub ++ "/2147483648)")]], -5,
      <<"wpkh(): Key path value 2147483648 is out of range">>},
     {"path not a uint32",
      [<<"start">>, [bin("wpkh(" ++ Xpub ++ "/zz)")]], -5,
      <<"wpkh(): Key path value \'zz\' is not a valid uint32">>},
     {"hybrid pubkey",
      [<<"start">>, [<<"pk(06", (binary:copy(<<"00">>, 64))/binary, ")">>]], -5,
      <<"pk(): Hybrid public keys are not allowed">>},
     {"uncompressed wpkh",
      [<<"start">>, [fun_uncomp_wpkh()]], -5,
      <<"wpkh(): Uncompressed keys are not allowed">>},
     {"uncompressed inside sh(wpkh)",
      [<<"start">>, [fun_uncomp_sh_wpkh()]], -5,
      <<"wpkh(): Uncompressed keys are not allowed">>},
     {"range begin after end",
      [<<"start">>, [#{<<"desc">> => <<"wpkh(", (bin(Pk))/binary, ")">>,
                       <<"range">> => [5, 4]}]], -8,
      <<"Range specified as [begin,end] must not have begin after end">>},
     {"range on a bad descriptor is still a range error",
      [<<"start">>, [#{<<"desc">> => <<"not_a_desc">>,
                       <<"range">> => [5, 4]}]], -8,
      <<"Range specified as [begin,end] must not have begin after end">>},
     {"range string",
      [<<"start">>, [#{<<"desc">> => <<"raw(51)">>, <<"range">> => <<"10">>}]], -8,
      <<"Range must be specified as end or as [begin,end]">>},
     {"range one element",
      [<<"start">>, [#{<<"desc">> => <<"raw(51)">>, <<"range">> => [1]}]], -8,
      <<"Range must be specified as end or as [begin,end]">>},
     {"range below zero",
      [<<"start">>, [#{<<"desc">> => <<"raw(51)">>, <<"range">> => [-1, 5]}]], -8,
      <<"Range should be greater or equal than 0">>},
     {"negative range end",
      [<<"start">>, [#{<<"desc">> => <<"raw(51)">>, <<"range">> => -1}]], -8,
      <<"End of range is too high">>},
     {"range end 2^31",
      [<<"start">>, [#{<<"desc">> => <<"raw(51)">>, <<"range">> => 2147483648}]], -8,
      <<"End of range is too high">>},
     {"range too large",
      [<<"start">>, [#{<<"desc">> => <<"raw(51)">>, <<"range">> => 1000000}]], -8,
      <<"Range is too large">>},
     {"float range",
      [<<"start">>, [#{<<"desc">> => <<"raw(51)">>, <<"range">> => 1.5}]], -1,
      <<"JSON integer out of range">>},
     {"hardened child from xpub",
      [<<"start">>, [bin("wpkh(" ++ Xpub ++ "/0h)")]], -5,
      bin("Cannot derive script without private keys: 'wpkh(" ++ Xpub ++ "/0h)'")}
    ].

%% The payload-changed checksum vector is multi(3, ...) with the checksum
%% copied from multi(2, ...). string:slice on the shared body swaps the
%% threshold digit only when it sits at that offset; pin the checksum here
%% so a drifted body fails this test instead of a wrong RPC string.
missing_scanobjects() ->
    ?assertEqual("tjg09x5t", beamchain_descriptor:checksum(?MULTI_BODY)),
    ?assertEqual("d4x0uxyv",
                 beamchain_descriptor:checksum(
                   string:slice(?MULTI_BODY, 0, 9) ++ "3" ++
                   string:slice(?MULTI_BODY, 10))),
    assert_err([<<"start">>], -1,
               <<"scanobjects argument is required for the start action">>).

in_progress_before_missing() ->
    beamchain_rpc:handle_method(<<"scantxoutset">>, [<<"status">>], undefined),
    ets:insert(beamchain_scantxoutset, {in_progress, make_ref()}),
    try
        assert_err([<<"start">>], -8,
                   <<"Scan already in progress, use action \"abort\" or \"status\"">>)
    after
        ets:delete(beamchain_scantxoutset, in_progress)
    end.

idle_status_abort() ->
    ?assertEqual({ok_raw_json, <<"null">>},
                 beamchain_rpc:handle_method(<<"scantxoutset">>,
                                             [<<"status">>], undefined)),
    ?assertEqual({ok, false},
                 beamchain_rpc:handle_method(<<"scantxoutset">>,
                                             [<<"abort">>], undefined)).

fun_uncomp_wpkh() ->
    bin("wpkh(" ++ hexs(uncompressed()) ++ ")").

fun_uncomp_sh_wpkh() ->
    bin("sh(wpkh(" ++ hexs(uncompressed()) ++ "))").

p2sh_too_large(Pk) ->
    Keys = lists:join(",", lists:duplicate(16, Pk)),
    "sh(multi(1," ++ Keys ++ "))".

%%% ===================================================================
%%% Success cases
%%% ===================================================================

success_tests() ->
    [
     {"raw() infers raw(hex)#checksum and JSON key order",
      fun raw_checksum_and_key_order/0},
     {"fixed pubkeys get a hash160 origin",
      fun fixed_pubkey_origins/0},
     {"combo expands to four scripts",
      fun combo_compressed/0},
     {"combo of an uncompressed key is pk and pkh",
      fun combo_uncompressed/0},
     {"odd compressed tr() key fingerprints the odd pubkey",
      fun tr_odd_vs_xonly/0},
     {"tr() with a pk() leaf round-trips the tree",
      fun tr_pk_leaf/0},
     {"tr() rebuilds single-level and multi-level trees",
      fun tr_trees/0},
     {"sortedmulti is inferred as multi in script order",
      fun sortedmulti_infers_multi/0},
     {"xpub origin is the xpub pubkey id plus the derived path",
      fun xpub_origin/0},
     {"explicit origin is kept and extended",
      fun explicit_origin/0},
     {"sh(multi) xpubs infer hex keys and the Core script",
      fun sh_multi_xpub/0},
     {"WIF scan infers the pubkey form",
      fun wif_pk/0},
     {"addr() and raw() with an empty provider",
      fun addr_and_raw_empty_provider/0},
     {"first scan object wins a duplicate script",
      fun first_descriptor_wins/0},
     {"range object and the default 0..1000 string range",
      fun ranges/0},
     {"non-range descriptor accepts a large but legal range",
      fun nonrange_ignores_range/0},
     {"empty scanobjects succeeds",
      fun empty_scan/0},
     {"unspents follow internal txid order then vout",
      fun unspent_order/0},
     {"amount, coinbase, height, blockhash, confirmations",
      fun coin_fields/0},
     {"a bare address is rejected",
      fun bare_address_rejected/0}
    ].

raw_checksum_and_key_order() ->
    Script = <<1, 2, 3>>,
    seed(Script, 100000000, false),
    Desc = cs("raw(010203)"),
    {Raw, Map} = scan_ok([<<"raw(010203)">>]),
    [U] = matches(Map, Script),
    ?assertEqual(Desc, maps:get(<<"desc">>, U)),
    ?assertEqual(hex(Script), maps:get(<<"scriptPubKey">>, U)),
    assert_result_key_order(Raw),
    assert_unspent_key_order(Raw),
    %% Same descriptor with its checksum spelled out.
    {_, Map2} = scan_ok([cs("raw(010203)")]),
    [U2] = matches(Map2, Script),
    ?assertEqual(Desc, maps:get(<<"desc">>, U2)).

fixed_pubkey_origins() ->
    Pk = hexdec(?PK_C),
    lists:foreach(
      fun({Desc, Script, Infer}) ->
              seed(Script, 100000000, false),
              {_, Map} = scan_ok([bin(Desc)]),
              assert_desc(Map, Script, cs(Infer))
      end,
      [
       {"pkh(" ++ ?PK_C ++ ")", p2pkh(Pk),
        "pkh(" ++ origin_key(Pk) ++ ")"},
       {"wpkh(" ++ ?PK_C ++ ")", p2wpkh(Pk),
        "wpkh(" ++ origin_key(Pk) ++ ")"},
       {"sh(wpkh(" ++ ?PK_C ++ "))", p2sh(p2wpkh(Pk)),
        "sh(wpkh(" ++ origin_key(Pk) ++ "))"},
       {"pk(" ++ ?PK_C ++ ")", p2pk(Pk),
        "pk(" ++ origin_key(Pk) ++ ")"}
      ]).

combo_compressed() ->
    Pk = hexdec(?PK_C),
    P2wpkh = p2wpkh(Pk),
    Scripts = [p2pk(Pk), p2pkh(Pk), P2wpkh, p2sh(P2wpkh)],
    lists:foreach(fun(S) -> seed(S, 50000000, false) end, Scripts),
    {_, Map} = scan_ok([bin("combo(" ++ ?PK_C ++ ")")]),
    Got = lists:usort([maps:get(<<"desc">>, U)
                       || U <- maps:get(<<"unspents">>, Map),
                          lists:member(hexdec(maps:get(<<"scriptPubKey">>, U)),
                                       Scripts)]),
    ?assertEqual(
       lists:sort([cs("pk(" ++ origin_key(Pk) ++ ")"),
                   cs("pkh(" ++ origin_key(Pk) ++ ")"),
                   cs("wpkh(" ++ origin_key(Pk) ++ ")"),
                   cs("sh(wpkh(" ++ origin_key(Pk) ++ "))")]),
       Got).

combo_uncompressed() ->
    Pk = uncompressed(),
    Scripts = [p2pk(Pk), p2pkh(Pk)],
    lists:foreach(fun(S) -> seed(S, 50000000, false) end, Scripts),
    {_, Map} = scan_ok([bin("combo(" ++ hexs(Pk) ++ ")")]),
    Got = lists:usort([maps:get(<<"desc">>, U)
                       || U <- maps:get(<<"unspents">>, Map),
                          lists:member(hexdec(maps:get(<<"scriptPubKey">>, U)),
                                       Scripts)]),
    ?assertEqual(
       lists:sort([cs("pk(" ++ origin_key(Pk) ++ ")"),
                   cs("pkh(" ++ origin_key(Pk) ++ ")")]),
       Got).

tr_odd_vs_xonly() ->
    X = hexdec(?X1),
    Script = tr_output(X, []),
    seed(Script, 100000000, false),
    Odd = hexdec(?PK_A34),
    OddDesc = cs("tr(" ++ origin_key_xonly(Odd, X) ++ ")"),
    EvenDesc = cs("tr(" ++ origin_xonly(X) ++ ")"),
    {_, MapOdd} = scan_ok([bin("tr(" ++ ?PK_A34 ++ ")")]),
    assert_desc(MapOdd, Script, OddDesc),
    {_, MapX} = scan_ok([bin("tr(" ++ ?X1 ++ ")")]),
    assert_desc(MapX, Script, EvenDesc),
    ?assertNotEqual(OddDesc, EvenDesc),
    Rawtr = <<16#51, 16#20, X/binary>>,
    seed(Rawtr, 100000000, false),
    {_, MapR} = scan_ok([bin("rawtr(" ++ ?X1 ++ ")")]),
    assert_desc(MapR, Rawtr, cs("rawtr(" ++ origin_xonly(X) ++ ")")).

tr_pk_leaf() ->
    X = hexdec(?X1),
    LeafKey = hexdec(?X2),
    Leaf = pk_leaf(LeafKey),
    Script = tr_output(X, [{0, Leaf}]),
    %% Core descriptor_tests.cpp vector for this tr(KEY,pk(LEAF)).
    ?assertEqual(<<"512017cf18db381d836d8923b1bdb246cfcd818da1a9f0e6e7907f187f0b2f937754">>,
                 hex(Script)),
    seed(Script, 100000000, false),
    Desc = "tr(" ++ ?X1 ++ ",pk(" ++ ?X2 ++ "))",
    {_, Map} = scan_ok([bin(Desc)]),
    assert_desc(Map, Script,
                cs("tr(" ++ origin_xonly(X) ++ ",pk(" ++
                   origin_xonly(LeafKey) ++ "))")).

tr_trees() ->
    X = hexdec(?X1),
    K2 = hexdec(?X2),
    K3 = hexdec(?X3),
    L1 = pk_leaf(X),
    L2 = pk_leaf(K2),
    L3 = pk_leaf(K3),
    Cases = [
     {"tr(" ++ ?X1 ++ ",{pk(" ++ ?X2 ++ "),pk(" ++ ?X3 ++ ")})",
      [{1, L2}, {1, L3}],
      "tr(" ++ origin_xonly(X) ++ ",{" ++
          "pk(" ++ origin_xonly(K2) ++ "),pk(" ++ origin_xonly(K3) ++ ")})"},
     {"tr(" ++ ?X1 ++ ",{{pk(" ++ ?X2 ++ "),pk(" ++ ?X3 ++ ")},pk(" ++ ?X1 ++ ")})",
      [{2, L2}, {2, L3}, {1, L1}],
      "tr(" ++ origin_xonly(X) ++ ",{{" ++
          "pk(" ++ origin_xonly(K2) ++ "),pk(" ++ origin_xonly(K3) ++ ")},pk(" ++
          origin_xonly(X) ++ ")})"},
     {"tr(" ++ ?X1 ++ ",{pk(" ++ ?X2 ++ "),{pk(" ++ ?X3 ++ "),pk(" ++ ?X1 ++ ")}})",
      [{1, L2}, {2, L3}, {2, L1}],
      "tr(" ++ origin_xonly(X) ++ ",{pk(" ++ origin_xonly(K2) ++ "),{pk(" ++
          origin_xonly(K3) ++ "),pk(" ++ origin_xonly(X) ++ ")}})"}
    ],
    lists:foreach(
      fun({Desc, Leaves, Infer}) ->
              Script = tr_output(X, Leaves),
              seed(Script, 100000000, false),
              {_, Map} = scan_ok([bin(Desc)]),
              assert_desc(Map, Script, cs(Infer))
      end, Cases).

sortedmulti_infers_multi() ->
    Hi = hexdec(?PK_HI),
    Lo = hexdec(?PK_C),
    %% sortedmulti sorts before building the script; inference is multi().
    Redeem = multi(1, [Lo, Hi]),
    ?assertEqual(multi(1, lists:sort([Hi, Lo])), Redeem),
    Sh = p2sh(Redeem),
    seed(Sh, 100000000, false),
    {_, Map} = scan_ok([bin("sh(sortedmulti(1," ++ ?PK_HI ++ "," ++ ?PK_C ++ "))")]),
    assert_desc(Map, Sh,
                cs("sh(multi(1," ++ origin_key(Lo) ++ "," ++
                   origin_key(Hi) ++ "))")),
    Wit = multi(1, [Hi, Lo]),
    Wsh = p2wsh(Wit),
    seed(Wsh, 100000000, false),
    {_, Map2} = scan_ok([bin("wsh(multi(1," ++ ?PK_HI ++ "," ++ ?PK_C ++ "))")]),
    assert_desc(Map2, Wsh,
                cs("wsh(multi(1," ++ origin_key(Hi) ++ "," ++
                   origin_key(Lo) ++ "))")).

xpub_origin() ->
    {Child, Script} = xpub_child(?XPUB, [0, 5]),
    {ok, Parsed} = beamchain_descriptor:parse(
                     "wpkh(" ++ ?XPUB ++ "/0/*)"),
    {ok, Derived} = beamchain_descriptor:derive(Parsed, 5, regtest),
    ?assertEqual(Script, Derived),
    seed(Script, 100000000, false),
    {_, Map} = scan_ok([bin("wpkh(" ++ ?XPUB ++ "/0/*)")]),
    assert_desc(Map, Script,
                cs("wpkh(" ++ xpub_fp_path(?XPUB, "0/5") ++ hexs(Child) ++ ")")).

explicit_origin() ->
    {Child, Script} = xpub_child(?XPUB, [0, 5]),
    Desc = "wpkh([d34db33f/84h/0h/0h]" ++ ?XPUB ++ "/0/*)",
    seed(Script, 100000000, false),
    {_, Map} = scan_ok([#{<<"desc">> => bin(Desc), <<"range">> => 5}]),
    assert_desc(Map, Script,
                cs("wpkh([d34db33f/84h/0h/0h/0/5]" ++ hexs(Child) ++ ")")).

sh_multi_xpub() ->
    {ok, KeyA, _} = beamchain_descriptor:decode_xpub(?XPUB_A),
    {Child, _} = ckd_path(?XPUB_B, [0]),
    Redeem = multi(2, [KeyA, Child]),
    Script = p2sh(Redeem),
    ?assertEqual(<<"a91445a9a622a8b0a1269944be477640eedc447bbd8487">>,
                 hex(Script)),
    seed(Script, 100000000, false),
    {_, Map} = scan_ok([bin(?MULTI_BODY)]),
    assert_desc(Map, Script,
                cs("sh(multi(2,[00000000/111h/222]" ++ hexs(KeyA) ++ "," ++
                   xpub_fp_path(?XPUB_B, "0") ++ hexs(Child) ++ "))")).

wif_pk() ->
    Pk = hexdec(?PK_A34),
    Script = p2pk(Pk),
    seed(Script, 100000000, false),
    {_, Map} = scan_ok([bin("pk(" ++ ?WIF ++ ")")]),
    assert_desc(Map, Script, cs("pk(" ++ origin_key(Pk) ++ ")")).

addr_and_raw_empty_provider() ->
    Pk = hexdec(?PK_C),
    Pkh = p2pkh(Pk),
    Addr = beamchain_address:script_to_address(Pkh, regtest),
    seed(Pkh, 100000000, false),
    {_, MapA} = scan_ok([bin("addr(" ++ Addr ++ ")")]),
    assert_desc(MapA, Pkh, cs("addr(" ++ Addr ++ ")")),
    {_, MapR} = scan_ok([bin("raw(" ++ hexs(Pkh) ++ ")")]),
    assert_desc(MapR, Pkh, cs("addr(" ++ Addr ++ ")")),
    Wpkh = p2wpkh(Pk),
    seed(Wpkh, 100000000, false),
    WAddr = beamchain_address:script_to_address(Wpkh, regtest),
    {_, MapW} = scan_ok([bin("raw(" ++ hexs(Wpkh) ++ ")")]),
    assert_desc(MapW, Wpkh, cs("addr(" ++ WAddr ++ ")")),
    P2sh = p2sh(<<16#51>>),
    seed(P2sh, 100000000, false),
    ShAddr = beamchain_address:script_to_address(P2sh, regtest),
    {_, MapS} = scan_ok([bin("raw(" ++ hexs(P2sh) ++ ")")]),
    assert_desc(MapS, P2sh, cs("addr(" ++ ShAddr ++ ")")),
    P2wsh = p2wsh(<<16#51>>),
    seed(P2wsh, 100000000, false),
    WsAddr = beamchain_address:script_to_address(P2wsh, regtest),
    {_, MapWS} = scan_ok([bin("raw(" ++ hexs(P2wsh) ++ ")")]),
    assert_desc(MapWS, P2wsh, cs("addr(" ++ WsAddr ++ ")")),
    X = hexdec(?X1),
    Rawtr = <<16#51, 16#20, X/binary>>,
    %% Seeded by tr_odd_vs_xonly; scanning raw() must not invent an origin.
    {_, MapT} = scan_ok([bin("raw(" ++ hexs(Rawtr) ++ ")")]),
    assert_desc(MapT, Rawtr, cs("rawtr(" ++ ?X1 ++ ")")),
    BadTr = <<16#51, 16#20, 0:256>>,
    seed(BadTr, 100000000, false),
    BadAddr = beamchain_address:script_to_address(BadTr, regtest),
    {_, MapB} = scan_ok([bin("raw(" ++ hexs(BadTr) ++ ")")]),
    assert_desc(MapB, BadTr, cs("addr(" ++ BadAddr ++ ")")),
    PkScript = p2pk(Pk),
    {_, MapP} = scan_ok([bin("raw(" ++ hexs(PkScript) ++ ")")]),
    assert_desc(MapP, PkScript, cs("pk(" ++ ?PK_C ++ ")")).

first_descriptor_wins() ->
    Pk = hexdec(?PK_C),
    Script = p2wpkh(Pk),
    seed(Script, 100000000, false),
    WAddr = beamchain_address:script_to_address(Script, regtest),
    Raw = bin("raw(" ++ hexs(Script) ++ ")"),
    Wpkh = bin("wpkh(" ++ ?PK_C ++ ")"),
    {_, First} = scan_ok([Wpkh, Raw]),
    assert_desc(First, Script, cs("wpkh(" ++ origin_key(Pk) ++ ")")),
    {_, Second} = scan_ok([Raw, Wpkh]),
    assert_desc(Second, Script, cs("addr(" ++ WAddr ++ ")")).

ranges() ->
    Specs = [{0, xpub_child(?XPUB, [0, 0])},
             {1, xpub_child(?XPUB, [0, 1])},
             {2, xpub_child(?XPUB, [0, 2])},
             {3, xpub_child(?XPUB, [0, 3])},
             {1000, xpub_child(?XPUB, [0, 1000])},
             {1001, xpub_child(?XPUB, [0, 1001])}],
    lists:foreach(fun({_, {_, S}}) -> seed(S, 10000, false) end, Specs),
    Desc = bin("wpkh(" ++ ?XPUB ++ "/0/*)"),
    SpecScripts = [S || {_, {_, S}} <- Specs],
    {_, Map0} = scan_ok([#{<<"desc">> => Desc, <<"range">> => [0, 2]}]),
    ?assertEqual(lists:usort([S || {I, {_, S}} <- Specs, I =< 2]),
                 lists:usort([hexdec(maps:get(<<"scriptPubKey">>, U))
                              || U <- maps:get(<<"unspents">>, Map0),
                                 lists:member(hexdec(maps:get(<<"scriptPubKey">>, U)),
                                              SpecScripts)])),
    {_, {_, S3}} = lists:keyfind(3, 1, Specs),
    ?assertEqual([], matches(Map0, S3)),
    {_, MapD} = scan_ok([Desc]),
    {_, {_, S1000}} = lists:keyfind(1000, 1, Specs),
    {_, {_, S1001}} = lists:keyfind(1001, 1, Specs),
    ?assert(matches(MapD, S1000) =/= []),
    ?assertEqual([], matches(MapD, S1001)).

nonrange_ignores_range() ->
    Pk = hexdec(?PK_C),
    Script = p2wpkh(Pk),
    {_, Map} = scan_ok([#{<<"desc">> => bin("wpkh(" ++ ?PK_C ++ ")"),
                          <<"range">> => 999999}]),
    assert_desc(Map, Script, cs("wpkh(" ++ origin_key(Pk) ++ ")")).

empty_scan() ->
    {Raw, Map} = scan_ok([]),
    ?assertEqual(true, maps:get(<<"success">>, Map)),
    ?assertEqual([], maps:get(<<"unspents">>, Map)),
    ?assert(is_integer(maps:get(<<"txouts">>, Map))),
    assert_result_key_order(Raw).

unspent_order() ->
    Script = <<16#51, 16#20, 1, 2, 3, 4>>,
    %% Internal memcmp puts B before A. Display hex sorts the other way.
    TxA = <<1, 0:248>>,
    TxB = <<0, 1, 0:240>>,
    ok = beamchain_chainstate:add_utxo(
           TxA, 1, #utxo{value = 1, script_pubkey = Script,
                         is_coinbase = false, height = 0}),
    ok = beamchain_chainstate:add_utxo(
           TxA, 0, #utxo{value = 2, script_pubkey = Script,
                         is_coinbase = false, height = 0}),
    ok = beamchain_chainstate:add_utxo(
           TxB, 0, #utxo{value = 3, script_pubkey = Script,
                         is_coinbase = false, height = 0}),
    {_, Map} = scan_ok([bin("raw(" ++ hexs(Script) ++ ")")]),
    Got = [{maps:get(<<"txid">>, U), maps:get(<<"vout">>, U)}
           || U <- matches(Map, Script)],
    ?assertEqual([{display(TxB), 0}, {display(TxA), 0}, {display(TxA), 1}],
                 Got),
    ?assert(display(TxA) < display(TxB)).

coin_fields() ->
    Script = <<4, 5, 6, 7>>,
    Txid = <<9, 0:248>>,
    ok = beamchain_chainstate:add_utxo(
           Txid, 0, #utxo{value = 123456789, script_pubkey = Script,
                          is_coinbase = true, height = 0}),
    {Raw, Map} = scan_ok([bin("raw(" ++ hexs(Script) ++ ")")]),
    [U] = matches(Map, Script),
    ?assertEqual(true, maps:get(<<"success">>, Map)),
    ?assert(is_integer(maps:get(<<"txouts">>, Map))),
    ?assert(maps:get(<<"txouts">>, Map) >= 1),
    {ok, {TipHash, TipH}} = beamchain_chainstate:get_tip(),
    ?assertEqual(TipH, maps:get(<<"height">>, Map)),
    ?assertEqual(display(TipHash), maps:get(<<"bestblock">>, Map)),
    ?assertEqual(display(Txid), maps:get(<<"txid">>, U)),
    ?assertEqual(0, maps:get(<<"vout">>, U)),
    ?assertEqual(true, maps:get(<<"coinbase">>, U)),
    ?assertEqual(0, maps:get(<<"height">>, U)),
    ?assertEqual(display(TipHash), maps:get(<<"blockhash">>, U)),
    ?assertEqual(TipH - 0 + 1, maps:get(<<"confirmations">>, U)),
    ?assert(binary:match(Raw, <<"\"amount\":1.23456789">>) =/= nomatch),
    ?assert(binary:match(Raw, <<"\"total_amount\":1.23456789">>) =/= nomatch),
    ?assertEqual(cs("raw(04050607)"), maps:get(<<"desc">>, U)).

bare_address_rejected() ->
    Pk = hexdec(?PK_C),
    Addr = beamchain_address:script_to_address(p2pkh(Pk), regtest),
    assert_err([<<"start">>, [bin(Addr)]], -5,
               bin("'" ++ Addr ++ "' is not a valid descriptor function")).

%%% ===================================================================
%%% Scan / fixture helpers
%%% ===================================================================

assert_err(Params, Code, Msg) ->
    ?assertEqual({error, Code, Msg},
                 beamchain_rpc:handle_method(<<"scantxoutset">>, Params, undefined)).

scan_ok(Objs) ->
    case beamchain_rpc:handle_method(<<"scantxoutset">>,
                                     [<<"start">>, Objs], undefined) of
        {ok_raw_json, Bin} ->
            {Bin, jsx:decode(Bin, [return_maps])};
        Other ->
            error({scan_failed, Other})
    end.

matches(Map, Script) ->
    Hex = hex(Script),
    [U || U <- maps:get(<<"unspents">>, Map),
          maps:get(<<"scriptPubKey">>, U) =:= Hex].

%% Every coin of Script must carry the same inferred descriptor. The
%% chainstate is shared, so a script seeded by an earlier case can show
%% up more than once.
assert_desc(Map, Script, Expected) ->
    Ms = matches(Map, Script),
    ?assert(Ms =/= []),
    ?assertEqual([Expected],
                 lists:usort([maps:get(<<"desc">>, U) || U <- Ms])).

seed(Script, Value, Coinbase) ->
    N = erlang:unique_integer([positive, monotonic]),
    Txid = <<N:32/big, 0:224>>,
    ok = beamchain_chainstate:add_utxo(
           Txid, 0, #utxo{value = Value, script_pubkey = Script,
                          is_coinbase = Coinbase, height = 0}).

assert_result_key_order(Raw) ->
    assert_increasing(key_positions(
                        Raw,
                        [<<"success">>, <<"txouts">>, <<"height">>,
                         <<"bestblock">>, <<"unspents">>, <<"total_amount">>],
                        0)).

assert_unspent_key_order(Raw) ->
    {Pos, _} = binary:match(Raw, <<"\"unspents\":[">>),
    assert_increasing(key_positions(
                        Raw,
                        [<<"txid">>, <<"vout">>, <<"scriptPubKey">>,
                         <<"desc">>, <<"amount">>, <<"coinbase">>,
                         <<"height">>, <<"blockhash">>, <<"confirmations">>],
                        Pos)).

%% '_' would match a missing key. Require real, strictly increasing offsets.
assert_increasing(Pos) ->
    ?assert(lists:all(fun is_integer/1, Pos)),
    ?assertEqual(Pos, lists:usort(Pos)).

key_positions(_Bin, [], _Off) -> [];
key_positions(Bin, [K | Rest], Off) ->
    Needle = <<"\"", K/binary, "\":">>,
    case binary:match(Bin, Needle, [{scope, {Off, byte_size(Bin) - Off}}]) of
        {Pos, Len} -> [Pos | key_positions(Bin, Rest, Pos + Len)];
        nomatch -> [nomatch | key_positions(Bin, Rest, Off)]
    end.

%%% ===================================================================
%%% Descriptor / script helpers (Core rules, local to the test)
%%% ===================================================================

cs(Str) ->
    bin(Str ++ "#" ++ beamchain_descriptor:checksum(Str)).

fp(Pub) ->
    <<F:4/binary, _/binary>> = beamchain_crypto:hash160(Pub),
    binary_to_list(hex(F)).

origin_key(Pub) ->
    "[" ++ fp(Pub) ++ "]" ++ hexs(Pub).

%% ConstPubkeyProvider for an x-only input stores the even 33-byte key.
origin_xonly(X32) ->
    "[" ++ fp(<<2, X32/binary>>) ++ "]" ++ hexs(X32).

%% A 33-byte tr() key is stored as-is. Inference still prints the x-only
%% form; the fingerprint is hash160 of that 33-byte key (GetKeyOriginByXOnly
%% probes hash160(02||x) then hash160(03||x)).
origin_key_xonly(Pub33, X32) ->
    "[" ++ fp(Pub33) ++ "]" ++ hexs(X32).

xpub_fp_path(Xpub, PathStr) ->
    {ok, Key, _} = beamchain_descriptor:decode_xpub(Xpub),
    "[" ++ fp(Key) ++ "/" ++ PathStr ++ "]".

xpub_child(Xpub, Path) ->
    {Child, _} = ckd_path(Xpub, Path),
    {Child, p2wpkh(Child)}.

ckd_path(Xpub, Path) ->
    {ok, Key, CC} = beamchain_descriptor:decode_xpub(Xpub),
    lists:foldl(fun(I, {P, C}) -> ckd(P, C, I) end, {Key, CC}, Path).

ckd(Pub, CC, Index) ->
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(CC, <<Pub/binary, Index:32/big>>),
    {ok, Child} = beamchain_crypto:pubkey_tweak_add(Pub, IL),
    {Child, IR}.

uncompressed() ->
    {ok, Uncomp} = beamchain_crypto:pubkey_decompress(hexdec(?PK_A34)),
    Uncomp.

p2pk(Pk) ->
    <<(byte_size(Pk)), Pk/binary, 16#ac>>.

p2pkh(Pk) ->
    H = beamchain_crypto:hash160(Pk),
    <<16#76, 16#a9, 20, H/binary, 16#88, 16#ac>>.

p2wpkh(Pk) ->
    H = beamchain_crypto:hash160(Pk),
    <<0, 20, H/binary>>.

p2sh(Script) ->
    H = beamchain_crypto:hash160(Script),
    <<16#a9, 20, H/binary, 16#87>>.

p2wsh(Script) ->
    H = beamchain_crypto:sha256(Script),
    <<0, 32, H/binary>>.

multi(K, Keys) ->
    Pushes = iolist_to_binary([<<(byte_size(PK)), PK/binary>> || PK <- Keys]),
    <<(op_n(K)), Pushes/binary, (op_n(length(Keys))), 16#ae>>.

op_n(N) when N >= 1, N =< 16 -> 16#50 + N.

pk_leaf(X32) ->
    <<32, X32/binary, 16#ac>>.

%% TaprootBuilder::Insert / ComputeTapbranchHash. A single depth-0 leaf
%% matches the Core vector asserted in tr_pk_leaf/0.
tr_output(Internal, Leaves) ->
    Tweak = case merkle(Leaves) of
                none ->
                    beamchain_crypto:tagged_hash(<<"TapTweak">>, Internal);
                Root ->
                    beamchain_crypto:tagged_hash(
                      <<"TapTweak">>, <<Internal/binary, Root/binary>>)
            end,
    {ok, Out, _} = beamchain_crypto:xonly_pubkey_tweak_add(Internal, Tweak),
    <<16#51, 16#20, Out/binary>>.

merkle([]) ->
    none;
merkle(Leaves) ->
    Branch = lists:foldl(fun({D, S}, B) ->
                                 tap_insert(tapleaf(S), D, B)
                         end, [], Leaves),
    [Root] = Branch,
    Root.

tapleaf(Script) ->
    Data = <<16#c0, (byte_size(Script)), Script/binary>>,
    beamchain_crypto:tagged_hash(<<"TapLeaf">>, Data).

tapbranch(A, B) ->
    {L, R} = case A < B of true -> {A, B}; false -> {B, A} end,
    beamchain_crypto:tagged_hash(<<"TapBranch">>, <<L/binary, R/binary>>).

tap_insert(Node, Depth, Branch) ->
    tap_insert2(Node, Depth, Branch).

tap_insert2(Node, Depth, Branch) when length(Branch) > Depth ->
    case lists:nth(Depth + 1, Branch) of
        empty ->
            set_nth(Depth + 1, Node, Branch);
        Existing ->
            tap_insert2(tapbranch(Node, Existing), Depth - 1,
                        lists:droplast(Branch))
    end;
tap_insert2(Node, Depth, Branch) ->
    Pad = lists:duplicate(Depth + 1 - length(Branch), empty),
    set_nth(Depth + 1, Node, Branch ++ Pad).

set_nth(1, V, [_ | T]) -> [V | T];
set_nth(N, V, [H | T]) -> [H | set_nth(N - 1, V, T)].

hex(Bin) ->
    beamchain_serialize:hex_encode(Bin).

hexs(Bin) ->
    binary_to_list(hex(Bin)).

hexdec(Str) when is_list(Str) ->
    beamchain_serialize:hex_decode(list_to_binary(Str));
hexdec(Bin) when is_binary(Bin) ->
    beamchain_serialize:hex_decode(Bin).

bin(Str) when is_list(Str) -> list_to_binary(Str);
bin(Bin) when is_binary(Bin) -> Bin.

display(Hash) ->
    hex(beamchain_serialize:reverse_bytes(Hash)).

%%% ===================================================================
%%% Fixture
%%% ===================================================================

setup() ->
    TmpDir = filename:join(["/tmp", "beamchain_scanparity_" ++
                            integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    application:ensure_all_started(crypto),
    application:ensure_all_started(rocksdb),
    application:set_env(beamchain, datadir, TmpDir),
    application:set_env(beamchain, network, regtest),
    application:set_env(beamchain, fatal_halt, false),
    os:unsetenv("BEAMCHAIN_DATADIR"),
    os:unsetenv("BEAMCHAIN_NETWORK"),
    os:unsetenv("BEAMCHAIN_TEST_HOOK_DIR"),
    catch beamchain_fault:clear_all(),
    catch beamchain_fatal:reset_for_test(),
    catch gen_server:stop(beamchain_chainstate),
    catch beamchain_db:stop(),
    catch gen_server:stop(beamchain_config),
    delete_ets(),
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
    delete_ets(),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

delete_ets() ->
    lists:foreach(
      fun(T) ->
          case ets:info(T) of
              undefined -> ok;
              _ -> catch ets:delete(T)
          end
      end,
      [beamchain_utxo_cache, beamchain_utxo_dirty, beamchain_utxo_fresh,
       beamchain_utxo_spent, beamchain_chain_meta, beamchain_scantxoutset]).
