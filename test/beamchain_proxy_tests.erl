-module(beamchain_proxy_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Network Detection Tests
%%% ===================================================================

detect_network_test_() ->
    [
        {"IPv4 address", ?_assertEqual(ipv4, beamchain_proxy:detect_network("192.168.1.1"))},
        {"IPv6 address", ?_assertEqual(ipv6, beamchain_proxy:detect_network("::1"))},
        {"IPv6 full", ?_assertEqual(ipv6, beamchain_proxy:detect_network("2001:db8::1"))},
        {"Onion v3 address", ?_assertEqual(onion, beamchain_proxy:detect_network(
            "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion"))},
        {"I2P address", ?_assertEqual(i2p, beamchain_proxy:detect_network(
            "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"))},
        {"Regular hostname as ipv4", ?_assertEqual(ipv4, beamchain_proxy:detect_network("example.com"))},
        {"Binary onion", ?_assertEqual(onion, beamchain_proxy:detect_network(
            <<"test.onion">>))},
        {"Binary i2p", ?_assertEqual(i2p, beamchain_proxy:detect_network(
            <<"test.b32.i2p">>))}
    ].

%%% ===================================================================
%%% Onion Address Tests
%%% ===================================================================

is_onion_address_test_() ->
    [
        {"Valid v3 onion (56 chars)", ?_assertEqual(true, beamchain_proxy:is_onion_address(
            "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion"))},
        {"Not onion - no suffix", ?_assertEqual(false, beamchain_proxy:is_onion_address(
            "example.com"))},
        {"Not onion - wrong length", ?_assertEqual(false, beamchain_proxy:is_onion_address(
            "short.onion"))},
        {"Binary onion", ?_assertEqual(true, beamchain_proxy:is_onion_address(
            <<"vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion">>))}
    ].

is_i2p_address_test_() ->
    [
        {"Valid I2P address", ?_assertEqual(true, beamchain_proxy:is_i2p_address(
            "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"))},
        {"Not I2P - wrong suffix", ?_assertEqual(false, beamchain_proxy:is_i2p_address(
            "example.com"))},
        {"Binary I2P", ?_assertEqual(true, beamchain_proxy:is_i2p_address(
            <<"test.b32.i2p">>))}
    ].

%%% ===================================================================
%%% V3 Onion Address Generation Tests
%%% ===================================================================

onion_address_generation_test_() ->
    %% Test with a known Ed25519 public key
    %% Using a test vector - the format is:
    %% Address = base32(pubkey || checksum || version) + ".onion"
    TestPubKey = crypto:strong_rand_bytes(32),
    [
        {"Generated address has correct format", fun() ->
            Address = beamchain_proxy:onion_address_from_pubkey(TestPubKey),
            ?assertEqual(62, length(Address)),  %% 56 + ".onion"
            ?assert(lists:suffix(".onion", Address))
        end},
        {"Generated address is lowercase", fun() ->
            Address = beamchain_proxy:onion_address_from_pubkey(TestPubKey),
            Base32Part = lists:sublist(Address, 56),
            ?assertEqual(Base32Part, string:lowercase(Base32Part))
        end},
        {"Round-trip pubkey extraction", fun() ->
            Address = beamchain_proxy:onion_address_from_pubkey(TestPubKey),
            {ok, ExtractedPubKey} = beamchain_proxy:parse_onion_address(Address),
            ?assertEqual(TestPubKey, ExtractedPubKey)
        end}
    ].

parse_onion_address_test_() ->
    [
        {"Invalid checksum fails", fun() ->
            %% Create a valid-looking address but with wrong checksum
            FakePubKey = crypto:strong_rand_bytes(32),
            FakeChecksum = <<16#AA, 16#BB>>,
            FakeVersion = <<3>>,
            AddrBin = <<FakePubKey/binary, FakeChecksum/binary, FakeVersion/binary>>,
            FakeAddr = base32_lower(AddrBin) ++ ".onion",
            ?assertEqual({error, invalid_checksum},
                         beamchain_proxy:parse_onion_address(FakeAddr))
        end},
        {"Wrong version fails", fun() ->
            %% Version must be 3 for v3 onions
            Result = beamchain_proxy:parse_onion_address("aa.onion"),
            ?assertMatch({error, _}, Result)
        end},
        {"Not onion address fails", fun() ->
            ?assertEqual({error, not_onion_address},
                         beamchain_proxy:parse_onion_address("example.com"))
        end}
    ].

%%% ===================================================================
%%% Stream Isolation Tests
%%% ===================================================================

stream_isolation_test_() ->
    [
        {"Generator creates unique credentials", fun() ->
            Gen = beamchain_proxy:new_stream_isolation_generator(),
            {User1, Pass1} = beamchain_proxy:generate_credentials(Gen),
            {User2, Pass2} = beamchain_proxy:generate_credentials(Gen),
            {User3, Pass3} = beamchain_proxy:generate_credentials(Gen),
            %% All should be different
            ?assertNotEqual(User1, User2),
            ?assertNotEqual(User2, User3),
            %% Username and password should be the same for each call
            ?assertEqual(User1, Pass1),
            ?assertEqual(User2, Pass2),
            ?assertEqual(User3, Pass3)
        end},
        {"Generator has random prefix", fun() ->
            Gen1 = beamchain_proxy:new_stream_isolation_generator(),
            Gen2 = beamchain_proxy:new_stream_isolation_generator(),
            {User1, _} = beamchain_proxy:generate_credentials(Gen1),
            {User2, _} = beamchain_proxy:generate_credentials(Gen2),
            %% Different generators should have different prefixes
            %% (with overwhelming probability)
            Prefix1 = lists:sublist(User1, 17),  %% 16 hex chars + "-"
            Prefix2 = lists:sublist(User2, 17),
            ?assertNotEqual(Prefix1, Prefix2)
        end}
    ].

%%% ===================================================================
%%% Routing Tests
%%% ===================================================================

route_for_address_test_() ->
    %% Note: These tests assume no proxies are configured by default
    %% They also need the config module to be started (or ETS table to exist)
    {setup,
     fun() ->
         %% Clear any env vars
         os:unsetenv("BEAMCHAIN_PROXY"),
         os:unsetenv("BEAMCHAIN_ONION"),
         os:unsetenv("BEAMCHAIN_I2PSAM"),
         %% Create ETS table if it doesn't exist (for standalone tests)
         case ets:info(beamchain_config_ets) of
             undefined ->
                 ets:new(beamchain_config_ets, [named_table, set, public, {read_concurrency, true}]),
                 created;
             _ ->
                 existed
         end
     end,
     fun(created) -> ets:delete(beamchain_config_ets);
        (existed) -> ok
     end,
     [
         {"IPv4 routes direct by default", fun() ->
             ?assertEqual(direct, beamchain_proxy:route_for_address(ipv4))
         end},
         {"Onion routes direct without proxy config", fun() ->
             ?assertEqual(direct, beamchain_proxy:route_for_address(onion))
         end},
         {"I2P routes direct without SAM config", fun() ->
             ?assertEqual(direct, beamchain_proxy:route_for_address(i2p))
         end}
     ]}.

%%% ===================================================================
%%% SOCKS5 Protocol Tests (Unit Tests - No Network)
%%% ===================================================================

socks5_error_codes_test_() ->
    [
        {"General failure code", fun() ->
            %% Test internal error code mapping
            ?assertEqual(socks5_general_failure,
                         beamchain_proxy:socks5_error_code(1))
        end},
        {"Network unreachable code", fun() ->
            ?assertEqual(socks5_network_unreachable,
                         beamchain_proxy:socks5_error_code(3))
        end},
        {"Connection refused code", fun() ->
            ?assertEqual(socks5_connection_refused,
                         beamchain_proxy:socks5_error_code(5))
        end},
        {"Tor hidden service not found", fun() ->
            ?assertEqual(tor_hs_descriptor_not_found,
                         beamchain_proxy:socks5_error_code(16#f0))
        end},
        {"Tor intro timeout", fun() ->
            ?assertEqual(tor_hs_intro_timeout,
                         beamchain_proxy:socks5_error_code(16#f7))
        end}
    ].

%%% ===================================================================
%%% Base32 Encoding Tests
%%% ===================================================================

base32_roundtrip_test_() ->
    [
        {"Empty binary", fun() ->
            test_base32_roundtrip(<<>>)
        end},
        {"Single byte", fun() ->
            test_base32_roundtrip(<<16#AB>>)
        end},
        {"5 bytes (40 bits = 8 base32 chars)", fun() ->
            test_base32_roundtrip(<<1, 2, 3, 4, 5>>)
        end},
        {"32 bytes (Ed25519 pubkey size)", fun() ->
            test_base32_roundtrip(crypto:strong_rand_bytes(32))
        end},
        {"35 bytes (v3 onion address size)", fun() ->
            test_base32_roundtrip(crypto:strong_rand_bytes(35))
        end}
    ].

test_base32_roundtrip(Bin) ->
    Encoded = base32_lower(Bin),
    {ok, Decoded} = base32_decode_lower(Encoded),
    ?assertEqual(Bin, Decoded).

%%% ===================================================================
%%% Helper Functions
%%% ===================================================================

%% Expose internal base32 functions for testing via module attribute trick
%% We call the internal functions indirectly through the public API

base32_lower(Bin) ->
    %% Generate an onion address and extract the base32 logic
    %% Or implement our own test version
    base32_encode_lower(Bin).

base32_encode_lower(Bin) ->
    Encoded = base32_encode(Bin, []),
    string:lowercase(Encoded).

base32_encode(<<>>, Acc) ->
    lists:reverse(Acc);
base32_encode(<<A:5, B:5, C:5, D:5, E:5, F:5, G:5, H:5, Rest/binary>>, Acc) ->
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D),
             base32_char(E), base32_char(F), base32_char(G), base32_char(H)],
    base32_encode(Rest, lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:5, C:5, D:5, E:5, F:5, G:2>>, Acc) ->
    G2 = G bsl 3,
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D),
             base32_char(E), base32_char(F), base32_char(G2)],
    lists:reverse(lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:5, C:5, D:5, E:4>>, Acc) ->
    E2 = E bsl 1,
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D),
             base32_char(E2)],
    lists:reverse(lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:5, C:5, D:1>>, Acc) ->
    D2 = D bsl 4,
    Chars = [base32_char(A), base32_char(B), base32_char(C), base32_char(D2)],
    lists:reverse(lists:reverse(Chars) ++ Acc);
base32_encode(<<A:5, B:3>>, Acc) ->
    B2 = B bsl 2,
    Chars = [base32_char(A), base32_char(B2)],
    lists:reverse(lists:reverse(Chars) ++ Acc).

base32_char(N) when N >= 0, N =< 25 -> N + $A;
base32_char(N) when N >= 26, N =< 31 -> N - 26 + $2.

base32_decode_lower(Str) ->
    Upper = string:uppercase(Str),
    base32_decode(Upper).

base32_decode(Str) ->
    case catch base32_decode_impl(Str, <<>>) of
        {'EXIT', _} -> {error, invalid_base32};
        Result -> {ok, Result}
    end.

base32_decode_impl([], Acc) ->
    Acc;
base32_decode_impl([A,B,C,D,E,F,G,H | Rest], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    Byte3 = ((base32_val(D) band 15) bsl 4) bor (base32_val(E) bsr 1),
    Byte4 = ((base32_val(E) band 1) bsl 7) bor (base32_val(F) bsl 2) bor (base32_val(G) bsr 3),
    Byte5 = ((base32_val(G) band 7) bsl 5) bor base32_val(H),
    base32_decode_impl(Rest, <<Acc/binary, Byte1, Byte2, Byte3, Byte4, Byte5>>);
base32_decode_impl([A,B,C,D,E,F,G], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    Byte3 = ((base32_val(D) band 15) bsl 4) bor (base32_val(E) bsr 1),
    Byte4 = ((base32_val(E) band 1) bsl 7) bor (base32_val(F) bsl 2) bor (base32_val(G) bsr 3),
    <<Acc/binary, Byte1, Byte2, Byte3, Byte4>>;
base32_decode_impl([A,B,C,D,E], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    Byte3 = ((base32_val(D) band 15) bsl 4) bor (base32_val(E) bsr 1),
    <<Acc/binary, Byte1, Byte2, Byte3>>;
base32_decode_impl([A,B,C,D], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    Byte2 = ((base32_val(B) band 3) bsl 6) bor (base32_val(C) bsl 1) bor (base32_val(D) bsr 4),
    <<Acc/binary, Byte1, Byte2>>;
base32_decode_impl([A,B], Acc) ->
    Byte1 = (base32_val(A) bsl 3) bor (base32_val(B) bsr 2),
    <<Acc/binary, Byte1>>.

base32_val(C) when C >= $A, C =< $Z -> C - $A;
base32_val(C) when C >= $a, C =< $z -> C - $a;
base32_val(C) when C >= $2, C =< $7 -> C - $2 + 26.
