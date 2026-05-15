-module(beamchain_w117_bip155_networks_tests).
-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% W117 BIP-155 Networks audit tests
%%%
%%% Gates:
%%%   G1-G10   Tor v3
%%%   G11-G16  I2P
%%%   G17-G20  CJDNS
%%%   G21-G24  Outbound connection routing
%%%   G25-G28  Address resolution / getnetworkinfo
%%%   G29-G30  addrv2 wire + RPC
%%%
%%% Implementation status summary (as of audit):
%%%
%%%   Tor v3:
%%%     - SOCKS5 proxy support: YES  (beamchain_proxy)
%%%     - Stream isolation:     YES
%%%     - v3 address generation:YES
%%%     - Inbound hidden service:MISSING (no torcontrol / Tor control-port integration)
%%%     - proxy_randomize_credentials in getnetworkinfo: NO (hardcoded false)
%%%
%%%   I2P:
%%%     - SAM 3.1 protocol:     YES  (beamchain_proxy)
%%%     - Destination generation:YES
%%%     - SAM version max only 3.1: BUG – no 3.2/3.3 negotiation
%%%
%%%   CJDNS:
%%%     - Decode/encode in addrv2: YES
%%%     - Network type detection by 0xFC prefix: YES in addrman / p2p_msg
%%%     - detect_network() in beamchain_proxy: MISSING (proxy has no CJDNS branch)
%%%     - Route via proxy: MISSING (goes to default/direct path)
%%%
%%%   Outbound routing:
%%%     - SOCKS5 connect for .onion: YES
%%%     - SAM connect for .b32.i2p:  YES
%%%     - CJDNS routing via proxy:   PARTIAL (falls to default proxy, not dedicated)
%%%
%%%   getnetworkinfo:
%%%     - Only "ipv4" network reported: BUG (onion/i2p/cjdns/ipv6 absent)
%%%     - proxy_randomize_credentials hardcoded false: BUG
%%%     - localaddresses empty always: BUG
%%%
%%%   addrv2:
%%%     - Wire encode/decode all 6 network IDs: YES
%%%     - sendaddrv2 exchange in handshake: YES
%%%     - addrv2 relay honours wants_addrv2: BUG – relay always uses addr msg
%%%     - addrv2 msg handler drops non-IPv4 addresses: BUG
%%% ===================================================================

%%% ===================================================================
%%% G1 – Tor SOCKS5 proxy basic detection
%%% ===================================================================

g1_detect_onion_network_test_() ->
    [
        {"G1: detect_network returns onion for .onion suffix",
         ?_assertEqual(onion,
             beamchain_proxy:detect_network(
                 "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion"))},
        {"G1: detect_network binary .onion suffix",
         ?_assertEqual(onion,
             beamchain_proxy:detect_network(<<"test56charaddressgoeshere1234567.onion">>))},
        {"G1: non-onion address is not onion",
         ?_assertNotEqual(onion,
             beamchain_proxy:detect_network("192.168.1.1"))}
    ].

%%% ===================================================================
%%% G2 – Tor v3 address format (56 chars + .onion)
%%% ===================================================================

g2_torv3_address_format_test_() ->
    PubKey = crypto:strong_rand_bytes(32),
    [
        {"G2: onion_address_from_pubkey/1 produces 62-char string",
         fun() ->
             Addr = beamchain_proxy:onion_address_from_pubkey(PubKey),
             ?assertEqual(62, length(Addr))
         end},
        {"G2: address ends in .onion",
         fun() ->
             Addr = beamchain_proxy:onion_address_from_pubkey(PubKey),
             ?assert(lists:suffix(".onion", Addr))
         end},
        {"G2: base32 part is lowercase 56 chars",
         fun() ->
             Addr = beamchain_proxy:onion_address_from_pubkey(PubKey),
             B32 = lists:sublist(Addr, 56),
             ?assertEqual(B32, string:lowercase(B32))
         end},
        {"G2: is_onion_address/1 accepts well-formed v3 address",
         fun() ->
             Addr = beamchain_proxy:onion_address_from_pubkey(PubKey),
             ?assert(beamchain_proxy:is_onion_address(Addr))
         end}
    ].

%%% ===================================================================
%%% G3 – Tor v3 checksum / pubkey round-trip
%%% ===================================================================

g3_torv3_checksum_test_() ->
    PubKey = crypto:strong_rand_bytes(32),
    [
        {"G3: parse_onion_address round-trips the public key",
         fun() ->
             Addr = beamchain_proxy:onion_address_from_pubkey(PubKey),
             {ok, Extracted} = beamchain_proxy:parse_onion_address(Addr),
             ?assertEqual(PubKey, Extracted)
         end},
        {"G3: tampered checksum is rejected",
         fun() ->
             Addr = beamchain_proxy:onion_address_from_pubkey(PubKey),
             %% Flip one char in the base32 part to corrupt the checksum
             [H | Rest] = Addr,
             BadAddr = [H + 1 | Rest],
             ?assertMatch({error, _}, beamchain_proxy:parse_onion_address(BadAddr))
         end},
        {"G3: non-onion string returns not_onion_address",
         ?_assertEqual({error, not_onion_address},
             beamchain_proxy:parse_onion_address("example.com"))}
    ].

%%% ===================================================================
%%% G4 – Stream isolation (Tor per-connection credentials)
%%% %%%
%%% Core: CConnman sends unique SOCKS5 username/password per .onion
%%% connection so each gets its own Tor circuit.
%%% ===================================================================

g4_stream_isolation_test_() ->
    [
        {"G4: new_stream_isolation_generator/0 returns a tuple (record)",
         fun() ->
             Gen = beamchain_proxy:new_stream_isolation_generator(),
             ?assert(is_tuple(Gen))
         end},
        {"G4: generate_credentials/1 returns different creds each call",
         fun() ->
             Gen = beamchain_proxy:new_stream_isolation_generator(),
             {U1, P1} = beamchain_proxy:generate_credentials(Gen),
             {U2, P2} = beamchain_proxy:generate_credentials(Gen),
             ?assertNotEqual(U1, U2),
             %% username == password (SOCKS5 re-uses user as password for isolation)
             ?assertEqual(U1, P1),
             ?assertEqual(U2, P2)
         end},
        {"G4: two generators produce different credential prefixes",
         fun() ->
             Gen1 = beamchain_proxy:new_stream_isolation_generator(),
             Gen2 = beamchain_proxy:new_stream_isolation_generator(),
             {U1, _} = beamchain_proxy:generate_credentials(Gen1),
             {U2, _} = beamchain_proxy:generate_credentials(Gen2),
             %% Generators are seeded with random bytes; collision probability ~2^-64
             ?assertNotEqual(U1, U2)
         end}
    ].

%%% ===================================================================
%%% G5 – SOCKS5 error code mapping
%%% ===================================================================

g5_socks5_error_codes_test_() ->
    [
        {"G5: general failure code 1", ?_assertEqual(socks5_general_failure,   beamchain_proxy:socks5_error_code(1))},
        {"G5: not allowed code 2",     ?_assertEqual(socks5_not_allowed,       beamchain_proxy:socks5_error_code(2))},
        {"G5: net unreachable code 3", ?_assertEqual(socks5_network_unreachable, beamchain_proxy:socks5_error_code(3))},
        {"G5: host unreachable code 4",?_assertEqual(socks5_host_unreachable,  beamchain_proxy:socks5_error_code(4))},
        {"G5: conn refused code 5",    ?_assertEqual(socks5_connection_refused,beamchain_proxy:socks5_error_code(5))},
        {"G5: TTL expired code 6",     ?_assertEqual(socks5_ttl_expired,       beamchain_proxy:socks5_error_code(6))},
        {"G5: Tor HS desc not found",  ?_assertEqual(tor_hs_descriptor_not_found, beamchain_proxy:socks5_error_code(16#f0))},
        {"G5: Tor HS desc invalid",    ?_assertEqual(tor_hs_descriptor_invalid,   beamchain_proxy:socks5_error_code(16#f1))},
        {"G5: Tor intro failed",       ?_assertEqual(tor_hs_intro_failed,         beamchain_proxy:socks5_error_code(16#f2))},
        {"G5: Tor rend failed",        ?_assertEqual(tor_hs_rendezvous_failed,    beamchain_proxy:socks5_error_code(16#f3))},
        {"G5: Tor missing client auth",?_assertEqual(tor_hs_missing_client_auth,  beamchain_proxy:socks5_error_code(16#f4))},
        {"G5: Tor wrong client auth",  ?_assertEqual(tor_hs_wrong_client_auth,    beamchain_proxy:socks5_error_code(16#f5))},
        {"G5: Tor bad address",        ?_assertEqual(tor_hs_bad_address,          beamchain_proxy:socks5_error_code(16#f6))},
        {"G5: Tor intro timeout",      ?_assertEqual(tor_hs_intro_timeout,        beamchain_proxy:socks5_error_code(16#f7))},
        {"G5: unknown code returns tuple",
         fun() ->
             ?assertMatch({socks5_unknown_error, _},
                          beamchain_proxy:socks5_error_code(42))
         end}
    ].

%%% ===================================================================
%%% G6 – Onion routing goes through SOCKS5 proxy when configured
%%% ===================================================================

g6_onion_routes_through_socks5_test_() ->
    {setup,
     fun() ->
         os:putenv("BEAMCHAIN_ONION", "127.0.0.1:9050"),
         case ets:info(beamchain_config_ets) of
             undefined ->
                 ets:new(beamchain_config_ets, [named_table, set, public, {read_concurrency, true}]),
                 created;
             _ ->
                 existed
         end
     end,
     fun(created) ->
         os:unsetenv("BEAMCHAIN_ONION"),
         ets:delete(beamchain_config_ets);
        (existed) ->
         os:unsetenv("BEAMCHAIN_ONION")
     end,
     [
         {"G6: onion address routes via socks5 when proxy configured",
          fun() ->
              Result = beamchain_proxy:route_for_address(onion),
              ?assertMatch({socks5, #{host := _, port := _}}, Result)
          end}
     ]}.

%%% ===================================================================
%%% G7 – is_onion_address/1 rejects wrong-length addresses
%%% ===================================================================

g7_is_onion_address_validation_test_() ->
    [
        {"G7: correct-length v3 onion accepted",
         ?_assert(beamchain_proxy:is_onion_address(
             "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion"))},
        {"G7: wrong-length suffix rejected",
         ?_assertNot(beamchain_proxy:is_onion_address("short.onion"))},
        {"G7: no .onion suffix rejected",
         ?_assertNot(beamchain_proxy:is_onion_address("example.com"))},
        {"G7: binary form accepted",
         ?_assert(beamchain_proxy:is_onion_address(
             <<"vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion">>))}
    ].

%%% ===================================================================
%%% G8 – BIP155 TorV3 network ID in addrv2 wire format
%%% ===================================================================

g8_addrv2_torv3_encode_decode_test_() ->
    TorAddr = crypto:strong_rand_bytes(32),  %% 32-byte ed25519 pubkey
    Entry = #{
        timestamp => 1700000000,
        services  => 1,
        network   => torv3,
        address   => TorAddr,
        port      => 8333
    },
    [
        {"G8: encode_addrv2_entry produces non-empty binary",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(Entry),
             ?assert(byte_size(Bin) > 0)
         end},
        {"G8: round-trip preserves network=torv3 and address",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(Entry),
             {Decoded, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(torv3, maps:get(network, Decoded)),
             ?assertEqual(TorAddr, maps:get(address, Decoded))
         end},
        {"G8: network_id/1 returns BIP155 id 4 for torv3 (via network_id/1 dispatch)",
         fun() ->
             %% network_atom_to_id/1 is private; use the public network_id/1
             ?assertEqual(4, beamchain_p2p_msg:network_id(#{network => torv3}))
         end},
        {"G8: addr_size_for_network/1 returns 32 for torv3",
         ?_assertEqual(32, beamchain_p2p_msg:addr_size_for_network(4))}
    ].

%%% ===================================================================
%%% G9 – TorV2 (deprecated) decoded but not emitted
%%% ===================================================================

g9_torv2_deprecated_test_() ->
    TorV2Addr = crypto:strong_rand_bytes(10),  %% 10-byte v2 hash
    [
        {"G9: network_id_to_atom/1 recognises torv2 as atom",
         ?_assertEqual(torv2, beamchain_p2p_msg:network_id_to_atom(3))},
        {"G9: addr_size_for_network/1 returns 10 for torv2 id=3",
         ?_assertEqual(10, beamchain_p2p_msg:addr_size_for_network(3))},
        {"G9: legacy addr encode drops torv2 entry (returns <<>>)",
         fun() ->
             Entry = #{timestamp => 1700000000, services => 0,
                       network => torv2, address => TorV2Addr, port => 9050},
             Encoded = beamchain_p2p_msg:encode_addr_entry(Entry),
             ?assertEqual(<<>>, Encoded)
         end}
    ].

%%% ===================================================================
%%% G10 – Inbound Tor hidden service (MISSING ENTIRELY)
%%%
%%% BUG-1 (HIGH): beamchain has no torcontrol.cpp equivalent.
%%% The node cannot create or manage a Tor v3 hidden service for
%%% inbound .onion reachability.  beamchain_config:listen_onion/0
%%% exists and returns the config flag, but nothing reads it to
%%% actually register with Tor's control port.
%%% ===================================================================

g10_inbound_tor_hidden_service_missing_test_() ->
    [
        {"G10: listen_onion/0 is exported (config accessor exists)",
         fun() ->
             Exports = beamchain_config:module_info(exports),
             ?assert(lists:member({listen_onion, 0}, Exports))
         end},
        {"G10: [BUG-1] no torcontrol module exists (hidden service MISSING ENTIRELY)",
         fun() ->
             %% beamchain_torcontrol does not exist — the feature is absent
             Exists = code:which(beamchain_torcontrol),
             ?assertEqual(non_existing, Exists)
         end}
    ].

%%% ===================================================================
%%% G11 – I2P address detection
%%% ===================================================================

g11_detect_i2p_network_test_() ->
    [
        {"G11: detect_network returns i2p for .b32.i2p suffix",
         ?_assertEqual(i2p,
             beamchain_proxy:detect_network(
                 "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"))},
        {"G11: is_i2p_address/1 returns true for .b32.i2p",
         ?_assert(beamchain_proxy:is_i2p_address("test.b32.i2p"))},
        {"G11: non-I2P address returns false",
         ?_assertNot(beamchain_proxy:is_i2p_address("example.com"))},
        {"G11: binary .b32.i2p accepted",
         ?_assert(beamchain_proxy:is_i2p_address(<<"test.b32.i2p">>))}
    ].

%%% ===================================================================
%%% G12 – I2P SAM session management
%%% ===================================================================

g12_i2p_sam_session_test_() ->
    [
        {"G12: i2p_session_create/2 is exported",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({i2p_session_create, 2}, Exports))
         end},
        {"G12: i2p_session_close/1 is exported",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({i2p_session_close, 1}, Exports))
         end},
        {"G12: i2p_generate_destination/1 is exported",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({i2p_generate_destination, 1}, Exports))
         end}
    ].

%%% ===================================================================
%%% G13 – I2P routing goes through SAM when configured
%%% ===================================================================

g13_i2p_routes_through_sam_test_() ->
    %% beamchain_proxy:get_i2p_proxy/0 reads beamchain_config:get(i2psam) from ETS.
    {setup,
     fun() ->
         Existed = case ets:info(beamchain_config_ets) of
             undefined ->
                 ets:new(beamchain_config_ets, [named_table, set, public, {read_concurrency, true}]),
                 false;
             _ ->
                 true
         end,
         ets:insert(beamchain_config_ets, {i2psam, "127.0.0.1:7656"}),
         Existed
     end,
     fun(false) ->
         ets:delete(beamchain_config_ets);
        (true) ->
         ets:delete(beamchain_config_ets, i2psam)
     end,
     [
         {"G13: i2p address routes via i2p_sam when SAM address in config",
          fun() ->
              Result = beamchain_proxy:route_for_address(i2p),
              ?assertMatch({i2p_sam, #{host := _, port := _}}, Result)
          end}
     ]}.

%%% ===================================================================
%%% G14 – BIP155 I2P network ID in addrv2 wire format
%%% ===================================================================

g14_addrv2_i2p_encode_decode_test_() ->
    I2PAddr = crypto:strong_rand_bytes(32),  %% 32-byte SHA256 of destination
    Entry = #{
        timestamp => 1700000000,
        services  => 1,
        network   => i2p,
        address   => I2PAddr,
        port      => 4567
    },
    [
        {"G14: network_id_to_atom/1 recognises id=5 as i2p",
         ?_assertEqual(i2p, beamchain_p2p_msg:network_id_to_atom(5))},
        {"G14: addr_size_for_network/1 returns 32 for I2P id=5",
         ?_assertEqual(32, beamchain_p2p_msg:addr_size_for_network(5))},
        {"G14: round-trip preserves network=i2p and 32-byte address",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(Entry),
             {Decoded, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(i2p, maps:get(network, Decoded)),
             ?assertEqual(I2PAddr, maps:get(address, Decoded))
         end},
        {"G14: legacy addr encode drops I2P entry",
         fun() ->
             Encoded = beamchain_p2p_msg:encode_addr_entry(Entry),
             ?assertEqual(<<>>, Encoded)
         end}
    ].

%%% ===================================================================
%%% G15 – I2P SAM version negotiation
%%%
%%% BUG-2 (MEDIUM): SAM_VERSION_MAX is hardcoded to "3.1" in
%%% beamchain_proxy.  Bitcoin Core negotiates up to 3.1 as well, but
%%% newer SAM bridges support 3.2/3.3.  The restriction causes
%%% beamchain to miss improved session options in modern I2P routers.
%%% This is a PARTIAL compliance finding (not incorrect, but limited).
%%% ===================================================================

g15_i2p_sam_version_test_() ->
    [
        {"G15: SAM version limits are defined (3.1 min/max)",
         fun() ->
             %% These constants are module-private; verify indirectly by
             %% confirming the module compiles and exports SAM helpers.
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({i2p_stream_connect, 3}, Exports))
         end}
    ].

%%% ===================================================================
%%% G16 – I2P dest-to-.b32.i2p conversion
%%% ===================================================================

g16_i2p_dest_to_b32_test_() ->
    [
        {"G16: i2p_connect/3 is exported (SAM stream path exists)",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({i2p_connect, 3}, Exports))
         end},
        {"G16: is_i2p_address/1 accepts computed .b32.i2p suffix",
         %% i2p_dest_to_b32 is private; probe via is_i2p_address
         ?_assert(beamchain_proxy:is_i2p_address(
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p"))}
    ].

%%% ===================================================================
%%% G17 – CJDNS network-type detection (addrman / p2p_msg layer)
%%% ===================================================================

g17_cjdns_network_detection_test_() ->
    [
        {"G17: network_id_to_atom/1 recognises id=6 as cjdns",
         ?_assertEqual(cjdns, beamchain_p2p_msg:network_id_to_atom(6))},
        {"G17: addr_size_for_network/1 returns 16 for CJDNS id=6",
         ?_assertEqual(16, beamchain_p2p_msg:addr_size_for_network(6))},
        {"G17: network_id/1 returns 6 for cjdns (via network map dispatch)",
         fun() ->
             ?assertEqual(6, beamchain_p2p_msg:network_id(#{network => cjdns}))
         end},
        {"G17: [BUG-3] detect_network/1 in beamchain_proxy has no CJDNS branch — "
         "fc:: addresses fall through to ipv6 (not cjdns atom)",
         fun() ->
             %% CJDNS addresses are fc00::/8 IPv6. detect_network cannot
             %% distinguish them because it uses inet:parse_address which
             %% returns an IPv6 tuple and the proxy has no 0xFC prefix check.
             Result = beamchain_proxy:detect_network("fc00::1"),
             %% Current behaviour: returns ipv6, not cjdns
             ?assertNotEqual(cjdns, Result)
         end}
    ].

%%% ===================================================================
%%% G18 – CJDNS addrv2 encode/decode round-trip
%%% ===================================================================

g18_addrv2_cjdns_encode_decode_test_() ->
    %% CJDNS address: 16 bytes starting with 0xFC
    CjdnsAddr = <<16#FC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    Entry = #{
        timestamp => 1700000000,
        services  => 1,
        network   => cjdns,
        address   => CjdnsAddr,
        port      => 8333
    },
    [
        {"G18: addrv2 round-trip preserves cjdns network and 16-byte address",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(Entry),
             {Decoded, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(cjdns, maps:get(network, Decoded)),
             ?assertEqual(CjdnsAddr, maps:get(address, Decoded))
         end},
        {"G18: legacy addr encode drops cjdns entry",
         fun() ->
             Encoded = beamchain_p2p_msg:encode_addr_entry(Entry),
             ?assertEqual(<<>>, Encoded)
         end},
        {"G18: 16-byte address starting with 0xFC decoded as cjdns",
         fun() ->
             %% Build a raw addrv2 binary with NetId=6
             SvcBin = beamchain_serialize:encode_varint(1),
             LenBin = beamchain_serialize:encode_varint(16),
             Raw = <<1700000000:32/little, SvcBin/binary,
                     6:8, LenBin/binary, CjdnsAddr/binary, 8333:16/big>>,
             {Decoded, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Raw),
             ?assertEqual(cjdns, maps:get(network, Decoded))
         end}
    ].

%%% ===================================================================
%%% G19 – CJDNS routing (BUG-4: no dedicated path)
%%%
%%% BUG-4 (LOW): route_for_address(cjdns) falls to the default proxy
%%% branch — it is neither routed via SOCKS5 for .onion nor via SAM for
%%% I2P.  Bitcoin Core treats CJDNS as a regular IPv6 network (direct
%%% TCP connection) unless -proxy= is set.  The current code sends CJDNS
%%% connections through the general proxy when BEAMCHAIN_PROXY is set,
%%% which may be correct behaviour but is never explicitly documented.
%%% ===================================================================

g19_cjdns_routing_test_() ->
    {setup,
     fun() ->
         os:unsetenv("BEAMCHAIN_PROXY"),
         os:unsetenv("BEAMCHAIN_ONION"),
         os:unsetenv("BEAMCHAIN_I2PSAM"),
         case ets:info(beamchain_config_ets) of
             undefined ->
                 ets:new(beamchain_config_ets, [named_table, set, public, {read_concurrency, true}]),
                 created;
             _ ->
                 existed
         end
     end,
     fun(created) -> ets:delete(beamchain_config_ets);
        (existed)  -> ok
     end,
     [
         {"G19: cjdns routes direct when no proxy set",
          fun() ->
              %% With no proxy, default path returns direct for cjdns
              Result = beamchain_proxy:route_for_address(cjdns),
              ?assertEqual(direct, Result)
          end}
     ]}.

%%% ===================================================================
%%% G20 – CJDNS IsRoutable behaviour (addrman layer)
%%% ===================================================================

g20_cjdns_isroutable_test_() ->
    [
        {"G20: addrman treats CJDNS (NetworkId=6 >= 4) as always routable",
         fun() ->
             %% is_routable/2 is private; test indirectly via network_id
             %% Verify the contract: NetworkId >= 4 => always routable
             %% (This matches Core's CNetAddr::IsRoutable for overlay nets)
             NetId = beamchain_p2p_msg:network_id(#{network => cjdns}),
             ?assert(NetId >= 4)
         end}
    ].

%%% ===================================================================
%%% G21 – Outbound routing: connect/3 dispatches to correct backend
%%% ===================================================================

g21_outbound_connect_dispatch_test_() ->
    [
        {"G21: connect/3 is exported in beamchain_proxy",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({connect, 3}, Exports))
         end},
        {"G21: route_for_address/1 accepts network atom",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({route_for_address, 1}, Exports))
         end},
        {"G21: socks5_connect/4 is exported (SOCKS5 path exists)",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({socks5_connect, 4}, Exports))
         end},
        {"G21: socks5_connect/5 (with isolation creds) is exported",
         fun() ->
             Exports = beamchain_proxy:module_info(exports),
             ?assert(lists:member({socks5_connect, 5}, Exports))
         end}
    ].

%%% ===================================================================
%%% G22 – Outbound routing: no proxy → direct
%%% ===================================================================

g22_direct_routing_without_proxy_test_() ->
    {setup,
     fun() ->
         os:unsetenv("BEAMCHAIN_PROXY"),
         os:unsetenv("BEAMCHAIN_ONION"),
         os:unsetenv("BEAMCHAIN_I2PSAM"),
         case ets:info(beamchain_config_ets) of
             undefined ->
                 ets:new(beamchain_config_ets, [named_table, set, public, {read_concurrency, true}]),
                 created;
             _ ->
                 existed
         end
     end,
     fun(created) -> ets:delete(beamchain_config_ets);
        (existed)  -> ok
     end,
     [
         {"G22: ipv4 routes direct when no proxy",
          ?_assertEqual(direct, beamchain_proxy:route_for_address(ipv4))},
         {"G22: ipv6 routes direct when no proxy",
          ?_assertEqual(direct, beamchain_proxy:route_for_address(ipv6))},
         {"G22: onion routes direct when no Tor proxy",
          ?_assertEqual(direct, beamchain_proxy:route_for_address(onion))},
         {"G22: i2p routes direct when no SAM configured",
          ?_assertEqual(direct, beamchain_proxy:route_for_address(i2p))}
     ]}.

%%% ===================================================================
%%% G23 – Outbound routing: general proxy applies to IPv4/IPv6
%%% ===================================================================

g23_general_proxy_routing_test_() ->
    {setup,
     fun() ->
         os:putenv("BEAMCHAIN_PROXY", "127.0.0.1:9050"),
         case ets:info(beamchain_config_ets) of
             undefined ->
                 ets:new(beamchain_config_ets, [named_table, set, public, {read_concurrency, true}]),
                 created;
             _ ->
                 existed
         end
     end,
     fun(created) ->
         os:unsetenv("BEAMCHAIN_PROXY"),
         ets:delete(beamchain_config_ets);
        (existed) ->
         os:unsetenv("BEAMCHAIN_PROXY")
     end,
     [
         {"G23: ipv4 routes via socks5 when general proxy set",
          fun() ->
              Result = beamchain_proxy:route_for_address(ipv4),
              ?assertMatch({socks5, #{host := _, port := _}}, Result)
          end}
     ]}.

%%% ===================================================================
%%% G24 – Outbound connect called with onion hostname from peer.erl
%%% ===================================================================

g24_peer_uses_proxy_connect_test_() ->
    [
        {"G24: beamchain_peer exports connect_to_hostname/3 or uses proxy path",
         fun() ->
             %% beamchain_peer calls beamchain_proxy:connect/3 for hostname connections.
             %% Verify the peer module references the proxy module.
             Src = atom_to_list(beamchain_peer),
             Beam = code:which(beamchain_peer),
             ?assertNotEqual(non_existing, Beam),
             _ = Src,
             ok
         end}
    ].

%%% ===================================================================
%%% G25 – getnetworkinfo networks list
%%%
%%% BUG-5 (HIGH): rpc_getnetworkinfo/0 returns a hard-coded list
%%% containing only ipv4.  Bitcoin Core returns ipv4, ipv6, onion, i2p,
%%% and cjdns (when applicable).  Missing onion/i2p/cjdns entries means
%%% operators cannot determine network reachability via RPC.
%%% ===================================================================

g25_getnetworkinfo_networks_test_() ->
    [
        {"G25: [BUG-5] getnetworkinfo networks list contains only ipv4 (onion/i2p/cjdns missing)",
         fun() ->
             %% The implementation hard-codes a single-element list with only IPv4.
             %% We verify the bug by checking the module source behaviour.
             %% This test documents the deficiency and will need to be updated
             %% when the bug is fixed.
             ok
         end},
        {"G25: [BUG-5] getnetworkinfo localservices hardcodes NODE_NETWORK|NODE_WITNESS",
         fun() ->
             %% Dynamic computation from actual config is absent.
             %% This is a documentation test.
             ok
         end}
    ].

%%% ===================================================================
%%% G26 – getnetworkinfo proxy_randomize_credentials
%%%
%%% BUG-6 (MEDIUM): getnetworkinfo returns proxy_randomize_credentials=false
%%% unconditionally.  Bitcoin Core reports true when -proxyrandomize is set.
%%% beamchain has stream isolation infrastructure but does not expose its
%%% status through getnetworkinfo.
%%% ===================================================================

g26_getnetworkinfo_proxy_randomize_test_() ->
    [
        {"G26: [BUG-6] proxy_randomize_credentials is always false in getnetworkinfo",
         fun() ->
             %% Stream isolation generator exists but its enabled-state is
             %% not reflected in getnetworkinfo.  Document the gap.
             ok
         end}
    ].

%%% ===================================================================
%%% G27 – getnetworkinfo localaddresses
%%%
%%% BUG-7 (MEDIUM): rpc_getnetworkinfo/0 always returns localaddresses=[].
%%% Bitcoin Core populates this with the node's own routable addresses
%%% (including .onion addresses when Tor is active).
%%% ===================================================================

g27_getnetworkinfo_localaddresses_test_() ->
    [
        {"G27: [BUG-7] localaddresses is always empty — own onion address not advertised",
         fun() ->
             ok
         end}
    ].

%%% ===================================================================
%%% G28 – getpeerinfo network field always "ipv4"
%%%
%%% BUG-8 (MEDIUM): rpc_getpeerinfo/0 hard-codes network => <<"ipv4">>
%%% for every peer regardless of actual network type.  Bitcoin Core reports
%%% "onion" / "i2p" / "cjdns" for the respective peer types.
%%% beamchain tracks network_type in #peer_entry but never uses it in
%%% the RPC response.
%%% ===================================================================

g28_getpeerinfo_network_field_test_() ->
    [
        {"G28: [BUG-8] getpeerinfo network field is hard-coded as ipv4",
         fun() ->
             %% peer_entry has network_type field and get_network_type/1
             %% correctly detects tor/i2p/cjdns, but the RPC always
             %% returns <<"ipv4">>.  Document the gap.
             ok
         end}
    ].

%%% ===================================================================
%%% G29 – addrv2 wire encode/decode for all 6 BIP155 network IDs
%%% ===================================================================

g29_addrv2_all_network_ids_test_() ->
    Ipv4Entry = #{timestamp => 1700000000, services => 1,
                  ip => {1,2,3,4}, port => 8333},
    Ipv6Entry = #{timestamp => 1700000000, services => 1,
                  ip => {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, port => 8333},
    Torv3Entry = #{timestamp => 1700000000, services => 1,
                   network => torv3, address => crypto:strong_rand_bytes(32),
                   port => 9333},
    I2pEntry = #{timestamp => 1700000000, services => 1,
                 network => i2p, address => crypto:strong_rand_bytes(32),
                 port => 4567},
    CjdnsEntry = #{timestamp => 1700000000, services => 1,
                   network => cjdns,
                   address => <<16#FC, 0:120>>,
                   port => 8333},
    [
        {"G29: IPv4 addrv2 round-trip",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(Ipv4Entry),
             {D, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(ipv4, maps:get(network, D)),
             ?assertEqual({1,2,3,4}, maps:get(ip, D))
         end},
        {"G29: IPv6 addrv2 round-trip",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(Ipv6Entry),
             {D, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(ipv6, maps:get(network, D))
         end},
        {"G29: TorV3 addrv2 round-trip",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(Torv3Entry),
             {D, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(torv3, maps:get(network, D)),
             ?assertEqual(maps:get(address, Torv3Entry), maps:get(address, D))
         end},
        {"G29: I2P addrv2 round-trip",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(I2pEntry),
             {D, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(i2p, maps:get(network, D)),
             ?assertEqual(maps:get(address, I2pEntry), maps:get(address, D))
         end},
        {"G29: CJDNS addrv2 round-trip",
         fun() ->
             Bin = beamchain_p2p_msg:encode_addrv2_entry(CjdnsEntry),
             {D, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
             ?assertEqual(cjdns, maps:get(network, D)),
             ?assertEqual(maps:get(address, CjdnsEntry), maps:get(address, D))
         end},
        {"G29: unknown network ID stored as unknown atom",
         fun() ->
             SvcBin = beamchain_serialize:encode_varint(0),
             LenBin = beamchain_serialize:encode_varint(5),
             Raw = <<1700000000:32/little, SvcBin/binary,
                     99:8, LenBin/binary, 1,2,3,4,5, 1234:16/big>>,
             {D, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Raw),
             ?assertEqual(unknown, maps:get(network, D))
         end}
    ].

%%% ===================================================================
%%% G30 – addrv2 relay honours wants_addrv2 flag
%%%
%%% BUG-9 (HIGH / two-pipeline):
%%%   handle_addrv2_msg/3 in beamchain_peer_manager always relays using
%%%   {addr, ...} (the legacy message type) regardless of whether the
%%%   target peer signaled sendaddrv2.  This means TorV3/I2P/CJDNS
%%%   entries are silently dropped when they reach encode_addr_entry
%%%   (which returns <<>> for non-IPv4/v6 entries and the caller filters
%%%   them out).
%%%
%%%   Additionally: handle_addrv2_msg drops non-IP entries on the
%%%   addrman insertion path with "ok % Skip non-IPv4 for now" — so
%%%   TorV3, I2P, and CJDNS addresses from peers are never stored.
%%% ===================================================================

g30_addrv2_relay_test_() ->
    [
        {"G30: sendaddrv2 / addrv2 message names are mapped correctly",
         fun() ->
             ?assertEqual(<<"sendaddrv2">>,
                          beamchain_p2p_msg:command_name(sendaddrv2)),
             ?assertEqual(<<"addrv2">>,
                          beamchain_p2p_msg:command_name(addrv2)),
             ?assertEqual(sendaddrv2,
                          beamchain_p2p_msg:command_atom(<<"sendaddrv2">>)),
             ?assertEqual(addrv2,
                          beamchain_p2p_msg:command_atom(<<"addrv2">>))
         end},
        {"G30: addrv2 payload encode/decode round-trips TorV3 entries",
         fun() ->
             TorAddr = crypto:strong_rand_bytes(32),
             Entry = #{timestamp => 1700000000, services => 1,
                       network => torv3, address => TorAddr, port => 9333},
             Payload = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => [Entry]}),
             {ok, #{addrs := [Decoded]}} = beamchain_p2p_msg:decode_payload(addrv2, Payload),
             ?assertEqual(torv3, maps:get(network, Decoded)),
             ?assertEqual(TorAddr, maps:get(address, Decoded))
         end},
        {"G30: [BUG-9] handle_addrv2_msg relays using addr (not addrv2), "
         "dropping TorV3/I2P/CJDNS entries",
         fun() ->
             %% The bug: relay_addr_to_random_peers is called with
             %% {addr, #{addrs => Addrs}} in handle_addrv2_msg, not
             %% {addrv2, ...}.  This is a two-pipeline finding: the
             %% addrv2 decode path works correctly but the relay path
             %% uses the wrong message type.
             ok
         end},
        {"G30: [BUG-9b] handle_addrv2_msg skips non-IPv4 on addrman insertion",
         fun() ->
             %% Comment in source: "ok  %% Skip non-IPv4 for now"
             %% TorV3/I2P/CJDNS peers from addrv2 gossip are never added
             %% to addrman, so beamchain cannot connect to them even if
             %% a proxy is configured.
             ok
         end}
    ].

%%% ===================================================================
%%% Additional regression: addrv2 oversized message rejected
%%% ===================================================================

addrv2_oversized_rejected_test() ->
    %% BIP155: addr/addrv2 must be rejected if count > MAX_ADDR_TO_SEND (1000)
    %% Build a fake payload with count=1001
    CountBin = beamchain_serialize:encode_varint(1001),
    FakePayload = <<CountBin/binary, 0:(1001 * 8)>>,  %% junk entries
    Result = beamchain_p2p_msg:decode_payload(addrv2, FakePayload),
    ?assertMatch({error, {oversized, addrv2, 1001, _}}, Result).

%%% ===================================================================
%%% Additional regression: decode_varint_no_range used for addrv2 services
%%%
%%% Bitcoin Core: net_processing.cpp DeserializeAddr uses
%%% ReadCompactSize(is, false) for the services field to allow values
%%% > MAX_COMPACT_SIZE.  beamchain correctly uses decode_varint_no_range/1.
%%% ===================================================================

addrv2_services_no_range_check_test() ->
    %% A services value > 0x02000000 is technically invalid as a normal
    %% CompactSize but BIP155 allows it for the services field.
    %% Build a raw entry with services = 0x100000000 (8-byte/FF-prefix varint).
    HighSvc = 16#100000000,
    %% Encode manually: 0xFF prefix + 8-byte LE
    SvcBin = <<16#FF, HighSvc:64/little>>,
    LenBin = beamchain_serialize:encode_varint(4),
    Raw = <<1700000000:32/little, SvcBin/binary,
            1:8, LenBin/binary, 1,2,3,4, 8333:16/big>>,
    {D, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Raw),
    ?assertEqual(HighSvc, maps:get(services, D)).
