-module(beamchain_p2p_msg_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Message framing tests
%%% ===================================================================

frame_roundtrip_test() ->
    Magic = ?MAINNET_MAGIC,
    Payload = <<"hello">>,
    Msg = beamchain_p2p_msg:encode_msg(Magic, ping, Payload),
    %% 24-byte header + payload
    ?assertEqual(24 + 5, byte_size(Msg)),
    %% verify magic is at the front
    <<Magic:4/binary, _/binary>> = Msg,
    {ok, ping, Payload, <<>>} = beamchain_p2p_msg:decode_msg(Msg).

frame_with_trailing_data_test() ->
    Magic = ?TESTNET4_MAGIC,
    Payload = <<42:64/little>>,
    Msg = beamchain_p2p_msg:encode_msg(Magic, pong, Payload),
    Trailing = <<"extra_stuff">>,
    {ok, pong, Payload, Trailing} =
        beamchain_p2p_msg:decode_msg(<<Msg/binary, Trailing/binary>>).

frame_incomplete_header_test() ->
    ?assertEqual(incomplete, beamchain_p2p_msg:decode_msg(<<1,2,3>>)).

frame_incomplete_payload_test() ->
    Magic = ?MAINNET_MAGIC,
    Payload = <<"test data here">>,
    Msg = beamchain_p2p_msg:encode_msg(Magic, ping, Payload),
    %% chop off the last byte
    Chopped = binary:part(Msg, 0, byte_size(Msg) - 1),
    ?assertEqual(incomplete, beamchain_p2p_msg:decode_msg(Chopped)).

frame_bad_checksum_test() ->
    Magic = ?MAINNET_MAGIC,
    Payload = <<"test">>,
    Msg = beamchain_p2p_msg:encode_msg(Magic, ping, Payload),
    %% corrupt the checksum (bytes 20-23)
    <<Pre:20/binary, _Check:4/binary, Post/binary>> = Msg,
    Corrupted = <<Pre/binary, 0,0,0,0, Post/binary>>,
    ?assertEqual({error, bad_checksum}, beamchain_p2p_msg:decode_msg(Corrupted)).

%%% ===================================================================
%%% Command name mapping tests
%%% ===================================================================

command_roundtrip_test_() ->
    Commands = [version, verack, ping, pong, addr, getaddr, inv, getdata,
                notfound, getheaders, headers, getblocks, block, tx,
                mempool, sendheaders, feefilter, sendcmpct, cmpctblock,
                getblocktxn, blocktxn, wtxidrelay, sendaddrv2, addrv2],
    [?_assertEqual(Cmd, beamchain_p2p_msg:command_atom(
                            beamchain_p2p_msg:command_name(Cmd)))
     || Cmd <- Commands].

unknown_command_test() ->
    ?assertEqual(foobar, beamchain_p2p_msg:command_atom(<<"foobar">>)).

%%% ===================================================================
%%% Version message tests
%%% ===================================================================

version_roundtrip_test() ->
    Msg = #{
        version => ?PROTOCOL_VERSION,
        services => ?NODE_NETWORK bor ?NODE_WITNESS,
        timestamp => 1702000000,
        addr_recv => #{services => ?NODE_NETWORK, ip => {127,0,0,1}, port => 8333},
        addr_from => #{services => ?NODE_NETWORK bor ?NODE_WITNESS,
                       ip => {192,168,1,100}, port => 8333},
        nonce => 16#DEADBEEFCAFEBABE,
        user_agent => <<"/beamchain:0.1.0/">>,
        start_height => 800000,
        relay => true
    },
    Bin = beamchain_p2p_msg:encode_payload(version, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(version, Bin),
    ?assertEqual(maps:get(version, Msg), maps:get(version, Decoded)),
    ?assertEqual(maps:get(services, Msg), maps:get(services, Decoded)),
    ?assertEqual(maps:get(timestamp, Msg), maps:get(timestamp, Decoded)),
    ?assertEqual(maps:get(nonce, Msg), maps:get(nonce, Decoded)),
    ?assertEqual(maps:get(user_agent, Msg), maps:get(user_agent, Decoded)),
    ?assertEqual(maps:get(start_height, Msg), maps:get(start_height, Decoded)),
    ?assertEqual(maps:get(relay, Msg), maps:get(relay, Decoded)),
    %% check addresses
    ?assertEqual(maps:get(ip, maps:get(addr_recv, Msg)),
                 maps:get(ip, maps:get(addr_recv, Decoded))),
    ?assertEqual(maps:get(port, maps:get(addr_recv, Msg)),
                 maps:get(port, maps:get(addr_recv, Decoded))).

version_relay_false_test() ->
    Msg = #{
        version => 70015,
        services => 0,
        timestamp => 1700000000,
        addr_recv => #{services => 0, ip => {10,0,0,1}, port => 18333},
        addr_from => #{services => 0, ip => {10,0,0,2}, port => 18333},
        nonce => 12345,
        user_agent => <<>>,
        start_height => 0,
        relay => false
    },
    Bin = beamchain_p2p_msg:encode_payload(version, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(version, Bin),
    ?assertEqual(false, maps:get(relay, Decoded)).

version_full_frame_test() ->
    Msg = #{
        version => ?PROTOCOL_VERSION,
        services => ?NODE_NETWORK,
        timestamp => 1702000000,
        addr_recv => #{services => 0, ip => {127,0,0,1}, port => 8333},
        addr_from => #{services => 0, ip => {0,0,0,0}, port => 0},
        nonce => 99,
        user_agent => <<"/test/">>,
        start_height => 100,
        relay => true
    },
    Payload = beamchain_p2p_msg:encode_payload(version, Msg),
    Framed = beamchain_p2p_msg:encode_msg(?MAINNET_MAGIC, version, Payload),
    {ok, version, Payload, <<>>} = beamchain_p2p_msg:decode_msg(Framed),
    {ok, _Decoded} = beamchain_p2p_msg:decode_payload(version, Payload).

%%% ===================================================================
%%% Simple message tests (verack, ping, pong)
%%% ===================================================================

verack_test() ->
    Bin = beamchain_p2p_msg:encode_payload(verack, #{}),
    ?assertEqual(<<>>, Bin),
    ?assertEqual({ok, #{}}, beamchain_p2p_msg:decode_payload(verack, Bin)).

ping_roundtrip_test() ->
    Nonce = 16#0102030405060708,
    Bin = beamchain_p2p_msg:encode_payload(ping, #{nonce => Nonce}),
    ?assertEqual(8, byte_size(Bin)),
    {ok, #{nonce := Decoded}} = beamchain_p2p_msg:decode_payload(ping, Bin),
    ?assertEqual(Nonce, Decoded).

pong_roundtrip_test() ->
    Nonce = 16#FFFFFFFFFFFFFFFF,
    Bin = beamchain_p2p_msg:encode_payload(pong, #{nonce => Nonce}),
    {ok, #{nonce := Decoded}} = beamchain_p2p_msg:decode_payload(pong, Bin),
    ?assertEqual(Nonce, Decoded).

%%% ===================================================================
%%% Addr message tests
%%% ===================================================================

addr_roundtrip_test() ->
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_NETWORK,
          ip => {93,184,216,34}, port => 8333},
        #{timestamp => 1702000100, services => ?NODE_WITNESS,
          ip => {198,51,100,1}, port => 8333}
    ],
    Bin = beamchain_p2p_msg:encode_payload(addr, #{addrs => Addrs}),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addr, Bin),
    ?assertEqual(2, length(Decoded)),
    ?assertEqual(maps:get(ip, hd(Addrs)), maps:get(ip, hd(Decoded))),
    ?assertEqual(maps:get(timestamp, hd(Addrs)), maps:get(timestamp, hd(Decoded))).

addr_empty_test() ->
    Bin = beamchain_p2p_msg:encode_payload(addr, #{addrs => []}),
    {ok, #{addrs := []}} = beamchain_p2p_msg:decode_payload(addr, Bin).

getaddr_test() ->
    Bin = beamchain_p2p_msg:encode_payload(getaddr, #{}),
    ?assertEqual(<<>>, Bin),
    ?assertEqual({ok, #{}}, beamchain_p2p_msg:decode_payload(getaddr, Bin)).

%%% ===================================================================
%%% Net address tests
%%% ===================================================================

net_addr_ipv4_roundtrip_test() ->
    Addr = #{services => ?NODE_NETWORK bor ?NODE_WITNESS,
             ip => {192,168,1,1}, port => 8333},
    Bin = beamchain_p2p_msg:encode_net_addr(Addr),
    ?assertEqual(26, byte_size(Bin)),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_net_addr(Bin),
    ?assertEqual({192,168,1,1}, maps:get(ip, Decoded)),
    ?assertEqual(8333, maps:get(port, Decoded)),
    ?assertEqual(?NODE_NETWORK bor ?NODE_WITNESS, maps:get(services, Decoded)).

net_addr_ipv6_roundtrip_test() ->
    %% Real IPv6 must round-trip to an 8-tuple (matches inet conventions
    %% and lets netgroup/1 bucket by /48 prefix instead of collapsing
    %% every IPv6 peer into a single binary group).
    IPv6Bin = <<16#20,16#01,16#0d,16#b8, 0,0,0,0, 0,0,0,0, 0,0,0,1>>,
    IPv6Tuple = {16#2001, 16#0db8, 0, 0, 0, 0, 0, 1},
    Addr = #{services => 0, ip => IPv6Bin, port => 18333},
    Bin = beamchain_p2p_msg:encode_net_addr(Addr),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_net_addr(Bin),
    ?assertEqual(IPv6Tuple, maps:get(ip, Decoded)),
    ?assertEqual(18333, maps:get(port, Decoded)).

%% Regression: encode_ip used to crash on 8-tuple IPv6 peers
%% (function_clause in addr-gossip -> peer session death). Wire form
%% is always 16 bytes; IPv4 uses the IPv4-mapped IPv6 prefix.
%% Exercised through encode_net_addr, which is the only caller on the hot
%% addr-gossip path and is exported.
net_addr_ipv4_wire_is_mapped_ipv6_test() ->
    Addr = #{services => 0, ip => {192, 168, 1, 1}, port => 8333},
    Bin = beamchain_p2p_msg:encode_net_addr(Addr),
    %% 8 svc + 16 ip + 2 port = 26
    ?assertEqual(26, byte_size(Bin)),
    <<_Svc:8/binary, IPBin:16/binary, _Port:16>> = Bin,
    ?assertMatch(<<0:80, 16#FFFF:16, 192, 168, 1, 1>>, IPBin).

net_addr_ipv6_tuple_regression_test() ->
    %% Live-captured crash address: 2001:4c3c:8102:2d00::2
    IP = {8193, 19516, 33026, 11520, 0, 0, 0, 2},
    Addr = #{services => 0, ip => IP, port => 8333},
    NetBin = beamchain_p2p_msg:encode_net_addr(Addr),
    ?assertEqual(26, byte_size(NetBin)),
    <<_Svc:8/binary, IPBin:16/binary, _Port:16>> = NetBin,
    ?assertEqual(<<8193:16, 19516:16, 33026:16, 11520:16,
                   0:16, 0:16, 0:16, 2:16>>, IPBin),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_net_addr(NetBin),
    ?assertEqual(IP, maps:get(ip, Decoded)).

%%% ===================================================================
%%% Inventory message tests
%%% ===================================================================

inv_roundtrip_test() ->
    Hash1 = crypto:strong_rand_bytes(32),
    Hash2 = crypto:strong_rand_bytes(32),
    Items = [
        #{type => ?MSG_TX, hash => Hash1},
        #{type => ?MSG_BLOCK, hash => Hash2}
    ],
    Bin = beamchain_p2p_msg:encode_payload(inv, #{items => Items}),
    {ok, #{items := Decoded}} = beamchain_p2p_msg:decode_payload(inv, Bin),
    ?assertEqual(2, length(Decoded)),
    ?assertEqual(?MSG_TX, maps:get(type, lists:nth(1, Decoded))),
    ?assertEqual(Hash1, maps:get(hash, lists:nth(1, Decoded))),
    ?assertEqual(?MSG_BLOCK, maps:get(type, lists:nth(2, Decoded))),
    ?assertEqual(Hash2, maps:get(hash, lists:nth(2, Decoded))).

inv_witness_types_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Items = [
        #{type => ?MSG_WITNESS_TX, hash => Hash},
        #{type => ?MSG_WITNESS_BLOCK, hash => Hash}
    ],
    Bin = beamchain_p2p_msg:encode_payload(inv, #{items => Items}),
    {ok, #{items := Decoded}} = beamchain_p2p_msg:decode_payload(inv, Bin),
    ?assertEqual(?MSG_WITNESS_TX, maps:get(type, lists:nth(1, Decoded))),
    ?assertEqual(?MSG_WITNESS_BLOCK, maps:get(type, lists:nth(2, Decoded))).

inv_empty_test() ->
    Bin = beamchain_p2p_msg:encode_payload(inv, #{items => []}),
    {ok, #{items := []}} = beamchain_p2p_msg:decode_payload(inv, Bin).

getdata_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Items = [#{type => ?MSG_BLOCK, hash => Hash}],
    Bin = beamchain_p2p_msg:encode_payload(getdata, #{items => Items}),
    {ok, #{items := Decoded}} = beamchain_p2p_msg:decode_payload(getdata, Bin),
    ?assertEqual(Items, Decoded).

notfound_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Items = [#{type => ?MSG_TX, hash => Hash}],
    Bin = beamchain_p2p_msg:encode_payload(notfound, #{items => Items}),
    {ok, #{items := Decoded}} = beamchain_p2p_msg:decode_payload(notfound, Bin),
    ?assertEqual(Items, Decoded).

%%% ===================================================================
%%% Getheaders / headers tests
%%% ===================================================================

getheaders_roundtrip_test() ->
    Loc1 = crypto:strong_rand_bytes(32),
    Loc2 = crypto:strong_rand_bytes(32),
    Stop = <<0:256>>,
    Msg = #{version => ?PROTOCOL_VERSION,
            locators => [Loc1, Loc2],
            stop_hash => Stop},
    Bin = beamchain_p2p_msg:encode_payload(getheaders, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(getheaders, Bin),
    ?assertEqual(?PROTOCOL_VERSION, maps:get(version, Decoded)),
    ?assertEqual([Loc1, Loc2], maps:get(locators, Decoded)),
    ?assertEqual(Stop, maps:get(stop_hash, Decoded)).

getheaders_single_locator_test() ->
    Loc = crypto:strong_rand_bytes(32),
    Stop = crypto:strong_rand_bytes(32),
    Msg = #{version => 70015, locators => [Loc], stop_hash => Stop},
    Bin = beamchain_p2p_msg:encode_payload(getheaders, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(getheaders, Bin),
    ?assertEqual([Loc], maps:get(locators, Decoded)),
    ?assertEqual(Stop, maps:get(stop_hash, Decoded)).

headers_roundtrip_test() ->
    H1 = #block_header{version = 1, prev_hash = <<0:256>>,
                       merkle_root = crypto:strong_rand_bytes(32),
                       timestamp = 1231006505, bits = 16#1d00ffff,
                       nonce = 2083236893},
    H2 = #block_header{version = 2, prev_hash = crypto:strong_rand_bytes(32),
                       merkle_root = crypto:strong_rand_bytes(32),
                       timestamp = 1702000000, bits = 16#17034219,
                       nonce = 42},
    Bin = beamchain_p2p_msg:encode_payload(headers, #{headers => [H1, H2]}),
    {ok, #{headers := Decoded}} = beamchain_p2p_msg:decode_payload(headers, Bin),
    ?assertEqual(2, length(Decoded)),
    ?assertEqual(H1, lists:nth(1, Decoded)),
    ?assertEqual(H2, lists:nth(2, Decoded)).

headers_empty_test() ->
    Bin = beamchain_p2p_msg:encode_payload(headers, #{headers => []}),
    {ok, #{headers := []}} = beamchain_p2p_msg:decode_payload(headers, Bin).

%%% ===================================================================
%%% Getblocks test
%%% ===================================================================

getblocks_roundtrip_test() ->
    Loc = crypto:strong_rand_bytes(32),
    Stop = <<0:256>>,
    Msg = #{version => ?PROTOCOL_VERSION, locators => [Loc], stop_hash => Stop},
    Bin = beamchain_p2p_msg:encode_payload(getblocks, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(getblocks, Bin),
    ?assertEqual(?PROTOCOL_VERSION, maps:get(version, Decoded)),
    ?assertEqual([Loc], maps:get(locators, Decoded)),
    ?assertEqual(Stop, maps:get(stop_hash, Decoded)).

%%% ===================================================================
%%% Block / tx message tests
%%% ===================================================================

block_roundtrip_test() ->
    %% build a minimal block with a coinbase tx
    CoinbaseTx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1, 0, 0, 0>>,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{
            value = 5000000000,
            script_pubkey = <<16#76, 16#a9, 16#14,
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              16#88, 16#ac>>
        }],
        locktime = 0
    },
    Merkle = beamchain_serialize:tx_hash(CoinbaseTx),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = Merkle,
        timestamp = 1702000000,
        bits = 16#207fffff,
        nonce = 0
    },
    Block = #block{header = Header, transactions = [CoinbaseTx]},
    Bin = beamchain_p2p_msg:encode_payload(block, Block),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(block, Bin),
    ?assertEqual(Header, Decoded#block.header),
    ?assertEqual(1, length(Decoded#block.transactions)).

tx_roundtrip_test() ->
    Tx = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = crypto:strong_rand_bytes(32), index = 0},
            script_sig = <<>>,
            sequence = 16#fffffffe,
            witness = [<<16#30, 16#44>>, <<16#02, 16#20>>]
        }],
        outputs = [#tx_out{value = 50000, script_pubkey = <<0, 20, 0:160>>}],
        locktime = 800000
    },
    Bin = beamchain_p2p_msg:encode_payload(tx, Tx),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(tx, Bin),
    ?assertEqual(2, Decoded#transaction.version),
    ?assertEqual(800000, Decoded#transaction.locktime),
    ?assertEqual(1, length(Decoded#transaction.inputs)),
    ?assertEqual(1, length(Decoded#transaction.outputs)).

%%% ===================================================================
%%% Empty message tests
%%% ===================================================================

sendheaders_test() ->
    Bin = beamchain_p2p_msg:encode_payload(sendheaders, #{}),
    ?assertEqual(<<>>, Bin),
    ?assertEqual({ok, #{}}, beamchain_p2p_msg:decode_payload(sendheaders, Bin)).

mempool_test() ->
    Bin = beamchain_p2p_msg:encode_payload(mempool, #{}),
    ?assertEqual(<<>>, Bin),
    ?assertEqual({ok, #{}}, beamchain_p2p_msg:decode_payload(mempool, Bin)).

wtxidrelay_test() ->
    Bin = beamchain_p2p_msg:encode_payload(wtxidrelay, #{}),
    ?assertEqual(<<>>, Bin),
    ?assertEqual({ok, #{}}, beamchain_p2p_msg:decode_payload(wtxidrelay, Bin)).

sendaddrv2_test() ->
    Bin = beamchain_p2p_msg:encode_payload(sendaddrv2, #{}),
    ?assertEqual(<<>>, Bin),
    ?assertEqual({ok, #{}}, beamchain_p2p_msg:decode_payload(sendaddrv2, Bin)).

%%% ===================================================================
%%% Policy message tests
%%% ===================================================================

feefilter_roundtrip_test() ->
    Bin = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => 1000}),
    ?assertEqual(8, byte_size(Bin)),
    {ok, #{feerate := 1000}} = beamchain_p2p_msg:decode_payload(feefilter, Bin).

feefilter_zero_test() ->
    Bin = beamchain_p2p_msg:encode_payload(feefilter, #{feerate => 0}),
    {ok, #{feerate := 0}} = beamchain_p2p_msg:decode_payload(feefilter, Bin).

sendcmpct_roundtrip_test() ->
    Bin = beamchain_p2p_msg:encode_payload(sendcmpct,
        #{announce => true, version => 2}),
    ?assertEqual(9, byte_size(Bin)),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(sendcmpct, Bin),
    ?assertEqual(true, maps:get(announce, Decoded)),
    ?assertEqual(2, maps:get(version, Decoded)).

sendcmpct_no_announce_test() ->
    Bin = beamchain_p2p_msg:encode_payload(sendcmpct,
        #{announce => false, version => 1}),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(sendcmpct, Bin),
    ?assertEqual(false, maps:get(announce, Decoded)),
    ?assertEqual(1, maps:get(version, Decoded)).

%%% ===================================================================
%%% Compact block message tests
%%% ===================================================================

cmpctblock_roundtrip_test() ->
    Header = #block_header{
        version = 4, prev_hash = crypto:strong_rand_bytes(32),
        merkle_root = crypto:strong_rand_bytes(32),
        timestamp = 1702000000, bits = 16#17034219, nonce = 12345
    },
    SID1 = crypto:strong_rand_bytes(6),
    SID2 = crypto:strong_rand_bytes(6),
    PreTx = #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = <<4, 1>>,
            sequence = 16#ffffffff, witness = []
        }],
        outputs = [#tx_out{value = 5000000000,
                           script_pubkey = <<16#6a, 4, "test">>}],
        locktime = 0
    },
    Msg = #{header => Header, nonce => 16#CAFE,
            short_ids => [SID1, SID2],
            prefilled_txns => [#{index => 0, tx => PreTx}]},
    Bin = beamchain_p2p_msg:encode_payload(cmpctblock, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(cmpctblock, Bin),
    ?assertEqual(Header, maps:get(header, Decoded)),
    ?assertEqual(16#CAFE, maps:get(nonce, Decoded)),
    ?assertEqual([SID1, SID2], maps:get(short_ids, Decoded)),
    ?assertEqual(1, length(maps:get(prefilled_txns, Decoded))),
    #{index := 0} = hd(maps:get(prefilled_txns, Decoded)).

getblocktxn_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Indexes = [0, 3, 7, 15],
    Msg = #{block_hash => Hash, indexes => Indexes},
    Bin = beamchain_p2p_msg:encode_payload(getblocktxn, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(getblocktxn, Bin),
    ?assertEqual(Hash, maps:get(block_hash, Decoded)),
    ?assertEqual(Indexes, maps:get(indexes, Decoded)).

getblocktxn_consecutive_indexes_test() ->
    Hash = crypto:strong_rand_bytes(32),
    %% consecutive indexes: differential encoding should give [0,0,0,0]
    Indexes = [0, 1, 2, 3],
    Msg = #{block_hash => Hash, indexes => Indexes},
    Bin = beamchain_p2p_msg:encode_payload(getblocktxn, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(getblocktxn, Bin),
    ?assertEqual(Indexes, maps:get(indexes, Decoded)).

blocktxn_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Tx1 = #transaction{
        version = 2,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = crypto:strong_rand_bytes(32), index = 0},
            script_sig = <<>>,
            sequence = 16#ffffffff, witness = []
        }],
        outputs = [#tx_out{value = 100000, script_pubkey = <<16#6a>>}],
        locktime = 0
    },
    Msg = #{block_hash => Hash, transactions => [Tx1]},
    Bin = beamchain_p2p_msg:encode_payload(blocktxn, Msg),
    {ok, Decoded} = beamchain_p2p_msg:decode_payload(blocktxn, Bin),
    ?assertEqual(Hash, maps:get(block_hash, Decoded)),
    ?assertEqual(1, length(maps:get(transactions, Decoded))).

%%% ===================================================================
%%% Inv item tests
%%% ===================================================================

inv_item_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Item = #{type => ?MSG_TX, hash => Hash},
    Bin = beamchain_p2p_msg:encode_inv_item(Item),
    ?assertEqual(36, byte_size(Bin)),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_inv_item(Bin),
    ?assertEqual(Item, Decoded).

%%% ===================================================================
%%% Addr entry tests
%%% ===================================================================

addr_entry_roundtrip_test() ->
    Entry = #{timestamp => 1702000000, services => ?NODE_NETWORK,
              ip => {10,0,0,1}, port => 8333},
    Bin = beamchain_p2p_msg:encode_addr_entry(Entry),
    ?assertEqual(30, byte_size(Bin)),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_addr_entry(Bin),
    ?assertEqual(Entry, Decoded).

%% Regression: IPv6 8-tuples from the 2026-04-13 20:27-20:53 crash log must
%% round-trip through the exported encoder path without the function_clause
%% that took down the peer supervisor before 2e83163 shipped.
net_addr_ipv6_tuple_live_crash_test() ->
    LiveCrashTuples = [
        {9733,22986,11359,61704,12467,1306,21186,2662},
        {8193,2161,607,22362,11913,51145,45865,11027},
        {9728,16448,21459,50688,58534,25844,56963,12118}
    ],
    lists:foreach(fun(IP) ->
        %% encode_net_addr exercises encode_ip via the handshake path.
        NetAddr = #{services => 0, ip => IP, port => 8333},
        NetBin = beamchain_p2p_msg:encode_net_addr(NetAddr),
        ?assertEqual(26, byte_size(NetBin)),
        {Decoded, <<>>} = beamchain_p2p_msg:decode_net_addr(NetBin),
        ?assertEqual(IP, maps:get(ip, Decoded)),
        %% Full addr entry must also encode without crashing (this is the
        %% line-483 call site from the crash log).
        Entry = #{timestamp => 1776055000, services => ?NODE_NETWORK,
                  ip => IP, port => 8333},
        AddrBin = beamchain_p2p_msg:encode_addr_entry(Entry),
        ?assertEqual(30, byte_size(AddrBin))
    end, LiveCrashTuples).

%% Regression: BIP155 network entries (torv3/i2p/cjdns) used to crash
%% encode_addr_entry/1 at line 483 with a function_clause because that
%% legacy encoder only understood ip-tuples. They now return <<>> so the
%% legacy-addr caller can filter them out; relay of non-IP networks must
%% go through the addrv2 payload (encode_addrv2_entry) instead.
encode_addr_entry_torv3_drops_test() ->
    Entry = #{port => 8333, timestamp => 1776055509,
              address => crypto:strong_rand_bytes(32),
              services => 3145, network => torv3, network_id => 4},
    ?assertEqual(<<>>, beamchain_p2p_msg:encode_addr_entry(Entry)).

encode_addr_entry_i2p_drops_test() ->
    Entry = #{port => 0, timestamp => 1776055509,
              address => crypto:strong_rand_bytes(32),
              services => 0, network => i2p, network_id => 5},
    ?assertEqual(<<>>, beamchain_p2p_msg:encode_addr_entry(Entry)).

encode_addr_entry_cjdns_drops_test() ->
    %% cjdns addresses are 16 bytes starting with 0xFC.
    Entry = #{port => 8333, timestamp => 1776055509,
              address => <<16#FC, (crypto:strong_rand_bytes(15))/binary>>,
              services => 1, network => cjdns, network_id => 6},
    ?assertEqual(<<>>, beamchain_p2p_msg:encode_addr_entry(Entry)).

encode_addr_entry_unknown_network_test() ->
    %% Any unknown network atom must not crash.
    Entry = #{port => 8333, timestamp => 1776055509,
              address => <<0:64>>,
              services => 0, network => yggdrasil, network_id => 7},
    ?assertEqual(<<>>, beamchain_p2p_msg:encode_addr_entry(Entry)).

%% BIP155-decoder-shape entries for IPv4/IPv6 (address + network) must
%% round-trip through the legacy encoder. This lets the peer-manager relay
%% IPv4/IPv6 entries it received via addrv2 back out on the legacy channel
%% without having to translate shapes.
encode_addr_entry_ipv4_bip155_shape_test() ->
    Entry = #{port => 8333, timestamp => 1776055509,
              address => <<192, 168, 1, 1>>,
              services => 1, network => ipv4, network_id => 1},
    Bin = beamchain_p2p_msg:encode_addr_entry(Entry),
    ?assertEqual(30, byte_size(Bin)),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_addr_entry(Bin),
    ?assertEqual({192, 168, 1, 1}, maps:get(ip, Decoded)),
    ?assertEqual(8333, maps:get(port, Decoded)).

encode_addr_entry_ipv6_bip155_shape_test() ->
    %% 2001:4c3c:8102:2d00::2 in raw 16-byte wire form.
    Raw = <<8193:16, 19516:16, 33026:16, 11520:16, 0:16, 0:16, 0:16, 2:16>>,
    Entry = #{port => 8333, timestamp => 1776055509, address => Raw,
              services => 1, network => ipv6, network_id => 2},
    Bin = beamchain_p2p_msg:encode_addr_entry(Entry),
    ?assertEqual(30, byte_size(Bin)),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_addr_entry(Bin),
    ?assertEqual({8193, 19516, 33026, 11520, 0, 0, 0, 2},
                 maps:get(ip, Decoded)).

%% encode_payload(addr, ...) must drop unsupported entries and re-count so
%% the varint matches the actual number of encoded entries on the wire.
encode_payload_addr_skips_bad_entries_test() ->
    Good1 = #{timestamp => 1776055509, services => 1,
              ip => {10, 0, 0, 1}, port => 8333},
    Bad = #{timestamp => 1776055509, services => 3145, network => torv3,
            network_id => 4, address => crypto:strong_rand_bytes(32),
            port => 8333},
    Good2 = #{timestamp => 1776055509, services => 1,
              ip => {8193, 19516, 33026, 11520, 0, 0, 0, 2}, port => 8333},
    Bin = beamchain_p2p_msg:encode_payload(addr, #{addrs => [Good1, Bad, Good2]}),
    %% Count varint for 2 + 2 * 30-byte entries = 61 bytes total.
    ?assertEqual(61, byte_size(Bin)),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addr, Bin),
    ?assertEqual(2, length(Decoded)),
    ?assertEqual({10, 0, 0, 1}, maps:get(ip, lists:nth(1, Decoded))),
    ?assertEqual({8193, 19516, 33026, 11520, 0, 0, 0, 2},
                 maps:get(ip, lists:nth(2, Decoded))).

%%% ===================================================================
%%% Full integration: encode payload -> frame -> decode frame -> decode payload
%%% ===================================================================

full_pipeline_ping_test() ->
    Magic = ?REGTEST_MAGIC,
    Nonce = 16#1234567890ABCDEF,
    Payload = beamchain_p2p_msg:encode_payload(ping, #{nonce => Nonce}),
    Framed = beamchain_p2p_msg:encode_msg(Magic, ping, Payload),
    {ok, ping, RawPayload, <<>>} = beamchain_p2p_msg:decode_msg(Framed),
    {ok, #{nonce := Nonce}} = beamchain_p2p_msg:decode_payload(ping, RawPayload).

full_pipeline_inv_test() ->
    Magic = ?MAINNET_MAGIC,
    Hash = crypto:strong_rand_bytes(32),
    Items = [#{type => ?MSG_WITNESS_TX, hash => Hash}],
    Payload = beamchain_p2p_msg:encode_payload(inv, #{items => Items}),
    Framed = beamchain_p2p_msg:encode_msg(Magic, inv, Payload),
    {ok, inv, RawPayload, <<>>} = beamchain_p2p_msg:decode_msg(Framed),
    {ok, #{items := DecodedItems}} = beamchain_p2p_msg:decode_payload(inv, RawPayload),
    ?assertEqual(Items, DecodedItems).

full_pipeline_headers_test() ->
    Magic = ?TESTNET4_MAGIC,
    H = #block_header{version = 536870912, prev_hash = crypto:strong_rand_bytes(32),
                      merkle_root = crypto:strong_rand_bytes(32),
                      timestamp = 1714777860, bits = 16#1d00ffff, nonce = 1},
    Payload = beamchain_p2p_msg:encode_payload(headers, #{headers => [H]}),
    Framed = beamchain_p2p_msg:encode_msg(Magic, headers, Payload),
    {ok, headers, RawPayload, <<>>} = beamchain_p2p_msg:decode_msg(Framed),
    {ok, #{headers := [Decoded]}} = beamchain_p2p_msg:decode_payload(headers, RawPayload),
    ?assertEqual(H, Decoded).

%% Test decoding multiple messages from a concatenated stream
multiple_messages_stream_test() ->
    Magic = ?MAINNET_MAGIC,
    P1 = beamchain_p2p_msg:encode_payload(ping, #{nonce => 1}),
    P2 = beamchain_p2p_msg:encode_payload(pong, #{nonce => 1}),
    P3 = beamchain_p2p_msg:encode_payload(verack, #{}),
    M1 = beamchain_p2p_msg:encode_msg(Magic, ping, P1),
    M2 = beamchain_p2p_msg:encode_msg(Magic, pong, P2),
    M3 = beamchain_p2p_msg:encode_msg(Magic, verack, P3),
    Stream = <<M1/binary, M2/binary, M3/binary>>,
    {ok, ping, _, Rest1} = beamchain_p2p_msg:decode_msg(Stream),
    {ok, pong, _, Rest2} = beamchain_p2p_msg:decode_msg(Rest1),
    {ok, verack, _, <<>>} = beamchain_p2p_msg:decode_msg(Rest2).

%%% ===================================================================
%%% BIP155 ADDRv2 tests
%%% ===================================================================

%% Test addrv2 with IPv4 address
addrv2_ipv4_roundtrip_test() ->
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_NETWORK,
          network_id => 1, ip => {93, 184, 216, 34}, port => 8333}
    ],
    Bin = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => Addrs}),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addrv2, Bin),
    ?assertEqual(1, length(Decoded)),
    [Entry] = Decoded,
    ?assertEqual(1, maps:get(network_id, Entry)),
    ?assertEqual({93, 184, 216, 34}, maps:get(ip, Entry)),
    ?assertEqual(8333, maps:get(port, Entry)),
    ?assertEqual(?NODE_NETWORK, maps:get(services, Entry)).

%% Test addrv2 with IPv6 address
addrv2_ipv6_roundtrip_test() ->
    IPv6 = {8193, 3512, 0, 0, 0, 0, 0, 1},  %% 2001:db8::1
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_WITNESS,
          network_id => 2, ip => IPv6, port => 8333}
    ],
    Bin = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => Addrs}),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addrv2, Bin),
    ?assertEqual(1, length(Decoded)),
    [Entry] = Decoded,
    ?assertEqual(2, maps:get(network_id, Entry)),
    ?assertEqual(IPv6, maps:get(ip, Entry)),
    ?assertEqual(8333, maps:get(port, Entry)).

%% Test addrv2 with TorV3 address (32 bytes)
addrv2_torv3_roundtrip_test() ->
    %% TorV3: 32-byte ed25519 public key
    TorV3Addr = crypto:strong_rand_bytes(32),
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_NETWORK,
          network => torv3, network_id => 4, address => TorV3Addr, port => 9050}
    ],
    Bin = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => Addrs}),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addrv2, Bin),
    ?assertEqual(1, length(Decoded)),
    [Entry] = Decoded,
    ?assertEqual(4, maps:get(network_id, Entry)),
    ?assertEqual(TorV3Addr, maps:get(address, Entry)),
    ?assertEqual(9050, maps:get(port, Entry)),
    ?assertEqual(torv3, maps:get(network, Entry)).

%% Test addrv2 with I2P address (32 bytes)
addrv2_i2p_roundtrip_test() ->
    %% I2P: 32-byte SHA256 destination hash
    I2PAddr = crypto:strong_rand_bytes(32),
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_NETWORK,
          network => i2p, network_id => 5, address => I2PAddr, port => 0}
    ],
    Bin = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => Addrs}),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addrv2, Bin),
    ?assertEqual(1, length(Decoded)),
    [Entry] = Decoded,
    ?assertEqual(5, maps:get(network_id, Entry)),
    ?assertEqual(I2PAddr, maps:get(address, Entry)),
    ?assertEqual(i2p, maps:get(network, Entry)).

%% Test addrv2 with CJDNS address (16 bytes starting with 0xFC)
addrv2_cjdns_roundtrip_test() ->
    %% CJDNS: 16-byte address starting with 0xFC
    CJDNSAddr = <<16#FC, (crypto:strong_rand_bytes(15))/binary>>,
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_NETWORK,
          network => cjdns, network_id => 6, address => CJDNSAddr, port => 8333}
    ],
    Bin = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => Addrs}),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addrv2, Bin),
    ?assertEqual(1, length(Decoded)),
    [Entry] = Decoded,
    ?assertEqual(6, maps:get(network_id, Entry)),
    ?assertEqual(CJDNSAddr, maps:get(address, Entry)),
    ?assertEqual(cjdns, maps:get(network, Entry)).

%% Test addrv2 with multiple network types
addrv2_mixed_networks_test() ->
    TorV3Addr = crypto:strong_rand_bytes(32),
    I2PAddr = crypto:strong_rand_bytes(32),
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_NETWORK,
          network_id => 1, ip => {192, 168, 1, 1}, port => 8333},
        #{timestamp => 1702000100, services => ?NODE_WITNESS,
          network_id => 2, ip => {8193, 3512, 0, 0, 0, 0, 0, 1}, port => 8333},
        #{timestamp => 1702000200, services => 0,
          network => torv3, network_id => 4, address => TorV3Addr, port => 9050},
        #{timestamp => 1702000300, services => ?NODE_NETWORK,
          network => i2p, network_id => 5, address => I2PAddr, port => 0}
    ],
    Bin = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => Addrs}),
    {ok, #{addrs := Decoded}} = beamchain_p2p_msg:decode_payload(addrv2, Bin),
    ?assertEqual(4, length(Decoded)),
    %% Check network IDs
    NetworkIds = [maps:get(network_id, E) || E <- Decoded],
    ?assertEqual([1, 2, 4, 5], NetworkIds).

%% Test addrv2 empty message
addrv2_empty_test() ->
    Bin = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => []}),
    {ok, #{addrs := []}} = beamchain_p2p_msg:decode_payload(addrv2, Bin).

%% Test addrv2 entry encoding/decoding
addrv2_entry_roundtrip_test() ->
    Entry = #{timestamp => 1702000000, services => 1033,
              network_id => 1, ip => {10, 0, 0, 1}, port => 8333},
    Bin = beamchain_p2p_msg:encode_addrv2_entry(Entry),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
    ?assertEqual(1702000000, maps:get(timestamp, Decoded)),
    ?assertEqual(1033, maps:get(services, Decoded)),
    ?assertEqual(1, maps:get(network_id, Decoded)),
    ?assertEqual({10, 0, 0, 1}, maps:get(ip, Decoded)),
    ?assertEqual(8333, maps:get(port, Decoded)).

%% Test network_id helper functions
network_id_helpers_test() ->
    ?assertEqual(1, beamchain_p2p_msg:network_id(#{ip => {1, 2, 3, 4}})),
    ?assertEqual(2, beamchain_p2p_msg:network_id(#{ip => {1, 2, 3, 4, 5, 6, 7, 8}})),
    ?assertEqual(4, beamchain_p2p_msg:network_id(#{network_id => 4})),
    ?assertEqual(ipv4, beamchain_p2p_msg:network_id_to_atom(1)),
    ?assertEqual(ipv6, beamchain_p2p_msg:network_id_to_atom(2)),
    ?assertEqual(torv3, beamchain_p2p_msg:network_id_to_atom(4)),
    ?assertEqual(i2p, beamchain_p2p_msg:network_id_to_atom(5)),
    ?assertEqual(cjdns, beamchain_p2p_msg:network_id_to_atom(6)),
    ?assertEqual(4, beamchain_p2p_msg:addr_size_for_network(1)),
    ?assertEqual(16, beamchain_p2p_msg:addr_size_for_network(2)),
    ?assertEqual(32, beamchain_p2p_msg:addr_size_for_network(4)),
    ?assertEqual(32, beamchain_p2p_msg:addr_size_for_network(5)),
    ?assertEqual(16, beamchain_p2p_msg:addr_size_for_network(6)).

%% Test addrv2 CompactSize services encoding
addrv2_compactsize_services_test() ->
    %% Large services value that requires CompactSize encoding
    LargeSvc = 16#FFFFFFFF,
    Entry = #{timestamp => 1702000000, services => LargeSvc,
              network_id => 1, ip => {1, 2, 3, 4}, port => 8333},
    Bin = beamchain_p2p_msg:encode_addrv2_entry(Entry),
    {Decoded, <<>>} = beamchain_p2p_msg:decode_addrv2_entry(Bin),
    ?assertEqual(LargeSvc, maps:get(services, Decoded)).

%% Test full pipeline: addrv2 encode payload -> frame -> decode frame -> decode payload
full_pipeline_addrv2_test() ->
    Magic = ?MAINNET_MAGIC,
    TorV3Addr = crypto:strong_rand_bytes(32),
    Addrs = [
        #{timestamp => 1702000000, services => ?NODE_NETWORK,
          network_id => 1, ip => {192, 168, 1, 1}, port => 8333},
        #{timestamp => 1702000100, services => ?NODE_NETWORK,
          network => torv3, network_id => 4, address => TorV3Addr, port => 9050}
    ],
    Payload = beamchain_p2p_msg:encode_payload(addrv2, #{addrs => Addrs}),
    Framed = beamchain_p2p_msg:encode_msg(Magic, addrv2, Payload),
    {ok, addrv2, RawPayload, <<>>} = beamchain_p2p_msg:decode_msg(Framed),
    {ok, #{addrs := DecodedAddrs}} = beamchain_p2p_msg:decode_payload(addrv2, RawPayload),
    ?assertEqual(2, length(DecodedAddrs)).

%%% ===================================================================
%%% Wire-decode count caps (DoS hardening)
%%%
%%% Adversarial peers must not be able to trigger an unbounded list
%%% allocation by sending a tiny payload with a giant CompactSize count.
%%% Mirrors Bitcoin Core net_processing.cpp gates:
%%%   inv/getdata/notfound: MAX_INV_SZ = 50000     (:4042/:4133)
%%%   headers:              MAX_HEADERS_RESULTS=2000 (:4741)
%%%   addr/addrv2:          MAX_ADDR_TO_SEND = 1000 (:5637)
%%%   getheaders/getblocks: MAX_LOCATOR_SZ   = 101
%%% ===================================================================

%% Helper: encode CompactSize then enough zero bytes to "look like" the body,
%% so the cap rejects the count *before* allocation. We don't bother making
%% the body well-formed because the cap fires first (the whole point of the
%% fix is no allocation when count > MAX_X).
oversized_count_payload(Count) ->
    %% Just the varint — the cap rejects before reading any items.
    beamchain_serialize:encode_varint(Count).

inv_oversized_rejected_test() ->
    Bin = oversized_count_payload(?MAX_INV_SIZE + 1),
    ?assertMatch({error, {oversized, inv, _, ?MAX_INV_SIZE}},
                 beamchain_p2p_msg:decode_payload(inv, Bin)).

inv_attack_count_rejected_test() ->
    %% 1.0e9 > MAX_COMPACT_SIZE (0x02000000 = 33,554,432): decode_varint now
    %% rejects the count before the MAX_INV_SIZE check fires.  The inv handler
    %% propagates the parse error via {error, {bad_compact_size, inv, _}}.
    %% Any count > MAX_COMPACT_SIZE encoded in 5 wire bytes is now rejected
    %% at the CompactSize layer, not the inv-size layer.
    Bin = oversized_count_payload(1_000_000_000),
    ?assertMatch({error, {bad_compact_size, inv, oversized_compact_size}},
                 beamchain_p2p_msg:decode_payload(inv, Bin)).

getdata_oversized_rejected_test() ->
    Bin = oversized_count_payload(?MAX_INV_SIZE + 1),
    ?assertMatch({error, {oversized, getdata, _, ?MAX_INV_SIZE}},
                 beamchain_p2p_msg:decode_payload(getdata, Bin)).

notfound_oversized_rejected_test() ->
    Bin = oversized_count_payload(?MAX_INV_SIZE + 1),
    ?assertMatch({error, {oversized, notfound, _, ?MAX_INV_SIZE}},
                 beamchain_p2p_msg:decode_payload(notfound, Bin)).

headers_oversized_rejected_test() ->
    Bin = oversized_count_payload(?MAX_HEADERS_RESULTS + 1),
    ?assertMatch({error, {oversized, headers, _, ?MAX_HEADERS_RESULTS}},
                 beamchain_p2p_msg:decode_payload(headers, Bin)).

addr_oversized_rejected_test() ->
    Bin = oversized_count_payload(?MAX_ADDR_TO_SEND + 1),
    ?assertMatch({error, {oversized, addr, _, ?MAX_ADDR_TO_SEND}},
                 beamchain_p2p_msg:decode_payload(addr, Bin)).

addrv2_oversized_rejected_test() ->
    Bin = oversized_count_payload(?MAX_ADDR_TO_SEND + 1),
    ?assertMatch({error, {oversized, addrv2, _, ?MAX_ADDR_TO_SEND}},
                 beamchain_p2p_msg:decode_payload(addrv2, Bin)).

getheaders_locator_oversized_rejected_test() ->
    %% getheaders prefix: 4-byte version + varint locator count
    Prefix = <<?PROTOCOL_VERSION:32/little>>,
    CountBin = beamchain_serialize:encode_varint(?MAX_LOCATOR_SZ + 1),
    Bin = <<Prefix/binary, CountBin/binary>>,
    ?assertMatch({error, {oversized, getheaders, _, ?MAX_LOCATOR_SZ}},
                 beamchain_p2p_msg:decode_payload(getheaders, Bin)).

getblocks_locator_oversized_rejected_test() ->
    Prefix = <<?PROTOCOL_VERSION:32/little>>,
    CountBin = beamchain_serialize:encode_varint(?MAX_LOCATOR_SZ + 1),
    Bin = <<Prefix/binary, CountBin/binary>>,
    ?assertMatch({error, {oversized, getblocks, _, ?MAX_LOCATOR_SZ}},
                 beamchain_p2p_msg:decode_payload(getblocks, Bin)).

%% Boundary: exactly MAX must NOT be rejected by the cap (it's a count
%% gate, not a count-strictly-less-than gate). With count = MAX and an
%% empty body the decoder will fail later (not enough wire bytes), but the
%% failure must NOT be an `oversized` error.
inv_at_cap_not_oversized_test() ->
    Bin = oversized_count_payload(?MAX_INV_SIZE),
    Result = (catch beamchain_p2p_msg:decode_payload(inv, Bin)),
    %% Either it crashes on the missing body, or returns ok with [] —
    %% but it must NOT return our oversized error tag.
    case Result of
        {error, {oversized, _, _, _}} ->
            ?assert(false);
        _ ->
            ok
    end.

headers_at_cap_not_oversized_test() ->
    Bin = oversized_count_payload(?MAX_HEADERS_RESULTS),
    Result = (catch beamchain_p2p_msg:decode_payload(headers, Bin)),
    case Result of
        {error, {oversized, _, _, _}} ->
            ?assert(false);
        _ ->
            ok
    end.
