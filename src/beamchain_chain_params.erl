-module(beamchain_chain_params).

%% Network-specific consensus parameters.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([params/1]).

%% @doc Returns comprehensive chain parameters for the given network.
-spec params(mainnet | testnet | testnet4 | regtest | signet) -> map().
params(mainnet) ->
    #{
        network => mainnet,
        magic => <<16#F9, 16#BE, 16#B4, 16#D9>>,
        default_port => 8333,
        rpc_port => 8332,

        %% genesis block hash (display byte order)
        genesis_hash => hex_to_bin(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),

        %% proof of work
        pow_limit => hex_to_bin(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_target_timespan => ?POW_TARGET_TIMESPAN,
        pow_target_spacing => ?POW_TARGET_SPACING,
        pow_allow_min_difficulty => false,
        pow_no_retargeting => false,

        %% subsidy
        subsidy_halving_interval => ?SUBSIDY_HALVING_INTERVAL,

        %% buried deployment heights
        bip34_height => 227931,
        bip65_height => 388381,
        bip66_height => 363725,
        csv_height => 419328,
        segwit_height => 481824,
        taproot_height => 709632,

        %% minimum chainwork to accept
        min_chainwork => hex_to_bin(
            "000000000000000000000000000000000000000072a4fe66c1e2e826e5e1e9d0"),

        %% skip script verification before this block
        assume_valid => hex_to_bin(
            "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),

        %% checkpoints (height => hash in display byte order)
        checkpoints => mainnet_checkpoints(),

        %% dns seeds for initial peer discovery
        dns_seeds => [
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr-list-of-hierarchies.us",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz"
        ],

        %% bip30 exception heights (duplicate txids allowed)
        bip30_exceptions => [91722, 91812],

        %% address encoding
        pubkey_prefix => 0,
        script_prefix => 5,
        bech32_hrp => "bc"
    }.

%%% -------------------------------------------------------------------
%%% Checkpoints
%%% -------------------------------------------------------------------

mainnet_checkpoints() ->
    #{
        11111  => hex_to_bin("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"),
        33333  => hex_to_bin("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"),
        74000  => hex_to_bin("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"),
        105000 => hex_to_bin("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"),
        134444 => hex_to_bin("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"),
        168000 => hex_to_bin("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"),
        193000 => hex_to_bin("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"),
        210000 => hex_to_bin("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"),
        216116 => hex_to_bin("00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"),
        225430 => hex_to_bin("00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"),
        250000 => hex_to_bin("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"),
        279000 => hex_to_bin("0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"),
        295000 => hex_to_bin("00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")
    }.

%%% -------------------------------------------------------------------
%%% Internal helpers
%%% -------------------------------------------------------------------

hex_to_bin(HexStr) ->
    hex_to_bin(HexStr, <<>>).

hex_to_bin([], Acc) ->
    Acc;
hex_to_bin([H1, H2 | Rest], Acc) ->
    Byte = (hex_val(H1) bsl 4) bor hex_val(H2),
    hex_to_bin(Rest, <<Acc/binary, Byte>>).

hex_val(C) when C >= $0, C =< $9 -> C - $0;
hex_val(C) when C >= $a, C =< $f -> C - $a + 10;
hex_val(C) when C >= $A, C =< $F -> C - $A + 10.
