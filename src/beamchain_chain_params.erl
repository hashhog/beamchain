-module(beamchain_chain_params).

%% Network-specific consensus parameters.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([params/1, genesis_block/1, block_subsidy/2]).
-export([get_last_checkpoint/2, get_checkpoint/2]).
-export([get_assumeutxo/2, get_assumeutxo_by_hash/2,
         list_assumeutxo_heights/1]).

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
        genesis_block => genesis_block(mainnet),

        %% proof of work
        pow_limit => hex_to_bin(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_target_timespan => ?POW_TARGET_TIMESPAN,
        pow_target_spacing => ?POW_TARGET_SPACING,
        pow_allow_min_difficulty => false,
        pow_no_retargeting => false,
        enforce_bip94 => false,

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

        %% skip script verification before this block (height 938343)
        assume_valid => hex_to_bin(
            "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"),

        %% checkpoints (height => hash in display byte order)
        checkpoints => mainnet_checkpoints(),

        %% assumeutxo snapshots: {height, block_hash, utxo_hash, num_coins}
        %% Block hash and UTXO hash are in display byte order (reversed)
        assumeutxo => mainnet_assumeutxo(),

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

        %% BIP30 exception pairs {Height, BlockHash}: blocks whose coinbase txids
        %% duplicate an earlier coinbase.  Bitcoin Core's IsBIP30Repeat()
        %% (validation.cpp:6189-6193) exempts these two blocks from the BIP30
        %% check, matching on both height AND block hash.
        %% 91842 and 91880 are the REPEAT blocks; 91722 and 91812 are the
        %% ORIGINALS (whose coinbases were overwritten — never in UTXO set).
        bip30_exceptions => [
            {91842, hex_to_bin("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")},
            {91880, hex_to_bin("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")}
        ],

        %% BIP34 canonical activation hash.  Bitcoin Core checks this via
        %% pindexBIP34height->GetBlockHash() == BIP34Hash (validation.cpp:2462)
        %% to confirm we are on the known canonical chain before skipping
        %% BIP30 checks above the BIP34 activation height.
        bip34_hash => hex_to_bin(
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"),

        %% address encoding
        pubkey_prefix => 0,
        script_prefix => 5,
        bech32_hrp => "bc"
    };

params(testnet) ->
    #{
        network => testnet,
        magic => <<16#0B, 16#11, 16#09, 16#07>>,
        default_port => 18333,
        rpc_port => 18332,

        genesis_hash => hex_to_bin(
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
        genesis_block => genesis_block(testnet),

        pow_limit => hex_to_bin(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_target_timespan => ?POW_TARGET_TIMESPAN,
        pow_target_spacing => ?POW_TARGET_SPACING,
        pow_allow_min_difficulty => true,
        pow_no_retargeting => false,
        enforce_bip94 => false,

        subsidy_halving_interval => ?SUBSIDY_HALVING_INTERVAL,

        bip34_height => 21111,
        bip65_height => 581885,
        bip66_height => 330776,
        csv_height => 770112,
        segwit_height => 834624,
        taproot_height => 0,

        min_chainwork => <<0:256>>,
        assume_valid => <<0:256>>,
        checkpoints => #{},

        %% assumeutxo snapshots
        assumeutxo => #{},

        dns_seeds => [
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.net",
            "seed.testnet.bitcoin.sprovoost.nl",
            "testnet-seed.bluematt.me"
        ],

        bip30_exceptions => [],
        pubkey_prefix => 111,
        script_prefix => 196,
        bech32_hrp => "tb"
    };

params(testnet4) ->
    #{
        network => testnet4,
        magic => <<16#1C, 16#16, 16#3F, 16#28>>,
        default_port => 48333,
        rpc_port => 48332,

        genesis_hash => hex_to_bin(
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
        genesis_block => genesis_block(testnet4),

        pow_limit => hex_to_bin(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_target_timespan => ?POW_TARGET_TIMESPAN,
        pow_target_spacing => ?POW_TARGET_SPACING,
        pow_allow_min_difficulty => true,
        pow_no_retargeting => false,
        enforce_bip94 => true,

        subsidy_halving_interval => ?SUBSIDY_HALVING_INTERVAL,

        %% all BIPs active from block 1 on testnet4
        bip34_height => 1,
        bip65_height => 1,
        bip66_height => 1,
        csv_height => 1,
        segwit_height => 1,
        taproot_height => 1,

        min_chainwork => <<0:256>>,
        %% Skip script verification below height 123613
        assume_valid => hex_to_bin(
            "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a"),
        checkpoints => #{},

        %% assumeutxo snapshots
        assumeutxo => testnet4_assumeutxo(),

        dns_seeds => [
            "seed.testnet4.bitcoin.sprovoost.nl",
            "seed.testnet4.wiz.biz"
        ],

        bip30_exceptions => [],
        pubkey_prefix => 111,
        script_prefix => 196,
        bech32_hrp => "tb"
    };

params(regtest) ->
    #{
        network => regtest,
        magic => <<16#FA, 16#BF, 16#B5, 16#DA>>,
        default_port => 18444,
        rpc_port => 18443,

        genesis_hash => hex_to_bin(
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
        genesis_block => genesis_block(regtest),

        pow_limit => hex_to_bin(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        pow_target_timespan => ?POW_TARGET_TIMESPAN,
        pow_target_spacing => ?POW_TARGET_SPACING,
        pow_allow_min_difficulty => true,
        pow_no_retargeting => true,
        enforce_bip94 => false,

        subsidy_halving_interval => 150,

        bip34_height => 1,
        bip65_height => 1,
        bip66_height => 1,
        csv_height => 1,
        segwit_height => 1,
        taproot_height => 1,

        min_chainwork => <<0:256>>,
        assume_valid => <<0:256>>,
        checkpoints => #{},

        %% assumeutxo snapshots
        assumeutxo => regtest_assumeutxo(),

        dns_seeds => [],

        bip30_exceptions => [],
        pubkey_prefix => 111,
        script_prefix => 196,
        bech32_hrp => "bcrt"
    };

params(signet) ->
    #{
        network => signet,
        magic => <<16#0A, 16#03, 16#CF, 16#40>>,
        default_port => 38333,
        rpc_port => 38332,

        genesis_hash => hex_to_bin(
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
        genesis_block => genesis_block(signet),

        pow_limit => hex_to_bin(
            "00000377ae000000000000000000000000000000000000000000000000000000"),
        pow_target_timespan => ?POW_TARGET_TIMESPAN,
        pow_target_spacing => ?POW_TARGET_SPACING,
        pow_allow_min_difficulty => false,
        pow_no_retargeting => false,
        enforce_bip94 => false,

        subsidy_halving_interval => ?SUBSIDY_HALVING_INTERVAL,

        bip34_height => 1,
        bip65_height => 1,
        bip66_height => 1,
        csv_height => 1,
        segwit_height => 1,
        taproot_height => 1,

        min_chainwork => <<0:256>>,
        assume_valid => <<0:256>>,
        checkpoints => #{},

        %% assumeutxo snapshots
        assumeutxo => #{},

        dns_seeds => [
            "seed.signet.bitcoin.sprovoost.nl"
        ],

        bip30_exceptions => [],
        pubkey_prefix => 111,
        script_prefix => 196,
        bech32_hrp => "tb"
    }.

%%% -------------------------------------------------------------------
%%% Checkpoints
%%% -------------------------------------------------------------------

mainnet_checkpoints() ->
    #{
        0      => hex_to_bin("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
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
%%% Genesis blocks
%%% -------------------------------------------------------------------

%% @doc Build the genesis block for the given network.
%% Mainnet/testnet/regtest/signet use satoshi's original coinbase.
%% Testnet4 (BIP94) uses a different coinbase message and null output key.
-spec genesis_block(atom()) -> #block{}.
genesis_block(mainnet) ->
    make_genesis(satoshi_coinbase(), 1231006505, 2083236893, 16#1d00ffff);
genesis_block(testnet) ->
    make_genesis(satoshi_coinbase(), 1296688602, 414098458, 16#1d00ffff);
genesis_block(testnet4) ->
    make_genesis(testnet4_coinbase(), 1714777860, 393743547, 16#1d00ffff);
genesis_block(regtest) ->
    make_genesis(satoshi_coinbase(), 1296688602, 2, 16#207fffff);
genesis_block(signet) ->
    make_genesis(satoshi_coinbase(), 1598918400, 52613770, 16#1e0377ae).

make_genesis(CoinbaseTx, Timestamp, Nonce, Bits) ->
    MerkleRoot = beamchain_serialize:tx_hash(CoinbaseTx),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = MerkleRoot,
        timestamp = Timestamp,
        bits = Bits,
        nonce = Nonce
    },
    Hash = beamchain_serialize:block_hash(Header),
    #block{
        header = Header,
        transactions = [CoinbaseTx],
        hash = Hash,
        height = 0
    }.

%% The original satoshi coinbase used by mainnet, testnet3, regtest, signet
satoshi_coinbase() ->
    %% scriptSig: push(4) ffff001d push(1) 04 push(69) "The Times..."
    ScriptSig = hex_to_bin(
        "04ffff001d0104455468652054696d65732030332f4a616e2f323030"
        "39204368616e63656c6c6f72206f6e206272696e6b206f66207365"
        "636f6e64206261696c6f757420666f722062616e6b73"),
    %% output: <65-byte uncompressed pubkey> OP_CHECKSIG
    ScriptPubKey = hex_to_bin(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962"
        "e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba"
        "0b8d578a4c702b6bf11d5fac"),
    make_coinbase_tx(ScriptSig, ScriptPubKey).

%% BIP94 testnet4 coinbase — different message, null compressed pubkey
testnet4_coinbase() ->
    Msg = <<"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e">>,
    %% scriptSig: push(4) ffff001d push(1) 04 OP_PUSHDATA1(76) <msg>
    ScriptSig = <<16#04, 16#ff, 16#ff, 16#00, 16#1d,
                  16#01, 16#04,
                  16#4c, (byte_size(Msg)):8,
                  Msg/binary>>,
    %% output: <33 zero bytes (null compressed pubkey)> OP_CHECKSIG
    ScriptPubKey = <<16#21, 0:264, 16#ac>>,
    make_coinbase_tx(ScriptSig, ScriptPubKey).

make_coinbase_tx(ScriptSig, ScriptPubKey) ->
    #transaction{
        version = 1,
        inputs = [#tx_in{
            prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
            script_sig = ScriptSig,
            sequence = 16#ffffffff,
            witness = []
        }],
        outputs = [#tx_out{
            value = ?INITIAL_SUBSIDY,
            script_pubkey = ScriptPubKey
        }],
        locktime = 0
    }.

%%% -------------------------------------------------------------------
%%% Block subsidy
%%% -------------------------------------------------------------------

%% @doc Calculate the block subsidy (mining reward) at a given height.
%% Starts at 50 BTC, halves every `subsidy_halving_interval` blocks.
%% Returns 0 after 64 halvings.
-spec block_subsidy(non_neg_integer(), atom()) -> non_neg_integer().
block_subsidy(Height, Network) ->
    #{subsidy_halving_interval := Interval} = params(Network),
    Halvings = Height div Interval,
    case Halvings >= 64 of
        true -> 0;
        false -> ?INITIAL_SUBSIDY bsr Halvings
    end.

%%% -------------------------------------------------------------------
%%% Checkpoint helpers
%%% -------------------------------------------------------------------

%% @doc Get the highest checkpoint at or below the given height.
%% Returns {Height, Hash} or 'none' if no checkpoint exists at or below Height.
%% Hash is in display byte order.
-spec get_last_checkpoint(non_neg_integer(), atom()) ->
    {non_neg_integer(), binary()} | none.
get_last_checkpoint(Height, Network) ->
    #{checkpoints := Checkpoints} = params(Network),
    case maps:size(Checkpoints) of
        0 -> none;
        _ ->
            %% Find the highest checkpoint height <= Height
            ValidHeights = [H || H <- maps:keys(Checkpoints), H =< Height],
            case ValidHeights of
                [] -> none;
                _ ->
                    MaxH = lists:max(ValidHeights),
                    {MaxH, maps:get(MaxH, Checkpoints)}
            end
    end.

%% @doc Get the checkpoint hash at exact height, or none if no checkpoint.
%% Hash is in display byte order.
-spec get_checkpoint(non_neg_integer(), atom()) -> binary() | none.
get_checkpoint(Height, Network) ->
    #{checkpoints := Checkpoints} = params(Network),
    case maps:find(Height, Checkpoints) of
        {ok, Hash} -> Hash;
        error -> none
    end.

%%% -------------------------------------------------------------------
%%% assumeUTXO helpers
%%% -------------------------------------------------------------------

%% @doc Get assumeutxo parameters for a given height.
%% Returns {ok, #{block_hash, utxo_hash, chain_tx_count}} or not_found.
-spec get_assumeutxo(non_neg_integer(), atom()) ->
    {ok, #{block_hash => binary(), utxo_hash => binary(),
           chain_tx_count => non_neg_integer()}} | not_found.
get_assumeutxo(Height, Network) ->
    #{assumeutxo := AssumeUtxo} = params(Network),
    case maps:find(Height, AssumeUtxo) of
        {ok, Data} -> {ok, Data};
        error -> not_found
    end.

%% @doc Get assumeutxo parameters by block hash (in INTERNAL byte order
%% — i.e. the bytes a Core-format snapshot file's metadata header
%% carries, opposite of the display hex).
%% Returns {ok, Height, #{utxo_hash, chain_tx_count}} or not_found.
-spec get_assumeutxo_by_hash(binary(), atom()) ->
    {ok, non_neg_integer(), #{utxo_hash => binary(),
                               chain_tx_count => non_neg_integer()}} |
    not_found.
get_assumeutxo_by_hash(BlockHash, Network) ->
    #{assumeutxo := AssumeUtxo} = params(Network),
    %% Search through all entries for matching block hash
    Result = maps:fold(fun(Height, #{block_hash := Hash} = Data, Acc) ->
        case Hash =:= BlockHash of
            true -> {found, Height, maps:remove(block_hash, Data)};
            false -> Acc
        end
    end, not_found, AssumeUtxo),
    case Result of
        {found, H, D} -> {ok, H, D};
        not_found -> not_found
    end.

%% @doc List the heights of every assumeutxo snapshot defined for this
%% network, sorted ascending. Mirrors
%% bitcoin-core/src/kernel/chainparams.cpp `GetAvailableSnapshotHeights`,
%% used by `dumptxoutset rollback` (no explicit height) to pick the
%% latest snapshot ≤ tip.
-spec list_assumeutxo_heights(atom()) -> [non_neg_integer()].
list_assumeutxo_heights(Network) ->
    #{assumeutxo := AssumeUtxo} = params(Network),
    lists:sort(maps:keys(AssumeUtxo)).

%%% -------------------------------------------------------------------
%%% assumeUTXO snapshot parameters
%%% -------------------------------------------------------------------

%% Mainnet assumeutxo snapshots — kept byte-for-byte in sync with
%% bitcoin-core/src/kernel/chainparams.cpp m_assumeutxo_data (CMainParams).
%% Hashes are stored in INTERNAL byte order (the on-wire / on-disk
%% representation that uint256::Serialize emits) so they line up with the
%% bytes a Bitcoin Core-format snapshot file carries in its metadata
%% header. The Core source uses uint256{"<hex>"} which reverses display
%% hex into internal storage; we replicate that with display_hex_to_bin/1.
%%
%% Mirrors the AssumeutxoData struct (kernel/chainparams.h):
%%   * height
%%   * hash_serialized (utxo_hash here) — the SHA-256 of the serialized
%%     UTXO set. Verified against the loaded snapshot post-load.
%%   * m_chain_tx_count (chain_tx_count here) — used to populate
%%     CBlockIndex::m_chain_tx_count for the snapshot base block.
%%   * blockhash (block_hash here) — the base block's hash; the snapshot
%%     file's metadata header must agree.
mainnet_assumeutxo() ->
    #{
        %% Block 840,000 — post-4th halving
        840000 => #{
            block_hash => display_hex_to_bin(
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),
            utxo_hash => display_hex_to_bin(
                "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"),
            chain_tx_count => 991032194
        },
        %% Block 880,000
        880000 => #{
            block_hash => display_hex_to_bin(
                "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"),
            utxo_hash => display_hex_to_bin(
                "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"),
            chain_tx_count => 1145604538
        },
        %% Block 910,000
        910000 => #{
            block_hash => display_hex_to_bin(
                "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"),
            utxo_hash => display_hex_to_bin(
                "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"),
            chain_tx_count => 1226586151
        },
        %% Block 935,000
        935000 => #{
            block_hash => display_hex_to_bin(
                "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"),
            utxo_hash => display_hex_to_bin(
                "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"),
            chain_tx_count => 1305397408
        }
    }.

%% Testnet4 assumeutxo snapshots from bitcoin-core/src/kernel/chainparams.cpp
%% CTestNet4Params::m_assumeutxo_data (heights 90,000 and 120,000).
testnet4_assumeutxo() ->
    #{
        90000 => #{
            block_hash => display_hex_to_bin(
                "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"),
            utxo_hash => display_hex_to_bin(
                "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"),
            chain_tx_count => 11347043
        },
        120000 => #{
            block_hash => display_hex_to_bin(
                "000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8"),
            utxo_hash => display_hex_to_bin(
                "10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0"),
            chain_tx_count => 14141057
        }
    }.

%% Regtest assumeutxo - height 110 (useful for testing after coinbase maturity)
regtest_assumeutxo() ->
    #{
        %% Height 110 - allows spending first coinbase
        110 => #{
            block_hash => <<0:256>>,  %% Placeholder - must be computed
            utxo_hash => <<0:256>>,   %% Placeholder - must be computed
            chain_tx_count => 110
        }
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

%% @doc Convert a display-order hex string (block-explorer style, big-endian
%% as written) into INTERNAL byte order (little-endian, the on-disk
%% representation Core uses for uint256). Equivalent to
%% bitcoin-core/src/uint256.h base_blob(string_view) which reverses the
%% input via str_it = hex_str.rbegin().
display_hex_to_bin(HexStr) ->
    Bin = hex_to_bin(HexStr),
    %% Reverse to get internal byte order
    list_to_binary(lists:reverse(binary_to_list(Bin))).
