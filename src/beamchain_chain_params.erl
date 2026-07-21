-module(beamchain_chain_params).

%% Network-specific consensus parameters.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([params/1, genesis_block/1, block_subsidy/2]).
-export([get_last_checkpoint/2, get_checkpoint/2]).
-export([get_assumeutxo/2, get_assumeutxo_by_hash/2,
         list_assumeutxo_heights/1]).
-export([register_regtest_assumeutxo/4, register_regtest_assumeutxo/2,
         clear_regtest_assumeutxo/0, regtest_assumeutxo_registry/0]).
-export([load_campaign_assumeutxo/0, campaign_assumeutxo_registry/0,
         clear_campaign_assumeutxo/0]).

%% @doc Returns comprehensive chain parameters for the given network.
%%
%% assumevalid disable knob: when the operator passes `--noassumevalid`
%% (or `--assumevalid=0`), beamchain_cli routes it through the
%% BEAMCHAIN_ASSUMEVALID=0 environment variable. This wrapper then zeroes
%% the `assume_valid` field of whatever network params it returns, so the
%% skip_scripts gate (beamchain_validation:skip_scripts/3, condition 1) and
%% the block_sync assume_valid_height cache both see <<0:256>> = disabled,
%% forcing FULL script verification of all history. Used by the
%% mainnet-replay harness (assumevalid=0). Strictly MORE verification, never
%% less — non-consensus in the reject direction.
-spec params(mainnet | testnet | testnet4 | regtest | signet) -> map().
params(Network) ->
    maybe_disable_assume_valid(params_raw(Network)).

%% @doc Zero the assume_valid field when the disable knob is set.
-spec maybe_disable_assume_valid(map()) -> map().
maybe_disable_assume_valid(Params) ->
    case assume_valid_disabled() of
        true  -> Params#{assume_valid => <<0:256>>};
        false -> Params
    end.

%% @doc True iff BEAMCHAIN_ASSUMEVALID selects the disabled sentinel.
%% "0" / "false" / "none" all disable; anything else (incl. unset) leaves
%% the network's built-in assume_valid untouched.
-spec assume_valid_disabled() -> boolean().
assume_valid_disabled() ->
    case os:getenv("BEAMCHAIN_ASSUMEVALID") of
        "0"     -> true;
        "false" -> true;
        "none"  -> true;
        _       -> false
    end.

%% @doc Network params as declared in-source (before the assumevalid knob).
-spec params_raw(mainnet | testnet | testnet4 | regtest | signet) -> map().
params_raw(mainnet) ->
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
            "0000000000000000000000000000000000000001128750f82f4c366153a3a030"),

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
        %% INTERNAL byte order (display_hex_to_bin): compared against
        %% beamchain_serialize:block_hash/1 (raw hash256, internal LE) at the
        %% BIP30 check (beamchain_validation.erl:1101). hex_to_bin left these in
        %% display order so `BlockHash =:= ExHash` never matched -> BIP30 stayed
        %% enforced at 91842 -> forward-sync stalled at 91841 (W149 byte-order bug).
        bip30_exceptions => [
            {91842, display_hex_to_bin("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")},
            {91880, display_hex_to_bin("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")}
        ],

        %% BIP34 canonical activation hash.  Bitcoin Core checks this via
        %% pindexBIP34height->GetBlockHash() == BIP34Hash (validation.cpp:2462)
        %% to confirm we are on the known canonical chain before skipping
        %% BIP30 checks above the BIP34 activation height.
        %% INTERNAL byte order (display_hex_to_bin): compared against the block
        %% index hash at bip34_height (block_hash/1, internal LE) in Gate (b).
        bip34_hash => display_hex_to_bin(
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"),

        %% address encoding
        pubkey_prefix => 0,
        script_prefix => 5,
        bech32_hrp => "bc"
    };

params_raw(testnet) ->
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

        min_chainwork => hex_to_bin(
            "0000000000000000000000000000000000000000000017dde1c649f3708d14b6"),
        assume_valid => hex_to_bin(
            "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4"),
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

params_raw(testnet4) ->
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

        min_chainwork => hex_to_bin(
            "0000000000000000000000000000000000000000000009a0fe15d0177d086304"),
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

params_raw(regtest) ->
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

params_raw(signet) ->
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
    AssumeUtxo = effective_assumeutxo(Network),
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
    AssumeUtxo = effective_assumeutxo(Network),
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
    AssumeUtxo = effective_assumeutxo(Network),
    lists:sort(maps:keys(AssumeUtxo)).

%%% -------------------------------------------------------------------
%%% Runtime-registerable regtest AssumeUTXO whitelist.
%%%
%%% mainnet / testnet4 m_assumeutxo_data are hard-coded and UNTOUCHED by
%%% this registry (effective_assumeutxo/1 only consults it for regtest).
%%% Regtest snapshots have no canonical published base hash / commitment,
%%% so an operator (or a test) registers the {height, block_hash,
%%% utxo_hash, chain_tx_count} entry at runtime. Stored in a process-wide
%%% ETS table keyed by height. Mirrors how Core lets the regtest chain
%%% carry an m_assumeutxo_data that is populated for the test at hand.
%%% -------------------------------------------------------------------

-define(REGTEST_AU_TABLE, beamchain_regtest_assumeutxo).

%% @doc Register (or overwrite) a regtest AssumeUTXO entry at `Height`.
-spec register_regtest_assumeutxo(non_neg_integer(), binary(), binary(),
                                  non_neg_integer()) -> ok.
register_regtest_assumeutxo(Height, BlockHash, UtxoHash, ChainTxCount)
        when is_integer(Height), Height >= 0,
             is_binary(BlockHash), byte_size(BlockHash) =:= 32,
             is_binary(UtxoHash), byte_size(UtxoHash) =:= 32,
             is_integer(ChainTxCount), ChainTxCount >= 0 ->
    ensure_regtest_au_table(),
    ets:insert(?REGTEST_AU_TABLE,
               {Height, #{block_hash => BlockHash,
                          utxo_hash => UtxoHash,
                          chain_tx_count => ChainTxCount}}),
    ok.

%% @doc Register a regtest AssumeUTXO entry from a data map.
-spec register_regtest_assumeutxo(non_neg_integer(), map()) -> ok.
register_regtest_assumeutxo(Height, #{block_hash := BH, utxo_hash := UH} = Data) ->
    register_regtest_assumeutxo(Height, BH, UH,
                                maps:get(chain_tx_count, Data, Height)).

%% @doc Remove all runtime regtest AssumeUTXO registrations.
-spec clear_regtest_assumeutxo() -> ok.
clear_regtest_assumeutxo() ->
    case ets:whereis(?REGTEST_AU_TABLE) of
        undefined -> ok;
        _ -> ets:delete_all_objects(?REGTEST_AU_TABLE), ok
    end.

%% @doc Snapshot of the current regtest registry as a height-keyed map.
-spec regtest_assumeutxo_registry() -> map().
regtest_assumeutxo_registry() ->
    case ets:whereis(?REGTEST_AU_TABLE) of
        undefined -> #{};
        _ -> maps:from_list(ets:tab2list(?REGTEST_AU_TABLE))
    end.

ensure_regtest_au_table() ->
    case ets:whereis(?REGTEST_AU_TABLE) of
        undefined ->
            %% public + named so any process can register/read; heir-less
            %% (lives as long as the creating process). Guarded against the
            %% race where two callers create concurrently.
            try ets:new(?REGTEST_AU_TABLE,
                        [set, public, named_table, {keypos, 1}])
            catch error:badarg -> ?REGTEST_AU_TABLE end;
        _ ->
            ?REGTEST_AU_TABLE
    end.

%% Effective AssumeUTXO map for a network: hard-coded chainparams for
%% mainnet/testnet4 (UNTOUCHED), overlaid with the runtime registry for
%% regtest only, then overlaid with the campaign registry (any network —
%% see the campaign section below). Later maps:merge/2 args win on key
%% collision.
effective_assumeutxo(regtest) ->
    #{assumeutxo := Base} = params(regtest),
    WithRegtestRegistry = maps:merge(Base, regtest_assumeutxo_registry()),
    maps:merge(WithRegtestRegistry, campaign_assumeutxo_registry());
effective_assumeutxo(Network) ->
    #{assumeutxo := AssumeUtxo} = params(Network),
    maps:merge(AssumeUtxo, campaign_assumeutxo_registry()).

%%% -------------------------------------------------------------------
%%% Campaign-only AssumeUTXO allowlist (HASHHOG_CAMPAIGN_ASSUMEUTXO).
%%%
%%% Design spec: receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md. Lets the M2
%%% boundary campaign fast-forward a scratch node to `H-W-1` via a UTXO
%%% snapshot whose base isn't (yet) one of the hard-coded production
%%% entries above, WITHOUT ever touching those production tables.
%%%
%%% Read exactly once at startup (beamchain_app:start/2, before the
%%% supervision tree comes up) via load_campaign_assumeutxo/0. When the
%%% env var is unset or empty, that call is a single os:getenv/1 and
%%% nothing else executes — no ETS table is created, so
%%% campaign_assumeutxo_registry/0 returns #{} and effective_assumeutxo/1
%%% is BYTE-FOR-BYTE identical to the pre-campaign-flag code path. This
%%% is the production-safety invariant: real mainnet/testnet4 boots never
%%% set this var, so they never execute anything beyond the getenv.
%%%
%%% When set: the file is parsed, validated (well-formed 32-byte hex
%%% hashes, height > 0, no duplicate heights/hashes within the file), and
%%% checked for collision against the built-in table of EVERY network
%%% (mainnet, testnet4, regtest) — not just whichever one ends up running
%%% — since campaign data may never shadow a production hash on any
%%% network. On any validation failure OR a height/blockhash collision
%%% with a built-in entry, load_campaign_assumeutxo/0 returns {error, _};
%%% beamchain_app:start/2 propagates that as the application start
%%% failure, so the node refuses to start rather than silently shadowing
%%% a production hash.
%%% -------------------------------------------------------------------

-define(CAMPAIGN_ASSUMEUTXO_ENV, "HASHHOG_CAMPAIGN_ASSUMEUTXO").
-define(CAMPAIGN_AU_TABLE, beamchain_campaign_assumeutxo).

%% @doc Load campaign AssumeUTXO entries from the file named by
%% HASHHOG_CAMPAIGN_ASSUMEUTXO, if set. See the module-doc comment above
%% for the full contract. Call exactly once, early in application start.
-spec load_campaign_assumeutxo() -> ok | {error, term()}.
load_campaign_assumeutxo() ->
    case os:getenv(?CAMPAIGN_ASSUMEUTXO_ENV) of
        false -> ok;
        ""    -> ok;
        Path  -> do_load_campaign_assumeutxo(Path)
    end.

do_load_campaign_assumeutxo(Path) ->
    case file:read_file(Path) of
        {error, Reason} ->
            {error, {campaign_assumeutxo_read_failed, Path, Reason}};
        {ok, Bin} ->
            try jsx:decode(Bin, [return_maps]) of
                List when is_list(List) ->
                    validate_and_load_campaign(Path, List);
                Other ->
                    {error, {campaign_assumeutxo_not_a_list, Path, Other}}
            catch
                Class:Reason ->
                    {error, {campaign_assumeutxo_bad_json, Path,
                             {Class, Reason}}}
            end
    end.

validate_and_load_campaign(Path, RawEntries) ->
    case parse_campaign_entries(RawEntries) of
        {error, _} = Err ->
            Err;
        {ok, Parsed} ->
            case check_no_internal_duplicates(Parsed) of
                {error, _} = Err ->
                    Err;
                ok ->
                    case check_no_builtin_collision(Parsed) of
                        {error, _} = Err ->
                            Err;
                        ok ->
                            install_campaign_entries(Parsed),
                            Heights = lists:sort([H || {H, _} <- Parsed]),
                            logger:notice(
                                "[CAMPAIGN-ASSUMEUTXO] loaded ~B entries "
                                "from ~s heights=~p",
                                [length(Parsed), Path, Heights]),
                            ok
                    end
            end
    end.

parse_campaign_entries(RawEntries) ->
    parse_campaign_entries(RawEntries, []).

parse_campaign_entries([], Acc) ->
    {ok, lists:reverse(Acc)};
parse_campaign_entries([Raw | Rest], Acc) ->
    case parse_campaign_entry(Raw) of
        {ok, Height, Data} -> parse_campaign_entries(Rest, [{Height, Data} | Acc]);
        {error, _} = Err -> Err
    end.

%% First four keys required (prompt schema); base_mtp/base_header/
%% chainwork are accepted but currently unused by beamchain's chokepoint
%% (mirrors the shape of mainnet_assumeutxo/0's entries above, which
%% likewise carry only these three fields) — parsed-and-ignored rather
%% than rejected, so a shared fixture built for other impls still loads.
parse_campaign_entry(#{<<"height">> := Height,
                        <<"blockhash">> := BlockHashHex,
                        <<"hash_serialized">> := HashSerHex,
                        <<"m_chain_tx_count">> := ChainTxCount} = Entry)
        when is_integer(Height), Height > 0,
             is_integer(ChainTxCount), ChainTxCount >= 0 ->
    case {parse_display_hex32(BlockHashHex), parse_display_hex32(HashSerHex)} of
        {{ok, BlockHash}, {ok, UtxoHash}} ->
            {ok, Height, #{block_hash => BlockHash,
                           utxo_hash => UtxoHash,
                           chain_tx_count => ChainTxCount}};
        _ ->
            {error, {campaign_assumeutxo_invalid_hex, Entry}}
    end;
parse_campaign_entry(Entry) ->
    {error, {campaign_assumeutxo_missing_or_invalid_fields, Entry}}.

%% Validate + convert a display-order hex hash (as printed by Core /
%% shipped in the campaign JSON) to the same INTERNAL byte-order binary
%% the built-in tables use (display_hex_to_bin/1's convention — see its
%% doc comment below). Rejects anything that isn't exactly 64 hex chars.
parse_display_hex32(HexBin) when is_binary(HexBin), byte_size(HexBin) =:= 64 ->
    HexStr = binary_to_list(HexBin),
    case lists:all(fun is_hex_char/1, HexStr) of
        true -> {ok, display_hex_to_bin(HexStr)};
        false -> error
    end;
parse_display_hex32(_) ->
    error.

is_hex_char(C) when C >= $0, C =< $9 -> true;
is_hex_char(C) when C >= $a, C =< $f -> true;
is_hex_char(C) when C >= $A, C =< $F -> true;
is_hex_char(_) -> false.

%% Refuse a campaign file that has two entries at the same height, or two
%% entries with the same block hash (after byte-order conversion).
check_no_internal_duplicates(Parsed) ->
    Heights = [H || {H, _} <- Parsed],
    Hashes  = [maps:get(block_hash, D) || {_, D} <- Parsed],
    DupHeights = Heights -- lists:usort(Heights),
    DupHashes  = Hashes -- lists:usort(Hashes),
    case {DupHeights, DupHashes} of
        {[], []} -> ok;
        _ -> {error, {campaign_assumeutxo_duplicate, DupHeights, DupHashes}}
    end.

%% Refuse any campaign entry whose height or blockhash matches a built-in
%% (production) entry on ANY network's static table — mainnet, testnet4,
%% or regtest — not just whichever network happens to be configured to
%% run. Campaign data may never override/shadow a production hash, and
%% checking every network (rather than resolving "the" running network,
%% which requires duplicating beamchain_config's env/app-env resolution
%% order at a point in boot before that gen_server exists) is strictly
%% more conservative: it can only reject more, never accept a collision
%% it should have caught. Deliberately excludes the *runtime* regtest
%% registry (register_regtest_assumeutxo/2,4) — that one is expected to
%% be freely reassigned by tests/operators and isn't "production".
check_no_builtin_collision(Parsed) ->
    BuiltIn = maps:merge(maps:merge(mainnet_assumeutxo(), testnet4_assumeutxo()),
                          regtest_assumeutxo()),
    BuiltInHashes = sets:from_list(
        [maps:get(block_hash, V) || V <- maps:values(BuiltIn)]),
    Collisions = [H || {H, #{block_hash := BH}} <- Parsed,
                        (maps:is_key(H, BuiltIn)
                         orelse sets:is_element(BH, BuiltInHashes))],
    case Collisions of
        [] -> ok;
        _  -> {error, {campaign_assumeutxo_collision, Collisions}}
    end.

install_campaign_entries(Parsed) ->
    ensure_campaign_au_table(),
    lists:foreach(fun({Height, Data}) ->
        ets:insert(?CAMPAIGN_AU_TABLE, {Height, Data})
    end, Parsed),
    ok.

ensure_campaign_au_table() ->
    case ets:whereis(?CAMPAIGN_AU_TABLE) of
        undefined ->
            try ets:new(?CAMPAIGN_AU_TABLE,
                        [set, public, named_table, {keypos, 1}])
            catch error:badarg -> ?CAMPAIGN_AU_TABLE end;
        _ ->
            ?CAMPAIGN_AU_TABLE
    end.

%% @doc Snapshot of the current campaign registry as a height-keyed map.
%% Returns #{} (not a lookup/crash) when the table was never created —
%% i.e. whenever HASHHOG_CAMPAIGN_ASSUMEUTXO was unset/empty at startup.
%% This is what makes effective_assumeutxo/1 bit-identical when the flag
%% is off: maps:merge(X, #{}) =:= X.
-spec campaign_assumeutxo_registry() -> map().
campaign_assumeutxo_registry() ->
    case ets:whereis(?CAMPAIGN_AU_TABLE) of
        undefined -> #{};
        _ -> maps:from_list(ets:tab2list(?CAMPAIGN_AU_TABLE))
    end.

%% @doc Remove all campaign AssumeUTXO registrations (test helper).
-spec clear_campaign_assumeutxo() -> ok.
clear_campaign_assumeutxo() ->
    case ets:whereis(?CAMPAIGN_AU_TABLE) of
        undefined -> ok;
        _ -> ets:delete_all_objects(?CAMPAIGN_AU_TABLE), ok
    end.

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
        },
        %% Block 944,183
        944183 => #{
            block_hash => display_hex_to_bin(
                "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"),
            utxo_hash => display_hex_to_bin(
                "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"),
            chain_tx_count => 1334000000
        },
        %% Block 481,823 — Track-B WINDOWED replay: last pre-segwit block
        %% (segwit activates at 481824). block_hash from the 481823 header;
        %% utxo_hash (hash_serialized) + chain_tx_count (nchaintx) come from
        %% the boundary-snapshot result JSON (Core dumptxoutset rollback=481823).
        481823 => #{
            block_hash => display_hex_to_bin(
                "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80"),
            utxo_hash => display_hex_to_bin(
                "25429c30cfa0b6051106c29d15b188d746d8e7ecd184bf34fae1cebe2ea447f4"),
            chain_tx_count => 249036369
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

%% Regtest assumeutxo snapshots — Core-parity entries mirrored verbatim
%% from bitcoin-core/src/kernel/chainparams.cpp CRegTestParams
%% m_assumeutxo_data (heights 110 / 200 / 299). These are the fixed
%% snapshots feature_assumeutxo.py (and this repo's tools/boot-smoke.sh)
%% builds against, so a regtest node must recognize them out of the box —
%% unlike mainnet/testnet4, regtest has no other source of "real" base
%% hashes, but these three ARE Core's own regtest values, not placeholders.
%% Additional ad-hoc regtest snapshots (e.g. for a one-off test harness)
%% still go through register_regtest_assumeutxo/2,4 below; entries there
%% take precedence over these on height collision (see
%% effective_assumeutxo/1).
regtest_assumeutxo() ->
    #{
        %% Height 110 - allows spending first coinbase
        110 => #{
            block_hash => display_hex_to_bin(
                "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397"),
            utxo_hash => display_hex_to_bin(
                "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327"),
            chain_tx_count => 111
        },
        200 => #{
            block_hash => display_hex_to_bin(
                "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"),
            utxo_hash => display_hex_to_bin(
                "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"),
            chain_tx_count => 201
        },
        299 => #{
            block_hash => display_hex_to_bin(
                "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2"),
            utxo_hash => display_hex_to_bin(
                "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2"),
            chain_tx_count => 334
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
