-ifndef(BEAMCHAIN_HRL).
-define(BEAMCHAIN_HRL, true).

%%% -------------------------------------------------------------------
%%% Core data structures for Bitcoin
%%% -------------------------------------------------------------------

-record(block_header, {
    version       :: non_neg_integer(),
    prev_hash     :: binary(),       %% 32 bytes
    merkle_root   :: binary(),       %% 32 bytes
    timestamp     :: non_neg_integer(),
    bits          :: non_neg_integer(),
    nonce         :: non_neg_integer()
}).

-record(outpoint, {
    hash  :: binary(),          %% 32 bytes txid
    index :: non_neg_integer()
}).

-record(tx_in, {
    prev_out   :: #outpoint{},
    script_sig :: binary(),
    sequence   :: non_neg_integer(),
    witness    :: [binary()] | undefined    %% list of witness stack items; undefined = no witness
}).

-record(tx_out, {
    value         :: non_neg_integer(),  %% satoshis
    script_pubkey :: binary()
}).

-record(transaction, {
    version  :: non_neg_integer(),
    inputs   :: [#tx_in{}],
    outputs  :: [#tx_out{}],
    locktime :: non_neg_integer(),
    txid     :: binary() | undefined,
    wtxid    :: binary() | undefined
}).

-record(block, {
    header       :: #block_header{},
    transactions :: [#transaction{}],
    hash         :: binary() | undefined,
    height       :: non_neg_integer() | undefined,
    size         :: non_neg_integer() | undefined,
    weight       :: non_neg_integer() | undefined
}).

-record(utxo, {
    value         :: non_neg_integer(),
    script_pubkey :: binary(),
    is_coinbase   :: boolean(),
    height        :: non_neg_integer()
}).

%%% -------------------------------------------------------------------
%%% Network configuration
%%% -------------------------------------------------------------------

-record(network_params, {
    name               :: atom(),
    magic              :: binary(),     %% 4-byte network magic
    default_port       :: non_neg_integer(),
    rpc_port           :: non_neg_integer(),
    genesis_hash       :: binary(),     %% 32 bytes
    dns_seeds          :: [string()],
    bip34_height       :: non_neg_integer(),
    bip65_height       :: non_neg_integer(),
    bip66_height       :: non_neg_integer(),
    segwit_height      :: non_neg_integer(),
    taproot_height     :: non_neg_integer(),
    pow_limit          :: binary(),     %% 32 bytes, max target
    pow_allow_min_diff :: boolean(),
    subsidy_halving    :: non_neg_integer(),
    bech32_hrp         :: string()
}).

-endif.
