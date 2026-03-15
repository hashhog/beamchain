-ifndef(BEAMCHAIN_PROTOCOL_HRL).
-define(BEAMCHAIN_PROTOCOL_HRL, true).

%%% -------------------------------------------------------------------
%%% Consensus constants
%%% -------------------------------------------------------------------

%% Block limits
-define(MAX_BLOCK_WEIGHT, 4000000).
-define(MAX_BLOCK_SIGOPS_COST, 80000).
-define(WITNESS_SCALE_FACTOR, 4).
-define(MAX_BLOCK_SERIALIZED_SIZE, 4000000).
-define(MIN_TRANSACTION_WEIGHT, 60).

%% Money
-define(MAX_MONEY, 2100000000000000).   %% 21M BTC in satoshis
-define(COIN, 100000000).               %% 1 BTC = 100,000,000 satoshis

%% Coinbase
-define(COINBASE_MATURITY, 100).

%% Difficulty adjustment
-define(DIFFICULTY_ADJUSTMENT_INTERVAL, 2016).
-define(POW_TARGET_SPACING, 600).        %% 10 minutes
-define(POW_TARGET_TIMESPAN, 1209600).   %% 2 weeks

%% Block subsidy
-define(SUBSIDY_HALVING_INTERVAL, 210000).
-define(INITIAL_SUBSIDY, 5000000000).    %% 50 BTC

%%% -------------------------------------------------------------------
%%% Script limits
%%% -------------------------------------------------------------------

-define(MAX_SCRIPT_SIZE, 10000).
-define(MAX_SCRIPT_ELEMENT_SIZE, 520).
-define(MAX_OPS_PER_SCRIPT, 201).
-define(MAX_STACK_SIZE, 1000).
-define(MAX_PUBKEYS_PER_MULTISIG, 20).
-define(MAX_PUBKEYS_PER_MULTI_A, 999).   %% tapscript OP_CHECKSIGADD

%%% -------------------------------------------------------------------
%%% Locktime / sequence
%%% -------------------------------------------------------------------

-define(LOCKTIME_THRESHOLD, 500000000).
-define(SEQUENCE_FINAL, 16#ffffffff).
-define(SEQUENCE_LOCKTIME_DISABLE_FLAG, (1 bsl 31)).
-define(SEQUENCE_LOCKTIME_TYPE_FLAG, (1 bsl 22)).
-define(SEQUENCE_LOCKTIME_MASK, 16#0000ffff).
-define(SEQUENCE_LOCKTIME_GRANULARITY, 9).

%%% -------------------------------------------------------------------
%%% P2P protocol
%%% -------------------------------------------------------------------

-define(PROTOCOL_VERSION, 70016).
-define(MAX_PROTOCOL_MESSAGE_LENGTH, 4000000).
-define(MAX_HEADERS_RESULTS, 2000).
-define(MAX_INV_SIZE, 50000).
-define(MAX_SUBVERSION_LENGTH, 256).

%% Connection limits
-define(MAX_OUTBOUND_FULL_RELAY, 8).
-define(MAX_BLOCK_RELAY_ONLY, 2).
-define(MAX_INBOUND, 117).
-define(DEFAULT_MAX_PEERS, 125).

%% Service flags
-define(NODE_NETWORK, 1).
-define(NODE_BLOOM, 4).
-define(NODE_WITNESS, 8).
-define(NODE_NETWORK_LIMITED, 1024).

%%% -------------------------------------------------------------------
%%% Sighash types
%%% -------------------------------------------------------------------

-define(SIGHASH_ALL, 1).
-define(SIGHASH_NONE, 2).
-define(SIGHASH_SINGLE, 3).
-define(SIGHASH_ANYONECANPAY, 16#80).
-define(SIGHASH_DEFAULT, 0).    %% Taproot only

%%% -------------------------------------------------------------------
%%% Network magic bytes
%%% -------------------------------------------------------------------

-define(MAINNET_MAGIC, <<16#F9, 16#BE, 16#B4, 16#D9>>).
-define(TESTNET_MAGIC, <<16#0B, 16#11, 16#09, 16#07>>).
-define(TESTNET4_MAGIC, <<16#1C, 16#16, 16#3F, 16#28>>).
-define(REGTEST_MAGIC, <<16#FA, 16#BF, 16#B5, 16#DA>>).
-define(SIGNET_MAGIC, <<16#0A, 16#03, 16#CF, 16#40>>).

%%% -------------------------------------------------------------------
%%% Inv type codes
%%% -------------------------------------------------------------------

-define(MSG_TX, 1).
-define(MSG_BLOCK, 2).
-define(MSG_FILTERED_BLOCK, 3).
-define(MSG_CMPCT_BLOCK, 4).
-define(MSG_WITNESS_TX, 16#40000001).
-define(MSG_WITNESS_BLOCK, 16#40000002).
-define(MSG_WITNESS_FLAG, 16#40000000).

%%% -------------------------------------------------------------------
%%% Script verification flags
%%% -------------------------------------------------------------------

-define(SCRIPT_VERIFY_NONE,                 0).
-define(SCRIPT_VERIFY_P2SH,                 (1 bsl 0)).
-define(SCRIPT_VERIFY_STRICTENC,            (1 bsl 1)).
-define(SCRIPT_VERIFY_DERSIG,               (1 bsl 2)).
-define(SCRIPT_VERIFY_LOW_S,                (1 bsl 3)).
-define(SCRIPT_VERIFY_NULLDUMMY,            (1 bsl 4)).
-define(SCRIPT_VERIFY_SIGPUSHONLY,          (1 bsl 5)).
-define(SCRIPT_VERIFY_MINIMALDATA,          (1 bsl 6)).
-define(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, (1 bsl 7)).
-define(SCRIPT_VERIFY_CLEANSTACK,           (1 bsl 8)).
-define(SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,  (1 bsl 9)).
-define(SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,  (1 bsl 10)).
-define(SCRIPT_VERIFY_WITNESS,              (1 bsl 11)).
-define(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, (1 bsl 12)).
-define(SCRIPT_VERIFY_MINIMALIF,            (1 bsl 13)).
-define(SCRIPT_VERIFY_NULLFAIL,             (1 bsl 14)).
-define(SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,   (1 bsl 15)).
-define(SCRIPT_VERIFY_CONST_SCRIPTCODE,     (1 bsl 16)).
-define(SCRIPT_VERIFY_TAPROOT,              (1 bsl 17)).
-define(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, (1 bsl 18)).
-define(SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, (1 bsl 19)).
-define(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE, (1 bsl 20)).

%%% -------------------------------------------------------------------
%%% Policy constants (non-consensus)
%%% -------------------------------------------------------------------

-define(DEFAULT_MIN_RELAY_TX_FEE, 1000).     %% sat/kvB
-define(DEFAULT_MEMPOOL_MAX_SIZE, 300000000). %% 300 MB
-define(MEMPOOL_EXPIRY_HOURS, 336).           %% 14 days
-define(MAX_ANCESTOR_COUNT, 25).
-define(MAX_DESCENDANT_COUNT, 25).
-define(MAX_ANCESTOR_SIZE, 101000).           %% 101 kvB
-define(MAX_DESCENDANT_SIZE, 101000).         %% 101 kvB
-define(MAX_STANDARD_TX_WEIGHT, 400000).      %% 100 kvB
-define(MAX_P2SH_SIGOPS, 15).
-define(MAX_STANDARD_TX_SIGOPS_COST, 16000).

%%% -------------------------------------------------------------------
%%% Package relay constants
%%% -------------------------------------------------------------------

-define(MAX_PACKAGE_COUNT, 25).               %% Max transactions in a package
-define(MAX_PACKAGE_WEIGHT, 404000).          %% Max weight (allows 101 kvB vsize)

%%% -------------------------------------------------------------------
%%% v3/TRUC (Topologically Restricted Until Confirmation) policy
%%% BIP 431 - transactions with nVersion=3 have restricted topology
%%% -------------------------------------------------------------------

-define(TRUC_VERSION, 3).                     %% v3 transactions are TRUC
-define(TRUC_ANCESTOR_LIMIT, 2).              %% Max 1 unconfirmed parent + self
-define(TRUC_DESCENDANT_LIMIT, 2).            %% Max 1 unconfirmed child + self
-define(TRUC_MAX_VSIZE, 10000).               %% Max vsize for any v3 tx
-define(TRUC_CHILD_MAX_VSIZE, 1000).          %% Max vsize for v3 child (has unconf parent)

-endif.
