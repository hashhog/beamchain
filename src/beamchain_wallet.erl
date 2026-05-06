-module(beamchain_wallet).
-behaviour(gen_server).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Dialyzer suppressions for false positives:
%% handle_call({encryptwallet}): do_encrypt_wallet always succeeds per dialyzer;
%%   the {error,_} branch is defensive code kept for future error conditions.
%% generate_keypool/1: master_key=undefined guard is a valid safety net.
%% generate_address_silent/3: change_addr clauses are valid code paths even
%%   though current callers only use receive_addr.
-dialyzer({nowarn_function, [handle_call/3, generate_keypool/1,
                              generate_address_silent/3]}).

%% gen_server API
-export([start_link/0, start_link/1,
         create/0, create/1, create/2,
         load/1, load/2,
         get_new_address/0, get_new_address/1,
         get_change_address/0, get_change_address/1,
         list_addresses/0,
         get_balance/0,
         get_private_key/1,
         get_wallet_info/0]).

%% Multi-wallet API (wallet name as first parameter)
-export([get_new_address/2,
         get_change_address/2,
         list_addresses/1,
         get_balance/1,
         get_private_key/2,
         get_wallet_info/1,
         is_locked/1,
         import_address/5]).

%% Wallet encryption API
-export([encryptwallet/1,
         walletpassphrase/2,
         walletlock/0,
         is_locked/0]).

%% Encryption helpers (exported for testing)
-export([derive_encryption_key/2, pkcs7_pad/2, pkcs7_unpad/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

%% BIP 32 HD key derivation (pure functions)
-export([master_from_seed/1,
         derive_child/2,
         derive_path/2,
         parse_path/1]).

%% Key utilities
-export([pubkey_to_hash160/1,
         privkey_to_pubkey/1,
         privkey_to_xonly/1]).

%% Address generation (pure functions)
-export([pubkey_to_p2wpkh/2,
         pubkey_to_p2tr/2,
         pubkey_to_p2pkh/2]).

%% Transaction signing
-export([sign_transaction/3,
         build_transaction/3]).

%% PSBT (BIP 174/370)
-export([create_psbt/2,
         add_witness_utxo/3,
         sign_psbt/2,
         finalize_psbt/1,
         encode_psbt/1,
         decode_psbt/1]).

%% Coin selection
-export([select_coins/3]).

%% Wallet UTXO tracking
-export([scan_utxos_for_script/1,
         register_wallet_script/2,
         is_wallet_script/1,
         add_wallet_utxo/5,
         spend_wallet_utxo/2,
         get_wallet_utxos/0,
         get_wallet_balance/0,
         scan_block_for_wallet/1]).

%% Keypool
-export([get_keypool_size/0]).

%% Coin lock state (lockunspent / listlockunspent).  Mirrors Core's
%% CWallet::LockCoin / UnlockCoin / ListLockedCoins (wallet/wallet.cpp).
-export([lock_coin/3,
         unlock_coin/3,
         unlock_all_coins/1,
         is_locked_coin/2,
         list_locked_coins/1]).

-define(SERVER, ?MODULE).
-define(HARDENED, 16#80000000).

%% ETS table for wallet UTXOs: {Txid, Vout} -> {Value, ScriptPubKey, Height}
-define(WALLET_UTXO_TABLE, beamchain_wallet_utxos).
%% ETS table for script -> address lookup
-define(WALLET_SCRIPT_TABLE, beamchain_wallet_scripts).

%%% -------------------------------------------------------------------
%%% HD key record
%%% -------------------------------------------------------------------

-record(hd_key, {
    private_key  :: binary() | undefined,  %% 32 bytes
    public_key   :: binary(),              %% 33 bytes compressed
    chain_code   :: binary(),              %% 32 bytes
    depth        :: non_neg_integer(),
    fingerprint  :: binary(),              %% 4 bytes (parent key fingerprint)
    child_index  :: non_neg_integer()
}).

-export_type([hd_key/0]).
-type hd_key() :: #hd_key{}.

%%% -------------------------------------------------------------------
%%% Wallet gen_server state
%%% -------------------------------------------------------------------

-record(wallet_state, {
    wallet_name    :: binary(),             %% wallet name (<<>> for default)
    master_key     :: #hd_key{} | undefined,
    seed           :: binary() | undefined,
    network        :: atom(),
    coin_type      :: non_neg_integer(),    %% 0' mainnet, 1' testnet
    next_receive   :: #{atom() => non_neg_integer()},  %% type -> index
    next_change    :: #{atom() => non_neg_integer()},
    addresses      :: [map()],              %% list of address entries
    wallet_file    :: string() | undefined,
    passphrase     :: binary() | undefined, %% kept in memory for re-saving
    keypool_size   :: non_neg_integer(),    %% lookahead pool size
    gap_limit      :: non_neg_integer(),    %% BIP 44 gap limit
    %% Encryption state
    encrypted      :: boolean(),            %% true if wallet is encrypted
    locked         :: boolean(),            %% true if wallet is locked (keys unavailable)
    encrypted_seed :: binary() | undefined, %% AES-256-CBC encrypted seed
    encryption_salt :: binary() | undefined, %% 16-byte salt for PBKDF2
    lock_timer_ref :: reference() | undefined,  %% auto-lock timer reference
    %% Locked coins (lockunspent / listlockunspent).  Memory-only set of
    %% {Txid, Vout} pairs that coin selection must skip.  Mirrors Core's
    %% CWallet::setLockedCoins (wallet/wallet.h); cleared on process exit
    %% (we do not yet persist with persistent=true).
    locked_coins = sets:new() :: sets:set()
}).

%% Default keypool size (1000 addresses lookahead per type)
-define(DEFAULT_KEYPOOL_SIZE, 1000).
%% Default gap limit (20 unused addresses before stopping lookahead)
-define(DEFAULT_GAP_LIMIT, 20).

%%% ===================================================================
%%% gen_server API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [<<>>], []).

%% @doc Start a wallet with a specific name.
%% Used by beamchain_wallet_sup for multi-wallet support.
-spec start_link(binary()) -> {ok, pid()} | {error, term()}.
start_link(WalletName) when is_binary(WalletName) ->
    %% Don't register with a name - managed by wallet_sup registry
    gen_server:start_link(?MODULE, [WalletName], []).

%% @doc Create a new wallet with a random 32-byte seed.
-spec create() -> {ok, Seed :: binary()} | {error, term()}.
create() ->
    Seed = crypto:strong_rand_bytes(32),
    create(Seed).

%% @doc Create wallet from a specific seed.
-spec create(binary()) -> {ok, binary()} | {error, term()}.
create(Seed) ->
    create(Seed, undefined).

%% @doc Create wallet from seed with optional passphrase for encryption.
-spec create(binary(), binary() | undefined) -> {ok, binary()} | {error, term()}.
create(Seed, Passphrase) ->
    gen_server:call(?SERVER, {create, Seed, Passphrase}).

%% @doc Load a wallet from file.
-spec load(string()) -> ok | {error, term()}.
load(FilePath) ->
    load(FilePath, undefined).

%% @doc Load wallet from file with passphrase.
-spec load(string(), binary() | undefined) -> ok | {error, term()}.
load(FilePath, Passphrase) ->
    gen_server:call(?SERVER, {load, FilePath, Passphrase}).

%% @doc Generate a new receiving address (default: P2WPKH).
-spec get_new_address() -> {ok, string()}.
get_new_address() ->
    get_new_address(p2wpkh).

%% @doc Generate a new receiving address of the given type.
-spec get_new_address(p2wpkh | p2tr | p2pkh) -> {ok, string()}.
get_new_address(Type) ->
    gen_server:call(?SERVER, {get_new_address, Type}).

%% @doc Generate a new change address (default: P2WPKH).
-spec get_change_address() -> {ok, string()}.
get_change_address() ->
    get_change_address(p2wpkh).

-spec get_change_address(p2wpkh | p2tr | p2pkh) -> {ok, string()}.
get_change_address(Type) ->
    gen_server:call(?SERVER, {get_change_address, Type}).

%% @doc List all generated addresses.
-spec list_addresses() -> {ok, [map()]}.
list_addresses() ->
    gen_server:call(?SERVER, list_addresses).

%% @doc Get total balance of wallet addresses from UTXO set.
-spec get_balance() -> {ok, non_neg_integer()}.
get_balance() ->
    gen_server:call(?SERVER, get_balance).

%% @doc Get private key for a specific address (for external signing).
-spec get_private_key(string()) -> {ok, binary()} | {error, not_found}.
get_private_key(Address) ->
    gen_server:call(?SERVER, {get_private_key, Address}).

%% @doc Get wallet info map.
-spec get_wallet_info() -> {ok, map()}.
get_wallet_info() ->
    gen_server:call(?SERVER, get_wallet_info).

%% @doc Get keypool size (number of lookahead addresses).
-spec get_keypool_size() -> {ok, non_neg_integer()}.
get_keypool_size() ->
    gen_server:call(?SERVER, get_keypool_size).

%%% ===================================================================
%%% Wallet encryption API
%%% ===================================================================

%% @doc Encrypt the wallet with a passphrase.
%% After encryption, the wallet will be locked and require walletpassphrase
%% to unlock for signing operations. This is a one-way operation.
-spec encryptwallet(binary()) -> ok | {error, term()}.
encryptwallet(Passphrase) when is_binary(Passphrase), byte_size(Passphrase) >= 1 ->
    gen_server:call(?SERVER, {encryptwallet, Passphrase}).

%% @doc Unlock the wallet for the specified timeout (in seconds).
%% Decrypts the master key into memory for signing operations.
%% After the timeout, the wallet automatically locks.
-spec walletpassphrase(binary(), non_neg_integer()) -> ok | {error, term()}.
walletpassphrase(Passphrase, Timeout) when is_binary(Passphrase), Timeout > 0 ->
    gen_server:call(?SERVER, {walletpassphrase, Passphrase, Timeout}).

%% @doc Immediately lock the wallet.
%% Clears the decrypted master key from memory.
-spec walletlock() -> ok | {error, term()}.
walletlock() ->
    gen_server:call(?SERVER, walletlock).

%% @doc Check if the wallet is locked.
-spec is_locked() -> boolean().
is_locked() ->
    gen_server:call(?SERVER, is_locked).

%%% ===================================================================
%%% Coin lock state (lockunspent / listlockunspent)
%%% ===================================================================
%%
%% Mirrors Bitcoin Core's CWallet::LockCoin / UnlockCoin / ListLockedCoins
%% (`wallet/wallet.cpp`).  Beamchain stores the lock set in memory only —
%% Core's `persistent=true` flag is accepted at the RPC layer for parity
%% but does not yet write to disk (TODO: persistence).  Locks are cleared
%% on process exit, matching Core's `persistent=false` default.

%% @doc Mark `{Txid, Vout}` as temporarily unspendable in the given wallet.
%% Returns `ok` even when the coin is already locked; the RPC layer is
%% responsible for the "already locked" error per Core's
%% `wallet/rpc/coins.cpp:lockunspent`.
-spec lock_coin(pid(), binary(), non_neg_integer()) -> ok.
lock_coin(Pid, Txid, Vout) when is_pid(Pid), is_binary(Txid),
                                is_integer(Vout), Vout >= 0 ->
    gen_server:call(Pid, {lock_coin, Txid, Vout}).

%% @doc Remove the lock on `{Txid, Vout}`.
%% Returns `{error, not_locked}` if the coin was never locked, matching
%% Core's "expected locked output" check.
-spec unlock_coin(pid(), binary(), non_neg_integer()) ->
    ok | {error, not_locked}.
unlock_coin(Pid, Txid, Vout) when is_pid(Pid), is_binary(Txid),
                                  is_integer(Vout), Vout >= 0 ->
    gen_server:call(Pid, {unlock_coin, Txid, Vout}).

%% @doc Clear all locks (lockunspent true with no transactions).
-spec unlock_all_coins(pid()) -> ok.
unlock_all_coins(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, unlock_all_coins).

%% @doc Check whether `{Txid, Vout}` is currently locked.
-spec is_locked_coin(pid(), {binary(), non_neg_integer()}) -> boolean().
is_locked_coin(Pid, {Txid, Vout}) when is_pid(Pid), is_binary(Txid) ->
    gen_server:call(Pid, {is_locked_coin, Txid, Vout}).

%% @doc List all currently-locked coins as `[{Txid, Vout}]`.
-spec list_locked_coins(pid()) -> [{binary(), non_neg_integer()}].
list_locked_coins(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, list_locked_coins).

%%% ===================================================================
%%% Multi-wallet API (wallet specified by pid)
%%% ===================================================================

%% @doc Get a new address from a specific wallet.
-spec get_new_address(pid(), p2wpkh | p2tr | p2pkh) -> {ok, string()} | {error, term()}.
get_new_address(Pid, Type) when is_pid(Pid) ->
    gen_server:call(Pid, {get_new_address, Type}).

%% @doc Get a change address from a specific wallet.
-spec get_change_address(pid(), p2wpkh | p2tr | p2pkh) -> {ok, string()} | {error, term()}.
get_change_address(Pid, Type) when is_pid(Pid) ->
    gen_server:call(Pid, {get_change_address, Type}).

%% @doc List all addresses from a specific wallet.
-spec list_addresses(pid()) -> {ok, [map()]} | {error, term()}.
list_addresses(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, list_addresses).

%% @doc Get balance from a specific wallet.
-spec get_balance(pid()) -> {ok, non_neg_integer()} | {error, term()}.
get_balance(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, get_balance).

%% @doc Get private key from a specific wallet.
-spec get_private_key(pid(), string()) -> {ok, binary()} | {error, term()}.
get_private_key(Pid, Address) when is_pid(Pid) ->
    gen_server:call(Pid, {get_private_key, Address}).

%% @doc Get wallet info from a specific wallet.
-spec get_wallet_info(pid()) -> {ok, map()} | {error, term()}.
get_wallet_info(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, get_wallet_info).

%% @doc Check if a specific wallet is locked.
-spec is_locked(pid()) -> boolean().
is_locked(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, is_locked).

%% @doc Import a watch-only address into the wallet.
%% Stub — importdescriptors watch-only tracking is not yet implemented.
-spec import_address(pid(), string(), binary(), boolean(), binary()) -> ok.
import_address(_Pid, _Address, _Label, _Internal, _Timestamp) ->
    %% TODO: implement watch-only address tracking
    ok.

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    init([<<>>]);
init([WalletName]) when is_binary(WalletName) ->
    Network = try beamchain_config:network()
              catch _:_ -> mainnet
              end,
    CoinType = case Network of
        mainnet -> 0 + ?HARDENED;
        _       -> 1 + ?HARDENED
    end,
    %% Create ETS tables for wallet UTXOs and script lookup
    init_ets_tables(),
    {ok, #wallet_state{
        wallet_name  = WalletName,
        network      = Network,
        coin_type    = CoinType,
        next_receive = #{p2wpkh => 0, p2tr => 0, p2pkh => 0},
        next_change  = #{p2wpkh => 0, p2tr => 0, p2pkh => 0},
        addresses    = [],
        keypool_size = ?DEFAULT_KEYPOOL_SIZE,
        gap_limit    = ?DEFAULT_GAP_LIMIT,
        encrypted    = false,
        locked       = false,
        encrypted_seed = undefined,
        encryption_salt = undefined,
        lock_timer_ref = undefined
    }}.

%% @doc Initialize ETS tables for wallet UTXO tracking.
init_ets_tables() ->
    case ets:whereis(?WALLET_UTXO_TABLE) of
        undefined ->
            ets:new(?WALLET_UTXO_TABLE, [named_table, set, public,
                                          {read_concurrency, true}]);
        _ -> ok
    end,
    case ets:whereis(?WALLET_SCRIPT_TABLE) of
        undefined ->
            ets:new(?WALLET_SCRIPT_TABLE, [named_table, set, public,
                                            {read_concurrency, true}]);
        _ -> ok
    end,
    ok.

handle_call({create, Seed, Passphrase}, _From, State) ->
    MasterKey = master_from_seed(Seed),
    WalletDir = wallet_dir(State#wallet_state.network),
    ok = filelib:ensure_dir(WalletDir ++ "/"),
    WalletFile = WalletDir ++ "/wallet.json",
    NewState0 = State#wallet_state{
        master_key  = MasterKey,
        seed        = Seed,
        wallet_file = WalletFile,
        passphrase  = Passphrase,
        keypool_size = ?DEFAULT_KEYPOOL_SIZE,
        gap_limit    = ?DEFAULT_GAP_LIMIT
    },
    %% Generate initial keypool of lookahead addresses
    NewState = generate_keypool(NewState0),
    ok = save_wallet(NewState),
    {reply, {ok, Seed}, NewState};

handle_call({load, FilePath, Passphrase}, _From, State) ->
    case load_wallet_file(FilePath, Passphrase) of
        {ok, WalletData} ->
            Addrs = maps:get(<<"addresses">>, WalletData, []),
            NextRecv = maps:get(<<"next_receive">>, WalletData,
                                #{<<"p2wpkh">> => 0, <<"p2tr">> => 0,
                                  <<"p2pkh">> => 0}),
            NextChg = maps:get(<<"next_change">>, WalletData,
                               #{<<"p2wpkh">> => 0, <<"p2tr">> => 0,
                                 <<"p2pkh">> => 0}),
            %% Check if wallet is encrypted at the JSON level
            IsEncrypted = maps:get(<<"encrypted">>, WalletData, false),
            NewState = case IsEncrypted of
                true ->
                    %% Encrypted wallet: load encrypted seed, start locked
                    EncSeedHex = maps:get(<<"encrypted_seed">>, WalletData),
                    EncSaltHex = maps:get(<<"encryption_salt">>, WalletData),
                    EncSeed = hex_decode(EncSeedHex),
                    EncSalt = hex_decode(EncSaltHex),
                    State#wallet_state{
                        master_key  = undefined,
                        seed        = undefined,
                        wallet_file = FilePath,
                        passphrase  = Passphrase,
                        addresses   = Addrs,
                        next_receive = decode_index_map(NextRecv),
                        next_change  = decode_index_map(NextChg),
                        encrypted   = true,
                        locked      = true,
                        encrypted_seed = EncSeed,
                        encryption_salt = EncSalt
                    };
                false ->
                    %% Unencrypted wallet: load seed directly
                    SeedHex = maps:get(<<"seed">>, WalletData),
                    Seed = hex_decode(SeedHex),
                    MasterKey = master_from_seed(Seed),
                    State#wallet_state{
                        master_key  = MasterKey,
                        seed        = Seed,
                        wallet_file = FilePath,
                        passphrase  = Passphrase,
                        addresses   = Addrs,
                        next_receive = decode_index_map(NextRecv),
                        next_change  = decode_index_map(NextChg),
                        encrypted   = false,
                        locked      = false
                    }
            end,
            {reply, ok, NewState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call({get_new_address, _Type}, _From,
            #wallet_state{master_key = undefined} = State) ->
    {reply, {error, no_wallet}, State};
handle_call({get_new_address, Type}, _From, State) ->
    {Address, NewState} = generate_address(Type, receive_addr, State),
    ok = save_wallet(NewState),
    {reply, {ok, Address}, NewState};

handle_call({get_change_address, _Type}, _From,
            #wallet_state{master_key = undefined} = State) ->
    {reply, {error, no_wallet}, State};
handle_call({get_change_address, Type}, _From, State) ->
    {Address, NewState} = generate_address(Type, change_addr, State),
    ok = save_wallet(NewState),
    {reply, {ok, Address}, NewState};

handle_call(list_addresses, _From, State) ->
    {reply, {ok, State#wallet_state.addresses}, State};

handle_call(get_balance, _From, #wallet_state{addresses = Addrs,
                                               network = Network} = State) ->
    Balance = lists:foldl(fun(AddrInfo, Acc) ->
        Address = maps:get(<<"address">>, AddrInfo),
        case beamchain_address:address_to_script(binary_to_list(Address),
                                                  Network) of
            {ok, ScriptPubKey} ->
                Acc + scan_utxos_for_script(ScriptPubKey);
            _ ->
                Acc
        end
    end, 0, Addrs),
    {reply, {ok, Balance}, State};

handle_call({get_private_key, _Address}, _From,
            #wallet_state{locked = true} = State) ->
    {reply, {error, wallet_locked}, State};
handle_call({get_private_key, Address}, _From, State) ->
    AddrBin = case is_list(Address) of
        true -> list_to_binary(Address);
        false -> Address
    end,
    case find_address(AddrBin, State) of
        {ok, AddrInfo} ->
            Path = maps:get(<<"path">>, AddrInfo),
            PathList = parse_path(binary_to_list(Path)),
            Key = derive_path(State#wallet_state.master_key, PathList),
            {reply, {ok, Key#hd_key.private_key}, State};
        not_found ->
            {reply, {error, not_found}, State}
    end;

handle_call(get_wallet_info, _From, State) ->
    Info = #{
        wallet_name => State#wallet_state.wallet_name,
        network    => State#wallet_state.network,
        addresses  => length(State#wallet_state.addresses),
        has_seed   => State#wallet_state.seed =/= undefined,
        wallet_file => State#wallet_state.wallet_file,
        keypool_size => State#wallet_state.keypool_size,
        gap_limit    => State#wallet_state.gap_limit,
        encrypted    => State#wallet_state.encrypted,
        locked       => State#wallet_state.locked
    },
    {reply, {ok, Info}, State};

handle_call(get_keypool_size, _From, State) ->
    %% Return the actual number of addresses in the keypool
    {reply, {ok, length(State#wallet_state.addresses)}, State};

%% Encryption: encryptwallet
handle_call({encryptwallet, _Passphrase}, _From,
            #wallet_state{seed = undefined} = State) ->
    {reply, {error, no_wallet}, State};
handle_call({encryptwallet, _Passphrase}, _From,
            #wallet_state{encrypted = true} = State) ->
    {reply, {error, already_encrypted}, State};
handle_call({encryptwallet, Passphrase}, _From, State) ->
    case do_encrypt_wallet(State, Passphrase) of
        {ok, NewState} ->
            ok = save_wallet(NewState),
            {reply, ok, NewState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

%% Encryption: walletpassphrase (unlock)
handle_call({walletpassphrase, _Passphrase, _Timeout}, _From,
            #wallet_state{encrypted = false} = State) ->
    {reply, {error, not_encrypted}, State};
handle_call({walletpassphrase, _Passphrase, _Timeout}, _From,
            #wallet_state{locked = false} = State) ->
    {reply, {error, already_unlocked}, State};
handle_call({walletpassphrase, Passphrase, Timeout}, _From, State) ->
    case do_unlock_wallet(State, Passphrase, Timeout) of
        {ok, NewState} ->
            {reply, ok, NewState};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

%% Encryption: walletlock
handle_call(walletlock, _From, #wallet_state{encrypted = false} = State) ->
    {reply, {error, not_encrypted}, State};
handle_call(walletlock, _From, State) ->
    NewState = do_lock_wallet(State),
    {reply, ok, NewState};

%% Encryption: is_locked
handle_call(is_locked, _From, State) ->
    {reply, State#wallet_state.locked, State};

%% Coin lock state (lockunspent / listlockunspent).
handle_call({lock_coin, Txid, Vout}, _From,
            #wallet_state{locked_coins = Set} = State) ->
    NewSet = sets:add_element({Txid, Vout}, Set),
    {reply, ok, State#wallet_state{locked_coins = NewSet}};
handle_call({unlock_coin, Txid, Vout}, _From,
            #wallet_state{locked_coins = Set} = State) ->
    Key = {Txid, Vout},
    case sets:is_element(Key, Set) of
        true ->
            NewSet = sets:del_element(Key, Set),
            {reply, ok, State#wallet_state{locked_coins = NewSet}};
        false ->
            {reply, {error, not_locked}, State}
    end;
handle_call(unlock_all_coins, _From, State) ->
    {reply, ok, State#wallet_state{locked_coins = sets:new()}};
handle_call({is_locked_coin, Txid, Vout}, _From,
            #wallet_state{locked_coins = Set} = State) ->
    {reply, sets:is_element({Txid, Vout}, Set), State};
handle_call(list_locked_coins, _From,
            #wallet_state{locked_coins = Set} = State) ->
    {reply, sets:to_list(Set), State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(wallet_lock, State) ->
    %% Auto-lock timer fired
    logger:info("wallet: auto-locking after timeout"),
    NewState = do_lock_wallet(State),
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    %% Clear sensitive data on shutdown
    case State#wallet_state.seed of
        undefined -> ok;
        Seed when is_binary(Seed) ->
            %% Overwrite seed memory (best effort)
            _ = crypto:strong_rand_bytes(byte_size(Seed)),
            ok
    end,
    ok.

%%% ===================================================================
%%% Keypool generation
%%% ===================================================================

%% @doc Generate a keypool of lookahead addresses for UTXO detection.
%% Generates up to keypool_size addresses for each type (P2WPKH primary).
-spec generate_keypool(#wallet_state{}) -> #wallet_state{}.
generate_keypool(#wallet_state{master_key = undefined} = State) ->
    State;
generate_keypool(State) ->
    %% Generate keypool for P2WPKH (native SegWit) - the primary type
    %% For performance, only generate P2WPKH keypool by default
    KeypoolSize = State#wallet_state.keypool_size,
    generate_keypool_for_type(p2wpkh, receive_addr, KeypoolSize, State).

%% @doc Generate keypool addresses for a specific type and direction.
-spec generate_keypool_for_type(atom(), receive_addr | change_addr,
                                 non_neg_integer(), #wallet_state{}) ->
    #wallet_state{}.
generate_keypool_for_type(_Type, _Direction, 0, State) ->
    State;
generate_keypool_for_type(Type, Direction, Count, State) ->
    {_Address, NewState} = generate_address_silent(Type, Direction, State),
    generate_keypool_for_type(Type, Direction, Count - 1, NewState).

%% @doc Generate address without saving (for keypool initialization).
%% Same as generate_address but doesn't trigger a wallet save.
generate_address_silent(Type, Direction, State) ->
    #wallet_state{master_key = MasterKey, coin_type = CoinType,
                  network = Network} = State,
    {Purpose, ChainIdx, IndexMap} = case Direction of
        receive_addr ->
            {purpose_for_type(Type), 0,
             State#wallet_state.next_receive};
        change_addr ->
            {purpose_for_type(Type), 1,
             State#wallet_state.next_change}
    end,
    Index = maps:get(Type, IndexMap, 0),
    Path = [Purpose, CoinType, ?HARDENED, ChainIdx, Index],
    Key = derive_path(MasterKey, Path),
    Address = make_address(Type, Key#hd_key.public_key, Network),
    PathStr = format_path(Path),
    AddrEntry = #{
        <<"address">> => list_to_binary(Address),
        <<"path">>    => list_to_binary(PathStr),
        <<"type">>    => atom_to_binary(Type, utf8),
        <<"change">>  => ChainIdx =:= 1
    },
    %% Register the script for UTXO tracking
    {ok, ScriptPubKey} = beamchain_address:address_to_script(Address, Network),
    register_wallet_script(ScriptPubKey, list_to_binary(Address)),
    NewIndexMap = IndexMap#{Type => Index + 1},
    NewState = case Direction of
        receive_addr ->
            State#wallet_state{
                next_receive = NewIndexMap,
                addresses    = State#wallet_state.addresses ++ [AddrEntry]
            };
        change_addr ->
            State#wallet_state{
                next_change = NewIndexMap,
                addresses   = State#wallet_state.addresses ++ [AddrEntry]
            }
    end,
    {Address, NewState}.

%%% ===================================================================
%%% Address generation
%%% ===================================================================

generate_address(Type, Direction, State) ->
    #wallet_state{master_key = MasterKey, coin_type = CoinType,
                  network = Network} = State,
    {Purpose, ChainIdx, IndexMap} = case Direction of
        receive_addr ->
            {purpose_for_type(Type), 0,
             State#wallet_state.next_receive};
        change_addr ->
            {purpose_for_type(Type), 1,
             State#wallet_state.next_change}
    end,
    Index = maps:get(Type, IndexMap, 0),
    %% Derive: m / purpose' / coin_type' / 0' / chain / index
    Path = [Purpose, CoinType, ?HARDENED, ChainIdx, Index],
    Key = derive_path(MasterKey, Path),
    Address = make_address(Type, Key#hd_key.public_key, Network),
    PathStr = format_path(Path),
    AddrEntry = #{
        <<"address">> => list_to_binary(Address),
        <<"path">>    => list_to_binary(PathStr),
        <<"type">>    => atom_to_binary(Type, utf8),
        <<"change">>  => ChainIdx =:= 1
    },
    %% Register the script for UTXO tracking
    {ok, ScriptPubKey} = beamchain_address:address_to_script(Address, Network),
    register_wallet_script(ScriptPubKey, list_to_binary(Address)),
    NewIndexMap = IndexMap#{Type => Index + 1},
    NewState = case Direction of
        receive_addr ->
            State#wallet_state{
                next_receive = NewIndexMap,
                addresses    = State#wallet_state.addresses ++ [AddrEntry]
            };
        change_addr ->
            State#wallet_state{
                next_change = NewIndexMap,
                addresses   = State#wallet_state.addresses ++ [AddrEntry]
            }
    end,
    {Address, NewState}.

purpose_for_type(p2wpkh) -> 84 + ?HARDENED;
purpose_for_type(p2tr)   -> 86 + ?HARDENED;
purpose_for_type(p2pkh)  -> 44 + ?HARDENED.

make_address(p2wpkh, PubKey, Network) ->
    pubkey_to_p2wpkh(PubKey, Network);
make_address(p2tr, PubKey, Network) ->
    pubkey_to_p2tr(PubKey, Network);
make_address(p2pkh, PubKey, Network) ->
    pubkey_to_p2pkh(PubKey, Network).

format_path(Indices) ->
    Parts = lists:map(fun(I) ->
        case I >= ?HARDENED of
            true  -> integer_to_list(I - ?HARDENED) ++ "'";
            false -> integer_to_list(I)
        end
    end, Indices),
    "m/" ++ string:join(Parts, "/").

%%% ===================================================================
%%% Address encoding (pure functions)
%%% ===================================================================

%% @doc Generate a P2WPKH (native SegWit) address from a compressed pubkey.
-spec pubkey_to_p2wpkh(binary(), atom()) -> string().
pubkey_to_p2wpkh(PubKey, Network) when byte_size(PubKey) =:= 33 ->
    WitnessProg = beamchain_crypto:hash160(PubKey),
    Hrp = bech32_hrp(Network),
    FiveBit = beamchain_address:convert_bits(
        binary_to_list(WitnessProg), 8, 5, true),
    beamchain_address:bech32_encode(Hrp, [0 | FiveBit]).

%% @doc Generate a P2TR (Taproot) address from a compressed pubkey.
%% Applies the BIP 341 tweak for key-path spending.
-spec pubkey_to_p2tr(binary(), atom()) -> string().
pubkey_to_p2tr(PubKey, Network) when byte_size(PubKey) =:= 33 ->
    %% Get x-only pubkey (drop prefix byte)
    <<_Prefix:8, XOnly:32/binary>> = PubKey,
    %% Apply BIP 341 tweak: t = tagged_hash("TapTweak", x_only)
    Tweak = beamchain_crypto:tagged_hash(<<"TapTweak">>, XOnly),
    %% output_key = pubkey + t*G (x-only result)
    {ok, OutputKey, _Parity} =
        beamchain_crypto:xonly_pubkey_tweak_add(XOnly, Tweak),
    Hrp = bech32_hrp(Network),
    FiveBit = beamchain_address:convert_bits(
        binary_to_list(OutputKey), 8, 5, true),
    beamchain_address:bech32m_encode(Hrp, [1 | FiveBit]).

%% @doc Generate a P2PKH (legacy) address from a compressed pubkey.
-spec pubkey_to_p2pkh(binary(), atom()) -> string().
pubkey_to_p2pkh(PubKey, Network) when byte_size(PubKey) =:= 33 ->
    Hash = beamchain_crypto:hash160(PubKey),
    Version = case Network of
        mainnet -> 16#00;
        _       -> 16#6f
    end,
    beamchain_address:base58check_encode(Version, Hash).

bech32_hrp(mainnet)  -> "bc";
bech32_hrp(testnet)  -> "tb";
bech32_hrp(testnet4) -> "tb";
bech32_hrp(signet)   -> "tb";
bech32_hrp(regtest)  -> "bcrt".

%%% ===================================================================
%%% Transaction building
%%% ===================================================================

%% @doc Build an unsigned transaction from inputs and outputs.
%% Inputs: [{Txid, Vout, Utxo}] where Utxo is #utxo{}.
%% Outputs: [{Address, Amount}] where Address is a string.
-spec build_transaction([{binary(), non_neg_integer(), #utxo{}}],
                        [{string(), non_neg_integer()}],
                        atom()) ->
    {ok, #transaction{}} | {error, term()}.
build_transaction(Inputs, Outputs, Network) ->
    TxIns = lists:map(fun({Txid, Vout, _Utxo}) ->
        #tx_in{
            prev_out  = #outpoint{hash = Txid, index = Vout},
            script_sig = <<>>,
            sequence  = 16#fffffffd,  %% signal RBF
            witness   = []
        }
    end, Inputs),
    TxOuts = lists:map(fun({Address, Amount}) ->
        {ok, Script} = beamchain_address:address_to_script(Address, Network),
        #tx_out{value = Amount, script_pubkey = Script}
    end, Outputs),
    Tx = #transaction{
        version  = 2,
        inputs   = TxIns,
        outputs  = TxOuts,
        locktime = 0
    },
    {ok, Tx}.

%%% ===================================================================
%%% Transaction signing
%%% ===================================================================

%% @doc Sign a transaction given private keys and the UTXOs being spent.
%% PrivKeys must be ordered to match inputs.
%% InputUtxos: [#utxo{}] — the UTXOs being spent by each input.
-spec sign_transaction(#transaction{}, [#utxo{}], [binary()]) ->
    {ok, #transaction{}}.
sign_transaction(Tx, InputUtxos, PrivKeys) ->
    NumInputs = length(Tx#transaction.inputs),
    NumInputs = length(InputUtxos),
    NumInputs = length(PrivKeys),
    %% Build prev_outs list for taproot sighash (needs all amounts + scripts)
    PrevOuts = [{U#utxo.value, U#utxo.script_pubkey} || U <- InputUtxos],
    SignedInputs = lists:map(fun(Idx) ->
        Input = lists:nth(Idx + 1, Tx#transaction.inputs),
        Utxo = lists:nth(Idx + 1, InputUtxos),
        PrivKey = lists:nth(Idx + 1, PrivKeys),
        sign_input(Tx, Idx, Input, Utxo, PrivKey, PrevOuts)
    end, lists:seq(0, NumInputs - 1)),
    {ok, Tx#transaction{inputs = SignedInputs}}.

%% Sign a single input based on the scriptPubKey type.
sign_input(Tx, InputIndex, Input, Utxo, PrivKey, PrevOuts) ->
    ScriptPubKey = Utxo#utxo.script_pubkey,
    case beamchain_address:classify_script(ScriptPubKey) of
        p2wpkh ->
            sign_p2wpkh(Tx, InputIndex, Input, Utxo, PrivKey);
        p2pkh ->
            sign_p2pkh(Tx, InputIndex, Input, Utxo, PrivKey);
        p2tr ->
            sign_p2tr(Tx, InputIndex, Input, PrivKey, PrevOuts);
        p2sh ->
            %% P2SH-P2WPKH (wrapped segwit)
            sign_p2sh_p2wpkh(Tx, InputIndex, Input, Utxo, PrivKey);
        _Other ->
            error({unsupported_script_type, _Other})
    end.

%% --- P2WPKH signing ---
sign_p2wpkh(Tx, InputIndex, Input, Utxo, PrivKey) ->
    PubKey = privkey_to_pubkey(PrivKey),
    %% scriptCode for P2WPKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    PkHash = beamchain_crypto:hash160(PubKey),
    ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
    %% BIP 143 sighash
    SigHash = beamchain_script:sighash_witness_v0(
        Tx, InputIndex, ScriptCode, Utxo#utxo.value, ?SIGHASH_ALL),
    {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
    %% Witness: [sig || sighash_type, pubkey]
    SigWithType = <<DerSig/binary, ?SIGHASH_ALL>>,
    Input#tx_in{
        script_sig = <<>>,
        witness    = [SigWithType, PubKey]
    }.

%% --- P2PKH signing ---
sign_p2pkh(Tx, InputIndex, Input, _Utxo, PrivKey) ->
    PubKey = privkey_to_pubkey(PrivKey),
    PkHash = beamchain_crypto:hash160(PubKey),
    ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
    %% Legacy sighash
    SigHash = beamchain_script:sighash_legacy(
        Tx, InputIndex, ScriptCode, ?SIGHASH_ALL),
    {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
    SigWithType = <<DerSig/binary, ?SIGHASH_ALL>>,
    %% scriptSig: <sig> <pubkey>
    ScriptSig = push_data(SigWithType, <<(push_data(PubKey, <<>>))/binary>>),
    Input#tx_in{
        script_sig = ScriptSig,
        witness    = []
    }.

%% --- P2TR key-path signing ---
sign_p2tr(Tx, InputIndex, Input, PrivKey, PrevOuts) ->
    %% Taproot sighash (BIP 341)
    SigHash = beamchain_script:sighash_taproot(
        Tx, InputIndex, PrevOuts, ?SIGHASH_DEFAULT,
        undefined, undefined, 16#ffffffff),
    %% For key-path spending, we need to tweak the private key
    %% with the same TapTweak used to create the output key
    TweakedPrivKey = taproot_tweak_privkey(PrivKey),
    AuxRand = crypto:strong_rand_bytes(32),
    {ok, SchnorrSig} = beamchain_crypto:schnorr_sign(
        SigHash, TweakedPrivKey, AuxRand),
    %% Witness: [schnorr_sig (64 bytes for DEFAULT, 65 bytes otherwise)]
    %% SIGHASH_DEFAULT → 64 byte sig (no trailing byte)
    Input#tx_in{
        script_sig = <<>>,
        witness    = [SchnorrSig]
    }.

%% --- P2SH-P2WPKH signing (wrapped segwit) ---
sign_p2sh_p2wpkh(Tx, InputIndex, Input, Utxo, PrivKey) ->
    PubKey = privkey_to_pubkey(PrivKey),
    PkHash = beamchain_crypto:hash160(PubKey),
    %% Redeem script: OP_0 <20-byte-hash> (P2WPKH witness program)
    RedeemScript = <<0, 20, PkHash/binary>>,
    %% scriptCode for BIP 143: same as P2WPKH
    ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
    SigHash = beamchain_script:sighash_witness_v0(
        Tx, InputIndex, ScriptCode, Utxo#utxo.value, ?SIGHASH_ALL),
    {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
    SigWithType = <<DerSig/binary, ?SIGHASH_ALL>>,
    %% scriptSig: just push the redeem script
    ScriptSig = push_data(RedeemScript, <<>>),
    Input#tx_in{
        script_sig = ScriptSig,
        witness    = [SigWithType, PubKey]
    }.

%%% ===================================================================
%%% Signing helpers
%%% ===================================================================

%% Apply the BIP 341 TapTweak to a private key for key-path spending.
taproot_tweak_privkey(PrivKey) ->
    {ok, <<Prefix:8, XOnly:32/binary>>} =
        beamchain_crypto:pubkey_from_privkey(PrivKey),
    Tweak = beamchain_crypto:tagged_hash(<<"TapTweak">>, XOnly),
    %% If the public key has odd Y, negate the private key first
    PrivKey2 = case Prefix of
        16#02 -> PrivKey;  %% even Y, no negation needed
        16#03 -> negate_privkey(PrivKey)
    end,
    {ok, TweakedPriv} = beamchain_crypto:seckey_tweak_add(PrivKey2, Tweak),
    TweakedPriv.

%% Negate a private key: result = N - key (mod N)
negate_privkey(PrivKey) ->
    N = 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    KeyInt = binary:decode_unsigned(PrivKey, big),
    Negated = N - KeyInt,
    <<Negated:256/big>>.

%% Push data onto a script: creates proper push opcode
push_data(Data, Acc) ->
    Len = byte_size(Data),
    if
        Len =< 75 ->
            <<Acc/binary, Len, Data/binary>>;
        Len =< 255 ->
            <<Acc/binary, 16#4c, Len:8, Data/binary>>;
        Len =< 65535 ->
            <<Acc/binary, 16#4d, Len:16/little, Data/binary>>;
        true ->
            <<Acc/binary, 16#4e, Len:32/little, Data/binary>>
    end.

%%% ===================================================================
%%% PSBT (BIP 174/370)
%%% ===================================================================

%% PSBT magic bytes: "psbt" + 0xff
-define(PSBT_MAGIC, <<16#70, 16#73, 16#62, 16#74, 16#ff>>).

%% Key types for global map
-define(PSBT_GLOBAL_UNSIGNED_TX, 16#00).
-define(PSBT_GLOBAL_XPUB,       16#01).
-define(PSBT_GLOBAL_VERSION,    16#fb).

%% Key types for input map
-define(PSBT_IN_NON_WITNESS_UTXO, 16#00).
-define(PSBT_IN_WITNESS_UTXO,     16#01).
-define(PSBT_IN_PARTIAL_SIG,      16#02).
-define(PSBT_IN_SIGHASH_TYPE,     16#03).
-define(PSBT_IN_REDEEM_SCRIPT,    16#04).
-define(PSBT_IN_WITNESS_SCRIPT,   16#05).
-define(PSBT_IN_BIP32_DERIVATION, 16#06).
-define(PSBT_IN_FINAL_SCRIPTSIG,  16#07).
-define(PSBT_IN_FINAL_WITNESS,    16#08).
-define(PSBT_IN_TAP_KEY_SIG,      16#13).
-define(PSBT_IN_TAP_INTERNAL_KEY, 16#17).

%% Key types for output map
-define(PSBT_OUT_REDEEM_SCRIPT,    16#00).
-define(PSBT_OUT_WITNESS_SCRIPT,   16#01).
-define(PSBT_OUT_BIP32_DERIVATION, 16#02).

-record(psbt, {
    unsigned_tx :: #transaction{},
    inputs      :: [map()],    %% list of input key-value maps
    outputs     :: [map()]     %% list of output key-value maps
}).

%% @doc Create a new PSBT from inputs and outputs.
%% Inputs: [{Txid, Vout}], Outputs: [{ScriptPubKey, Amount}]
-spec create_psbt([{binary(), non_neg_integer()}],
                  [{binary(), non_neg_integer()}]) -> #psbt{}.
create_psbt(Inputs, Outputs) ->
    TxIns = lists:map(fun({Txid, Vout}) ->
        #tx_in{
            prev_out  = #outpoint{hash = Txid, index = Vout},
            script_sig = <<>>,
            sequence  = 16#fffffffd,
            witness   = []
        }
    end, Inputs),
    TxOuts = lists:map(fun({ScriptPubKey, Amount}) ->
        #tx_out{value = Amount, script_pubkey = ScriptPubKey}
    end, Outputs),
    Tx = #transaction{
        version  = 2,
        inputs   = TxIns,
        outputs  = TxOuts,
        locktime = 0
    },
    #psbt{
        unsigned_tx = Tx,
        inputs  = [#{} || _ <- Inputs],
        outputs = [#{} || _ <- Outputs]
    }.

%% @doc Add witness UTXO information to a PSBT input.
add_witness_utxo(Psbt, InputIndex, Utxo) ->
    Inputs = Psbt#psbt.inputs,
    InputMap = lists:nth(InputIndex + 1, Inputs),
    UtxoData = beamchain_serialize:encode_tx_out(
        #tx_out{value = Utxo#utxo.value,
                script_pubkey = Utxo#utxo.script_pubkey}),
    NewMap = InputMap#{witness_utxo => UtxoData,
                       utxo_record => Utxo},
    NewInputs = replace_nth(InputIndex + 1, NewMap, Inputs),
    Psbt#psbt{inputs = NewInputs}.

%% @doc Sign a PSBT with the given private keys.
%% PrivKeys: [{InputIndex, PrivKey}] — only sign specified inputs.
-spec sign_psbt(#psbt{}, [{non_neg_integer(), binary()}]) -> #psbt{}.
sign_psbt(Psbt, PrivKeyPairs) ->
    lists:foldl(fun({InputIndex, PrivKey}, Acc) ->
        sign_psbt_input(Acc, InputIndex, PrivKey)
    end, Psbt, PrivKeyPairs).

sign_psbt_input(Psbt, InputIndex, PrivKey) ->
    Tx = Psbt#psbt.unsigned_tx,
    InputMap = lists:nth(InputIndex + 1, Psbt#psbt.inputs),
    %% Determine script type from witness_utxo or the tx output
    Utxo = maps:get(utxo_record, InputMap, undefined),
    case Utxo of
        undefined ->
            %% Can't sign without UTXO info
            Psbt;
        _ ->
            ScriptPubKey = Utxo#utxo.script_pubkey,
            PubKey = privkey_to_pubkey(PrivKey),
            NewMap = case beamchain_address:classify_script(ScriptPubKey) of
                p2wpkh ->
                    PkHash = beamchain_crypto:hash160(PubKey),
                    ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
                    SigHash = beamchain_script:sighash_witness_v0(
                        Tx, InputIndex, ScriptCode, Utxo#utxo.value,
                        ?SIGHASH_ALL),
                    {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
                    SigWithType = <<DerSig/binary, ?SIGHASH_ALL>>,
                    InputMap#{partial_sigs =>
                        maps:put(PubKey, SigWithType,
                                 maps:get(partial_sigs, InputMap, #{}))};
                p2tr ->
                    PrevOuts = build_prevouts(Psbt),
                    SigHash = beamchain_script:sighash_taproot(
                        Tx, InputIndex, PrevOuts, ?SIGHASH_DEFAULT,
                        undefined, undefined, 16#ffffffff),
                    TweakedPrivKey = taproot_tweak_privkey(PrivKey),
                    AuxRand = crypto:strong_rand_bytes(32),
                    {ok, SchnorrSig} = beamchain_crypto:schnorr_sign(
                        SigHash, TweakedPrivKey, AuxRand),
                    InputMap#{tap_key_sig => SchnorrSig};
                p2pkh ->
                    PkHash = beamchain_crypto:hash160(PubKey),
                    ScriptCode = <<16#76, 16#a9, 20, PkHash/binary, 16#88, 16#ac>>,
                    SigHash = beamchain_script:sighash_legacy(
                        Tx, InputIndex, ScriptCode, ?SIGHASH_ALL),
                    {ok, DerSig} = beamchain_crypto:ecdsa_sign(SigHash, PrivKey),
                    SigWithType = <<DerSig/binary, ?SIGHASH_ALL>>,
                    InputMap#{partial_sigs =>
                        maps:put(PubKey, SigWithType,
                                 maps:get(partial_sigs, InputMap, #{}))}
            end,
            NewInputs = replace_nth(InputIndex + 1, NewMap, Psbt#psbt.inputs),
            Psbt#psbt{inputs = NewInputs}
    end.

build_prevouts(Psbt) ->
    lists:map(fun(InputMap) ->
        case maps:get(utxo_record, InputMap, undefined) of
            undefined -> {0, <<>>};
            U -> {U#utxo.value, U#utxo.script_pubkey}
        end
    end, Psbt#psbt.inputs).

%% @doc Finalize a PSBT — convert partial sigs into final scriptSig/witness.
-spec finalize_psbt(#psbt{}) -> {ok, #transaction{}} | {error, term()}.
finalize_psbt(Psbt) ->
    Tx = Psbt#psbt.unsigned_tx,
    try
        FinalInputs = lists:map(fun({Input, InputMap}) ->
            Utxo = maps:get(utxo_record, InputMap, undefined),
            case Utxo of
                undefined ->
                    error(missing_utxo_info);
                _ ->
                    finalize_input(Input, InputMap, Utxo)
            end
        end, lists:zip(Tx#transaction.inputs, Psbt#psbt.inputs)),
        FinalTx = Tx#transaction{inputs = FinalInputs},
        {ok, FinalTx}
    catch
        error:Reason ->
            {error, Reason}
    end.

finalize_input(Input, InputMap, Utxo) ->
    ScriptPubKey = Utxo#utxo.script_pubkey,
    case beamchain_address:classify_script(ScriptPubKey) of
        p2wpkh ->
            PartialSigs = maps:get(partial_sigs, InputMap, #{}),
            case maps:to_list(PartialSigs) of
                [{PubKey, Sig}] ->
                    Input#tx_in{script_sig = <<>>,
                                witness = [Sig, PubKey]};
                _ ->
                    error(incomplete_signatures)
            end;
        p2tr ->
            case maps:get(tap_key_sig, InputMap, undefined) of
                undefined -> error(missing_taproot_sig);
                Sig -> Input#tx_in{script_sig = <<>>,
                                   witness = [Sig]}
            end;
        p2pkh ->
            PartialSigs = maps:get(partial_sigs, InputMap, #{}),
            case maps:to_list(PartialSigs) of
                [{PubKey, Sig}] ->
                    ScriptSig = push_data(Sig,
                        <<(push_data(PubKey, <<>>))/binary>>),
                    Input#tx_in{script_sig = ScriptSig, witness = []};
                _ ->
                    error(incomplete_signatures)
            end
    end.

%% @doc Encode a PSBT to its binary format (BIP 174).
-spec encode_psbt(#psbt{}) -> binary().
encode_psbt(Psbt) ->
    %% Magic bytes
    Global = encode_psbt_global(Psbt),
    InputMaps = lists:map(fun encode_psbt_input/1, Psbt#psbt.inputs),
    OutputMaps = lists:map(fun encode_psbt_output/1, Psbt#psbt.outputs),
    iolist_to_binary([?PSBT_MAGIC, Global | InputMaps ++ OutputMaps]).

encode_psbt_global(Psbt) ->
    %% Unsigned tx: key=0x00, value=serialized tx (no witness)
    TxBin = beamchain_serialize:encode_transaction(
        Psbt#psbt.unsigned_tx, no_witness),
    encode_kv(<<0>>, TxBin, <<0>>).

encode_psbt_input(InputMap) ->
    Entries = lists:flatten([
        case maps:get(witness_utxo, InputMap, undefined) of
            undefined -> [];
            WU -> [encode_kv(<<1>>, WU, <<>>)]
        end,
        case maps:get(partial_sigs, InputMap, undefined) of
            undefined -> [];
            Sigs ->
                maps:fold(fun(PubKey, Sig, Acc) ->
                    [encode_kv(<<2, PubKey/binary>>, Sig, <<>>) | Acc]
                end, [], Sigs)
        end,
        case maps:get(tap_key_sig, InputMap, undefined) of
            undefined -> [];
            TapSig -> [encode_kv(<<16#13>>, TapSig, <<>>)]
        end
    ]),
    iolist_to_binary(Entries ++ [<<0>>]).  %% separator

encode_psbt_output(_OutputMap) ->
    <<0>>.  %% empty output map, just separator

encode_kv(Key, Value, _Extra) ->
    KeyLen = beamchain_serialize:encode_varint(byte_size(Key)),
    ValLen = beamchain_serialize:encode_varint(byte_size(Value)),
    <<KeyLen/binary, Key/binary, ValLen/binary, Value/binary>>.

%% @doc Decode a PSBT from its binary format.
-spec decode_psbt(binary()) -> #psbt{} | {error, term()}.
decode_psbt(<<16#70, 16#73, 16#62, 16#74, 16#ff, Rest/binary>>) ->
    {GlobalPairs, Rest1} = decode_psbt_map(Rest),
    %% Extract unsigned tx from global
    UnsignedTx = case proplists:get_value(<<0>>, GlobalPairs) of
        undefined -> error(missing_unsigned_tx);
        TxBin ->
            {Tx, _} = beamchain_serialize:decode_transaction(TxBin),
            Tx
    end,
    NumInputs = length(UnsignedTx#transaction.inputs),
    NumOutputs = length(UnsignedTx#transaction.outputs),
    {InputMaps, Rest2} = decode_n_maps(Rest1, NumInputs),
    {OutputMaps, _Rest3} = decode_n_maps(Rest2, NumOutputs),
    Inputs = lists:map(fun decode_input_map/1, InputMaps),
    Outputs = lists:map(fun decode_output_map/1, OutputMaps),
    #psbt{
        unsigned_tx = UnsignedTx,
        inputs      = Inputs,
        outputs     = Outputs
    };
decode_psbt(_) ->
    {error, invalid_psbt_magic}.

decode_psbt_map(Bin) ->
    decode_psbt_map(Bin, []).

decode_psbt_map(<<0, Rest/binary>>, Acc) ->
    {lists:reverse(Acc), Rest};
decode_psbt_map(Bin, Acc) ->
    {KeyLen, Rest1} = beamchain_serialize:decode_varint(Bin),
    <<Key:KeyLen/binary, Rest2/binary>> = Rest1,
    {ValLen, Rest3} = beamchain_serialize:decode_varint(Rest2),
    <<Value:ValLen/binary, Rest4/binary>> = Rest3,
    decode_psbt_map(Rest4, [{Key, Value} | Acc]).

decode_n_maps(Bin, 0) ->
    {[], Bin};
decode_n_maps(Bin, N) ->
    {Pairs, Rest} = decode_psbt_map(Bin),
    {MoreMaps, Rest2} = decode_n_maps(Rest, N - 1),
    {[Pairs | MoreMaps], Rest2}.

decode_input_map(Pairs) ->
    lists:foldl(fun({Key, Value}, Acc) ->
        case Key of
            <<1>> ->
                Acc#{witness_utxo => Value};
            <<2, PubKey/binary>> ->
                Sigs = maps:get(partial_sigs, Acc, #{}),
                Acc#{partial_sigs => Sigs#{PubKey => Value}};
            <<16#13>> ->
                Acc#{tap_key_sig => Value};
            _ ->
                Acc#{Key => Value}
        end
    end, #{}, Pairs).

decode_output_map(Pairs) ->
    maps:from_list(Pairs).

replace_nth(1, Elem, [_ | Rest]) -> [Elem | Rest];
replace_nth(N, Elem, [H | Rest]) -> [H | replace_nth(N - 1, Elem, Rest)].

%%% ===================================================================
%%% Coin selection
%%% ===================================================================

%% Estimated input weight for fee calculation
-define(P2WPKH_INPUT_WEIGHT, 272).   %% ~68 vbytes
-define(P2TR_INPUT_WEIGHT, 230).     %% ~57.5 vbytes
-define(P2PKH_INPUT_WEIGHT, 592).    %% ~148 vbytes

%% @doc Select coins to cover the target amount plus fees.
%% FeeRate is in sat/vByte. Available is a list of
%% {Txid, Vout, #utxo{}} tuples.
-spec select_coins(Target :: non_neg_integer(),
                   FeeRate :: number(),
                   Available :: [{binary(), non_neg_integer(), #utxo{}}]) ->
    {ok, Selected :: [{binary(), non_neg_integer(), #utxo{}}],
         Change :: non_neg_integer()} |
    {error, insufficient_funds}.
select_coins(Target, FeeRate, Available) ->
    %% Sort by value descending for knapsack
    Sorted = lists:sort(fun({_, _, A}, {_, _, B}) ->
        A#utxo.value >= B#utxo.value
    end, Available),
    %% Try branch-and-bound first (exact match, no change)
    case bnb_select(Target, FeeRate, Sorted) of
        {ok, _, _} = Result ->
            Result;
        no_match ->
            %% Fallback to knapsack selection
            knapsack_select(Target, FeeRate, Sorted)
    end.

%% Branch-and-Bound: try to find exact match (within dust threshold)
%% to avoid creating change output.
bnb_select(Target, FeeRate, Utxos) ->
    %% Cost of spending each UTXO
    CostPerInput = round(FeeRate * ?P2WPKH_INPUT_WEIGHT / 4),
    %% Target with base tx fee (header + 1 output, no change)
    BaseFee = round(FeeRate * 40),  %% ~40 vbytes for tx overhead + one output
    EffTarget = Target + BaseFee,
    %% Dust threshold — if we can get within this range, skip change
    DustLimit = 546,
    bnb_search(Utxos, EffTarget, CostPerInput, DustLimit, 0, [], 0).

bnb_search([], Target, _CostPerInput, DustLimit, Accumulated, Selected, _Depth) ->
    Diff = Accumulated - Target,
    if
        Diff >= 0 andalso Diff =< DustLimit ->
            {ok, lists:reverse(Selected), 0};
        true ->
            no_match
    end;
bnb_search(_Utxos, _Target, _CostPerInput, _DustLimit, _Acc, _Selected, Depth)
  when Depth > 20 ->
    %% Limit search depth to avoid exponential blowup
    no_match;
bnb_search([{_Txid, _Vout, Utxo} = Coin | Rest], Target, CostPerInput,
           DustLimit, Accumulated, Selected, Depth) ->
    EffValue = Utxo#utxo.value - CostPerInput,
    case EffValue > 0 of
        true ->
            NewAcc = Accumulated + EffValue,
            %% Include this coin
            case bnb_search(Rest, Target, CostPerInput, DustLimit,
                            NewAcc, [Coin | Selected], Depth + 1) of
                {ok, _, _} = Found ->
                    Found;
                no_match ->
                    %% Exclude this coin, try next
                    bnb_search(Rest, Target, CostPerInput, DustLimit,
                               Accumulated, Selected, Depth + 1)
            end;
        false ->
            %% Input costs more than it's worth, skip
            bnb_search(Rest, Target, CostPerInput, DustLimit,
                       Accumulated, Selected, Depth + 1)
    end.

%% Knapsack: pick smallest UTXOs that cover target + fees + change output.
knapsack_select(Target, FeeRate, Sorted) ->
    CostPerInput = round(FeeRate * ?P2WPKH_INPUT_WEIGHT / 4),
    %% Base fee includes change output (~31 vbytes for P2WPKH change)
    BaseFee = round(FeeRate * 71),  %% ~40 overhead + ~31 change output
    EffTarget = Target + BaseFee,
    %% Reverse to pick smallest first (Sorted is desc)
    SmallFirst = lists:reverse(Sorted),
    accumulate_coins(SmallFirst, EffTarget, CostPerInput, 0, []).

accumulate_coins([], _Target, _CostPerInput, _Acc, _Selected) ->
    {error, insufficient_funds};
accumulate_coins([{_Txid, _Vout, Utxo} = Coin | Rest], Target, CostPerInput,
                 Accumulated, Selected) ->
    EffValue = Utxo#utxo.value - CostPerInput,
    NewAcc = Accumulated + max(EffValue, 0),
    NewSelected = [Coin | Selected],
    case NewAcc >= Target of
        true ->
            Change = NewAcc - Target,
            {ok, lists:reverse(NewSelected), Change};
        false ->
            accumulate_coins(Rest, Target, CostPerInput, NewAcc, NewSelected)
    end.

%%% ===================================================================
%%% Wallet persistence
%%% ===================================================================

save_wallet(#wallet_state{wallet_file = undefined}) ->
    ok;
save_wallet(#wallet_state{addresses = Addrs,
                           next_receive = NextRecv, next_change = NextChg,
                           passphrase = Passphrase, wallet_file = File,
                           encrypted = Encrypted, encrypted_seed = EncSeed,
                           encryption_salt = EncSalt, seed = Seed}) ->
    %% For encrypted wallets, save the encrypted seed
    %% For unencrypted wallets, save the plaintext seed
    WalletData = case Encrypted of
        true ->
            #{
                <<"encrypted">>       => true,
                <<"encrypted_seed">>  => hex_encode(EncSeed),
                <<"encryption_salt">> => hex_encode(EncSalt),
                <<"addresses">>       => Addrs,
                <<"next_receive">>    => encode_index_map(NextRecv),
                <<"next_change">>     => encode_index_map(NextChg),
                <<"created_at">>      => erlang:system_time(second)
            };
        false ->
            #{
                <<"seed">>         => hex_encode(Seed),
                <<"addresses">>    => Addrs,
                <<"next_receive">> => encode_index_map(NextRecv),
                <<"next_change">>  => encode_index_map(NextChg),
                <<"created_at">>   => erlang:system_time(second)
            }
    end,
    Json = jsx:encode(WalletData, [space, indent]),
    case Passphrase of
        undefined ->
            file:write_file(File, Json);
        _ ->
            encrypt_and_write(File, Json, Passphrase)
    end.

load_wallet_file(FilePath, undefined) ->
    case file:read_file(FilePath) of
        {ok, Data} ->
            {ok, jsx:decode(Data, [return_maps])};
        {error, _} = Err ->
            Err
    end;
load_wallet_file(FilePath, Passphrase) ->
    case file:read_file(FilePath) of
        {ok, EncData} ->
            decrypt_and_parse(EncData, Passphrase);
        {error, _} = Err ->
            Err
    end.

encrypt_and_write(File, Plaintext, Passphrase) ->
    Salt = crypto:strong_rand_bytes(16),
    Key = derive_key(Passphrase, Salt),
    IV = crypto:strong_rand_bytes(12),
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, Key, IV, Plaintext, <<>>, true),
    %% File format: "BCWALLET" magic || salt(16) || iv(12) || tag(16) || ciphertext
    Encoded = <<"BCWALLET", Salt/binary, IV/binary, Tag/binary,
                Ciphertext/binary>>,
    file:write_file(File, Encoded).

decrypt_and_parse(<<"BCWALLET", Salt:16/binary, IV:12/binary,
                    Tag:16/binary, Ciphertext/binary>>, Passphrase) ->
    Key = derive_key(Passphrase, Salt),
    case crypto:crypto_one_time_aead(
             aes_256_gcm, Key, IV, Ciphertext, <<>>, Tag, false) of
        error ->
            {error, wrong_passphrase};
        Plaintext ->
            {ok, jsx:decode(Plaintext, [return_maps])}
    end;
decrypt_and_parse(_, _) ->
    {error, invalid_wallet_file}.

%% Simple key derivation: HMAC-SHA256 iterated
derive_key(Passphrase, Salt) ->
    PassBin = case is_list(Passphrase) of
        true -> list_to_binary(Passphrase);
        false -> Passphrase
    end,
    iterate_key(PassBin, Salt, 100000,
                beamchain_crypto:sha256(<<PassBin/binary, Salt/binary>>)).

iterate_key(_Pass, _Salt, 0, Key) ->
    Key;
iterate_key(Pass, Salt, N, Acc) ->
    iterate_key(Pass, Salt, N - 1,
                beamchain_crypto:sha256(<<Acc/binary, Pass/binary, Salt/binary>>)).

%%% ===================================================================
%%% UTXO scanning and tracking
%%% ===================================================================

%% @doc Scan the wallet UTXO table for outputs matching a given scriptPubKey.
%% Returns the total value of all UTXOs matching this script.
-spec scan_utxos_for_script(binary()) -> non_neg_integer().
scan_utxos_for_script(ScriptPubKey) ->
    case ets:whereis(?WALLET_UTXO_TABLE) of
        undefined -> 0;
        _ ->
            ets:foldl(fun({{_Txid, _Vout}, {Value, Script, _Height}}, Acc) ->
                case Script =:= ScriptPubKey of
                    true -> Acc + Value;
                    false -> Acc
                end
            end, 0, ?WALLET_UTXO_TABLE)
    end.

%% @doc Register a script as belonging to the wallet (for UTXO tracking).
-spec register_wallet_script(binary(), binary()) -> ok.
register_wallet_script(ScriptPubKey, Address) ->
    ets:insert(?WALLET_SCRIPT_TABLE, {ScriptPubKey, Address}),
    ok.

%% @doc Check if a script belongs to this wallet.
-spec is_wallet_script(binary()) -> boolean().
is_wallet_script(ScriptPubKey) ->
    case ets:whereis(?WALLET_SCRIPT_TABLE) of
        undefined -> false;
        _ -> ets:member(?WALLET_SCRIPT_TABLE, ScriptPubKey)
    end.

%% @doc Add a UTXO to the wallet's tracked set.
-spec add_wallet_utxo(binary(), non_neg_integer(), non_neg_integer(),
                       binary(), non_neg_integer()) -> ok.
add_wallet_utxo(Txid, Vout, Value, ScriptPubKey, Height) ->
    ets:insert(?WALLET_UTXO_TABLE, {{Txid, Vout}, {Value, ScriptPubKey, Height}}),
    ok.

%% @doc Remove a UTXO from the wallet's tracked set (when spent).
-spec spend_wallet_utxo(binary(), non_neg_integer()) -> ok.
spend_wallet_utxo(Txid, Vout) ->
    ets:delete(?WALLET_UTXO_TABLE, {Txid, Vout}),
    ok.

%% @doc Get all unspent wallet UTXOs.
-spec get_wallet_utxos() -> [{binary(), non_neg_integer(), #utxo{}}].
get_wallet_utxos() ->
    case ets:whereis(?WALLET_UTXO_TABLE) of
        undefined -> [];
        _ ->
            ets:foldl(fun({{Txid, Vout}, {Value, ScriptPubKey, Height}}, Acc) ->
                Utxo = #utxo{
                    value = Value,
                    script_pubkey = ScriptPubKey,
                    is_coinbase = false,  %% Wallet UTXOs are typically not coinbase
                    height = Height
                },
                [{Txid, Vout, Utxo} | Acc]
            end, [], ?WALLET_UTXO_TABLE)
    end.

%% @doc Get wallet balance from tracked UTXOs.
-spec get_wallet_balance() -> non_neg_integer().
get_wallet_balance() ->
    case ets:whereis(?WALLET_UTXO_TABLE) of
        undefined -> 0;
        _ ->
            ets:foldl(fun({{_Txid, _Vout}, {Value, _Script, _Height}}, Acc) ->
                Acc + Value
            end, 0, ?WALLET_UTXO_TABLE)
    end.

%% @doc Scan a block for wallet-relevant transactions.
%% This should be called when a new block is connected.
-spec scan_block_for_wallet(#block{}) -> ok.
scan_block_for_wallet(Block) ->
    Height = Block#block.height,
    lists:foreach(fun(Tx) ->
        %% First, mark any spent inputs
        lists:foreach(fun(Input) ->
            #tx_in{prev_out = #outpoint{hash = Txid, index = Vout}} = Input,
            spend_wallet_utxo(Txid, Vout)
        end, Tx#transaction.inputs),
        %% Then, add any outputs to wallet addresses
        Txid = case Tx#transaction.txid of
            undefined -> beamchain_serialize:tx_hash(Tx);
            T -> T
        end,
        lists:foldl(fun(Output, Idx) ->
            ScriptPubKey = Output#tx_out.script_pubkey,
            case is_wallet_script(ScriptPubKey) of
                true ->
                    add_wallet_utxo(Txid, Idx, Output#tx_out.value,
                                     ScriptPubKey, Height);
                false ->
                    ok
            end,
            Idx + 1
        end, 0, Tx#transaction.outputs)
    end, Block#block.transactions),
    ok.

find_address(AddrBin, #wallet_state{addresses = Addrs}) ->
    case lists:search(fun(A) ->
        maps:get(<<"address">>, A) =:= AddrBin
    end, Addrs) of
        {value, Found} -> {ok, Found};
        false -> not_found
    end.

%%% ===================================================================
%%% Wallet directory
%%% ===================================================================

wallet_dir(Network) ->
    DataDir = try beamchain_config:datadir()
              catch _:_ -> default_datadir()
              end,
    NetStr = atom_to_list(Network),
    DataDir ++ "/" ++ NetStr ++ "/wallet".

default_datadir() ->
    Home = os:getenv("HOME", "/tmp"),
    Home ++ "/.beamchain".

%%% ===================================================================
%%% Index map encoding for JSON
%%% ===================================================================

encode_index_map(Map) ->
    maps:fold(fun(K, V, Acc) ->
        Acc#{atom_to_binary(K, utf8) => V}
    end, #{}, Map).

decode_index_map(Map) ->
    maps:fold(fun(K, V, Acc) ->
        Key = case is_binary(K) of
            true -> binary_to_existing_atom(K, utf8);
            false -> K
        end,
        Acc#{Key => V}
    end, #{}, Map).

%%% ===================================================================
%%% BIP 32: Master key from seed
%%% ===================================================================

%% @doc Generate master HD key from a seed (typically 16-64 bytes).
-spec master_from_seed(Seed :: binary()) -> #hd_key{}.
master_from_seed(Seed) when byte_size(Seed) >= 16,
                             byte_size(Seed) =< 64 ->
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(<<"Bitcoin seed">>, Seed),
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(IL),
    #hd_key{
        private_key  = IL,
        public_key   = PubKey,
        chain_code   = IR,
        depth        = 0,
        fingerprint  = <<0, 0, 0, 0>>,
        child_index  = 0
    }.

%%% ===================================================================
%%% BIP 32: Child key derivation
%%% ===================================================================

-spec derive_child(Parent :: #hd_key{}, Index :: non_neg_integer()) -> #hd_key{}.
derive_child(#hd_key{private_key = PrivKey, chain_code = ChainCode,
                      public_key = PubKey} = Parent, Index)
  when PrivKey =/= undefined ->
    Data = case Index >= ?HARDENED of
        true ->
            <<0, PrivKey/binary, Index:32/big>>;
        false ->
            <<PubKey/binary, Index:32/big>>
    end,
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(ChainCode, Data),
    {ok, ChildPriv} = beamchain_crypto:seckey_tweak_add(PrivKey, IL),
    {ok, ChildPub} = beamchain_crypto:pubkey_from_privkey(ChildPriv),
    <<Fingerprint:4/binary, _/binary>> = beamchain_crypto:hash160(PubKey),
    #hd_key{
        private_key  = ChildPriv,
        public_key   = ChildPub,
        chain_code   = IR,
        depth        = Parent#hd_key.depth + 1,
        fingerprint  = Fingerprint,
        child_index  = Index
    };
derive_child(#hd_key{private_key = undefined}, Index)
  when Index >= ?HARDENED ->
    error(hardened_derivation_requires_private_key);
derive_child(#hd_key{private_key = undefined, chain_code = ChainCode,
                      public_key = PubKey} = Parent, Index) ->
    Data = <<PubKey/binary, Index:32/big>>,
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(ChainCode, Data),
    {ok, ChildPub} = beamchain_crypto:pubkey_tweak_add(PubKey, IL),
    <<Fingerprint:4/binary, _/binary>> = beamchain_crypto:hash160(PubKey),
    #hd_key{
        private_key  = undefined,
        public_key   = ChildPub,
        chain_code   = IR,
        depth        = Parent#hd_key.depth + 1,
        fingerprint  = Fingerprint,
        child_index  = Index
    }.

%%% ===================================================================
%%% BIP 32: Path derivation
%%% ===================================================================

-spec derive_path(Root :: #hd_key{}, Path :: [non_neg_integer()]) -> #hd_key{}.
derive_path(Key, []) ->
    Key;
derive_path(Key, [Index | Rest]) ->
    Child = derive_child(Key, Index),
    derive_path(Child, Rest).

-spec parse_path(string()) -> [non_neg_integer()].
parse_path("m" ++ Rest) ->
    parse_path_components(Rest);
parse_path(Path) ->
    parse_path_components("/" ++ Path).

parse_path_components([]) ->
    [];
parse_path_components("/" ++ Rest) ->
    {Component, Remaining} = take_until_slash(Rest, []),
    Index = parse_component(Component),
    [Index | parse_path_components(Remaining)].

take_until_slash([], Acc) ->
    {lists:reverse(Acc), []};
take_until_slash("/" ++ _ = Rest, Acc) ->
    {lists:reverse(Acc), Rest};
take_until_slash([C | Rest], Acc) ->
    take_until_slash(Rest, [C | Acc]).

parse_component(Str) ->
    case lists:last(Str) of
        $' ->
            N = list_to_integer(lists:droplast(Str)),
            N + ?HARDENED;
        $h ->
            N = list_to_integer(lists:droplast(Str)),
            N + ?HARDENED;
        _ ->
            list_to_integer(Str)
    end.

%%% ===================================================================
%%% Key utilities
%%% ===================================================================

-spec pubkey_to_hash160(binary()) -> binary().
pubkey_to_hash160(PubKey) when byte_size(PubKey) =:= 33 ->
    beamchain_crypto:hash160(PubKey).

-spec privkey_to_pubkey(binary()) -> binary().
privkey_to_pubkey(PrivKey) when byte_size(PrivKey) =:= 32 ->
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    PubKey.

-spec privkey_to_xonly(binary()) -> binary().
privkey_to_xonly(PrivKey) when byte_size(PrivKey) =:= 32 ->
    {ok, <<_Prefix:8, XOnly:32/binary>>} =
        beamchain_crypto:pubkey_from_privkey(PrivKey),
    XOnly.

%%% ===================================================================
%%% Hex helpers
%%% ===================================================================

hex_encode(Bin) ->
    list_to_binary(lists:flatten(
        [io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin])).

hex_decode(Hex) ->
    Str = case is_binary(Hex) of
        true -> binary_to_list(Hex);
        false -> Hex
    end,
    hex_decode_str(Str, <<>>).

hex_decode_str([], Acc) ->
    Acc;
hex_decode_str([H1, H2 | Rest], Acc) ->
    B = list_to_integer([H1, H2], 16),
    hex_decode_str(Rest, <<Acc/binary, B>>).

%%% ===================================================================
%%% Wallet encryption (at-rest key protection)
%%% ===================================================================

%% PBKDF2 iteration count for key derivation
-define(PBKDF2_ITERATIONS, 25000).
%% AES-256 key size
-define(AES_KEY_SIZE, 32).
%% IV size for AES-256-CBC
-define(AES_IV_SIZE, 16).
%% Salt size for PBKDF2
-define(PBKDF2_SALT_SIZE, 16).

%% @doc Encrypt the wallet's master seed with a passphrase.
%% Uses PBKDF2-SHA512 for key derivation and AES-256-CBC for encryption.
-spec do_encrypt_wallet(#wallet_state{}, binary()) -> {ok, #wallet_state{}} | {error, term()}.
do_encrypt_wallet(#wallet_state{seed = Seed} = State, Passphrase) ->
    %% Generate random salt
    Salt = crypto:strong_rand_bytes(?PBKDF2_SALT_SIZE),
    %% Derive encryption key using PBKDF2-SHA512
    DerivedKey = derive_encryption_key(Passphrase, Salt),
    %% Encrypt the seed using AES-256-CBC
    %% IV is the first 16 bytes of the derived key material
    <<Key:?AES_KEY_SIZE/binary, IV:?AES_IV_SIZE/binary>> = DerivedKey,
    %% PKCS#7 padding for 32-byte seed to align to 16-byte block
    PaddedSeed = pkcs7_pad(Seed, 16),
    EncryptedSeed = crypto:crypto_one_time(aes_256_cbc, Key, IV, PaddedSeed, true),
    %% Clear the plaintext seed and master key from state
    NewState = State#wallet_state{
        seed = undefined,
        master_key = undefined,
        encrypted = true,
        locked = true,
        encrypted_seed = EncryptedSeed,
        encryption_salt = Salt
    },
    logger:info("wallet: encrypted with passphrase (~B byte salt)",
                [byte_size(Salt)]),
    {ok, NewState}.

%% @doc Unlock the wallet by decrypting the master seed.
%% Sets a timer to auto-lock after the specified timeout.
-spec do_unlock_wallet(#wallet_state{}, binary(), non_neg_integer()) ->
    {ok, #wallet_state{}} | {error, term()}.
do_unlock_wallet(#wallet_state{encrypted_seed = EncSeed,
                                encryption_salt = Salt,
                                lock_timer_ref = OldRef} = State,
                  Passphrase, Timeout) ->
    %% Cancel any existing lock timer
    cancel_lock_timer(OldRef),
    %% Derive the decryption key
    DerivedKey = derive_encryption_key(Passphrase, Salt),
    <<Key:?AES_KEY_SIZE/binary, IV:?AES_IV_SIZE/binary>> = DerivedKey,
    %% Decrypt the seed
    try
        DecryptedPadded = crypto:crypto_one_time(aes_256_cbc, Key, IV, EncSeed, false),
        Seed = pkcs7_unpad(DecryptedPadded),
        %% Verify the seed is valid by deriving the master key
        MasterKey = master_from_seed(Seed),
        %% Set auto-lock timer
        TimerRef = erlang:send_after(Timeout * 1000, self(), wallet_lock),
        NewState = State#wallet_state{
            seed = Seed,
            master_key = MasterKey,
            locked = false,
            lock_timer_ref = TimerRef
        },
        logger:info("wallet: unlocked for ~B seconds", [Timeout]),
        {ok, NewState}
    catch
        _:_ ->
            {error, wrong_passphrase}
    end.

%% @doc Lock the wallet by clearing the decrypted seed from memory.
-spec do_lock_wallet(#wallet_state{}) -> #wallet_state{}.
do_lock_wallet(#wallet_state{lock_timer_ref = OldRef} = State) ->
    %% Cancel any existing lock timer
    cancel_lock_timer(OldRef),
    %% Clear sensitive data from state
    State#wallet_state{
        seed = undefined,
        master_key = undefined,
        locked = true,
        lock_timer_ref = undefined
    }.

%% @doc Cancel an existing lock timer if present.
-spec cancel_lock_timer(reference() | undefined) -> ok.
cancel_lock_timer(undefined) -> ok;
cancel_lock_timer(Ref) ->
    erlang:cancel_timer(Ref),
    %% Flush any pending wallet_lock message
    receive wallet_lock -> ok after 0 -> ok end.

%% @doc Derive an encryption key from a passphrase using PBKDF2-SHA512.
%% Returns 48 bytes: 32 for AES key + 16 for IV.
-spec derive_encryption_key(binary(), binary()) -> binary().
derive_encryption_key(Passphrase, Salt) ->
    %% Use crypto:pbkdf2_hmac for key derivation
    %% Returns 48 bytes: 32 for key + 16 for IV
    crypto:pbkdf2_hmac(sha512, Passphrase, Salt, ?PBKDF2_ITERATIONS, 48).

%% @doc PKCS#7 padding for block cipher.
-spec pkcs7_pad(binary(), pos_integer()) -> binary().
pkcs7_pad(Data, BlockSize) ->
    PadLen = BlockSize - (byte_size(Data) rem BlockSize),
    Padding = binary:copy(<<PadLen>>, PadLen),
    <<Data/binary, Padding/binary>>.

%% @doc PKCS#7 unpadding.
-spec pkcs7_unpad(binary()) -> binary().
pkcs7_unpad(Data) ->
    PadLen = binary:last(Data),
    DataLen = byte_size(Data) - PadLen,
    binary:part(Data, 0, DataLen).
