-module(beamchain_wallet).
-behaviour(gen_server).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% gen_server API
-export([start_link/0,
         create/0, create/1, create/2,
         load/1, load/2,
         get_new_address/0, get_new_address/1,
         get_change_address/0, get_change_address/1,
         list_addresses/0,
         get_balance/0,
         get_private_key/1,
         get_wallet_info/0]).

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

-define(SERVER, ?MODULE).
-define(HARDENED, 16#80000000).

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
    master_key     :: #hd_key{} | undefined,
    seed           :: binary() | undefined,
    network        :: atom(),
    coin_type      :: non_neg_integer(),    %% 0' mainnet, 1' testnet
    next_receive   :: #{atom() => non_neg_integer()},  %% type -> index
    next_change    :: #{atom() => non_neg_integer()},
    addresses      :: [map()],              %% list of address entries
    wallet_file    :: string() | undefined,
    passphrase     :: binary() | undefined  %% kept in memory for re-saving
}).

%%% ===================================================================
%%% gen_server API
%%% ===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

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

%%% ===================================================================
%%% gen_server callbacks
%%% ===================================================================

init([]) ->
    Network = try beamchain_config:network()
              catch _:_ -> mainnet
              end,
    CoinType = case Network of
        mainnet -> 0 + ?HARDENED;
        _       -> 1 + ?HARDENED
    end,
    {ok, #wallet_state{
        network      = Network,
        coin_type    = CoinType,
        next_receive = #{p2wpkh => 0, p2tr => 0, p2pkh => 0},
        next_change  = #{p2wpkh => 0, p2tr => 0, p2pkh => 0},
        addresses    = []
    }}.

handle_call({create, Seed, Passphrase}, _From, State) ->
    MasterKey = master_from_seed(Seed),
    WalletDir = wallet_dir(State#wallet_state.network),
    ok = filelib:ensure_dir(WalletDir ++ "/"),
    WalletFile = WalletDir ++ "/wallet.json",
    NewState = State#wallet_state{
        master_key  = MasterKey,
        seed        = Seed,
        wallet_file = WalletFile,
        passphrase  = Passphrase
    },
    ok = save_wallet(NewState),
    {reply, {ok, Seed}, NewState};

handle_call({load, FilePath, Passphrase}, _From, State) ->
    case load_wallet_file(FilePath, Passphrase) of
        {ok, WalletData} ->
            SeedHex = maps:get(<<"seed">>, WalletData),
            Seed = hex_decode(SeedHex),
            MasterKey = master_from_seed(Seed),
            Addrs = maps:get(<<"addresses">>, WalletData, []),
            NextRecv = maps:get(<<"next_receive">>, WalletData,
                                #{<<"p2wpkh">> => 0, <<"p2tr">> => 0,
                                  <<"p2pkh">> => 0}),
            NextChg = maps:get(<<"next_change">>, WalletData,
                               #{<<"p2wpkh">> => 0, <<"p2tr">> => 0,
                                 <<"p2pkh">> => 0}),
            NewState = State#wallet_state{
                master_key  = MasterKey,
                seed        = Seed,
                wallet_file = FilePath,
                passphrase  = Passphrase,
                addresses   = Addrs,
                next_receive = decode_index_map(NextRecv),
                next_change  = decode_index_map(NextChg)
            },
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
        network    => State#wallet_state.network,
        addresses  => length(State#wallet_state.addresses),
        has_seed   => State#wallet_state.seed =/= undefined,
        wallet_file => State#wallet_state.wallet_file
    },
    {reply, {ok, Info}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

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
%%% Wallet persistence
%%% ===================================================================

save_wallet(#wallet_state{wallet_file = undefined}) ->
    ok;
save_wallet(#wallet_state{seed = Seed, addresses = Addrs,
                           next_receive = NextRecv, next_change = NextChg,
                           passphrase = Passphrase, wallet_file = File}) ->
    WalletData = #{
        <<"seed">>         => hex_encode(Seed),
        <<"addresses">>    => Addrs,
        <<"next_receive">> => encode_index_map(NextRecv),
        <<"next_change">>  => encode_index_map(NextChg),
        <<"created_at">>   => erlang:system_time(second)
    },
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
%%% UTXO scanning
%%% ===================================================================

%% Scan the UTXO set for outputs matching a given scriptPubKey.
%% This is a simplified approach — a real wallet would maintain its own index.
scan_utxos_for_script(_ScriptPubKey) ->
    %% TODO: integrate with chainstate UTXO index
    %% For now return 0; needs proper UTXO scanning from ETS/DB
    0.

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
