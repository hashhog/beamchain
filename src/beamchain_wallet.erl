-module(beamchain_wallet).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% BIP 32 HD key derivation
-export([master_from_seed/1,
         derive_child/2,
         derive_path/2,
         parse_path/1]).

%% Key utilities
-export([pubkey_to_hash160/1,
         privkey_to_pubkey/1,
         privkey_to_xonly/1]).

%% Hardened child index threshold
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
%%% BIP 32: Master key from seed
%%% -------------------------------------------------------------------

%% @doc Generate master HD key from a seed (typically 16-64 bytes).
%% Uses HMAC-SHA512 with key "Bitcoin seed".
-spec master_from_seed(Seed :: binary()) -> #hd_key{}.
master_from_seed(Seed) when byte_size(Seed) >= 16,
                             byte_size(Seed) =< 64 ->
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(<<"Bitcoin seed">>, Seed),
    %% IL must be valid private key (non-zero, less than curve order)
    %% In practice with 256 bits of entropy this essentially never fails
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(IL),
    #hd_key{
        private_key  = IL,
        public_key   = PubKey,
        chain_code   = IR,
        depth        = 0,
        fingerprint  = <<0, 0, 0, 0>>,
        child_index  = 0
    }.

%%% -------------------------------------------------------------------
%%% BIP 32: Child key derivation
%%% -------------------------------------------------------------------

%% @doc Derive a child key at the given index.
%% Indices >= 0x80000000 are hardened (require private key).
-spec derive_child(Parent :: #hd_key{}, Index :: non_neg_integer()) -> #hd_key{}.
derive_child(#hd_key{private_key = PrivKey, chain_code = ChainCode,
                      public_key = PubKey} = _Parent, Index)
  when PrivKey =/= undefined ->
    Data = case Index >= ?HARDENED of
        true ->
            %% Hardened: HMAC-SHA512(chain_code, 0x00 || private_key || index)
            <<0, PrivKey/binary, Index:32/big>>;
        false ->
            %% Normal: HMAC-SHA512(chain_code, public_key || index)
            <<PubKey/binary, Index:32/big>>
    end,
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(ChainCode, Data),
    %% child_private = (parent_private + IL) mod n
    {ok, ChildPriv} = beamchain_crypto:seckey_tweak_add(PrivKey, IL),
    {ok, ChildPub} = beamchain_crypto:pubkey_from_privkey(ChildPriv),
    %% Parent fingerprint = first 4 bytes of HASH160(parent_pubkey)
    <<Fingerprint:4/binary, _/binary>> = beamchain_crypto:hash160(PubKey),
    #hd_key{
        private_key  = ChildPriv,
        public_key   = ChildPub,
        chain_code   = IR,
        depth        = _Parent#hd_key.depth + 1,
        fingerprint  = Fingerprint,
        child_index  = Index
    };
derive_child(#hd_key{private_key = undefined}, Index)
  when Index >= ?HARDENED ->
    error(hardened_derivation_requires_private_key);
derive_child(#hd_key{private_key = undefined, chain_code = ChainCode,
                      public_key = PubKey} = Parent, Index) ->
    %% Public-only normal derivation
    Data = <<PubKey/binary, Index:32/big>>,
    <<IL:32/binary, IR:32/binary>> =
        beamchain_crypto:hmac_sha512(ChainCode, Data),
    %% child_public = point(IL) + parent_public
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

%%% -------------------------------------------------------------------
%%% BIP 32: Path derivation
%%% -------------------------------------------------------------------

%% @doc Derive a key along a path like [84 + 0x80000000, 0x80000000, 0x80000000, 0, 0]
%% for m/84'/0'/0'/0/0.
-spec derive_path(Root :: #hd_key{}, Path :: [non_neg_integer()]) -> #hd_key{}.
derive_path(Key, []) ->
    Key;
derive_path(Key, [Index | Rest]) ->
    Child = derive_child(Key, Index),
    derive_path(Child, Rest).

%% @doc Parse a BIP 32 path string like "m/84'/0'/0'/0/0" into index list.
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

%%% -------------------------------------------------------------------
%%% Key utilities
%%% -------------------------------------------------------------------

%% @doc Get HASH160 of a compressed public key.
-spec pubkey_to_hash160(binary()) -> binary().
pubkey_to_hash160(PubKey) when byte_size(PubKey) =:= 33 ->
    beamchain_crypto:hash160(PubKey).

%% @doc Derive compressed public key from private key.
-spec privkey_to_pubkey(binary()) -> binary().
privkey_to_pubkey(PrivKey) when byte_size(PrivKey) =:= 32 ->
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    PubKey.

%% @doc Get x-only (32-byte) public key from private key.
%% For taproot: drops the 02/03 prefix byte.
-spec privkey_to_xonly(binary()) -> binary().
privkey_to_xonly(PrivKey) when byte_size(PrivKey) =:= 32 ->
    {ok, <<_Prefix:8, XOnly:32/binary>>} =
        beamchain_crypto:pubkey_from_privkey(PrivKey),
    XOnly.
