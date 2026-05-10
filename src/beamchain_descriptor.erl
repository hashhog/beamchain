-module(beamchain_descriptor).

%% Output Descriptors (BIP380-386) implementation.
%% Describes sets of output scripts that a wallet can sign for.

-include("beamchain.hrl").

%% Dialyzer suppressions for false positives:
%% derive/3, derive_key/2, derive_keys/3, derive_tree/3, maybe_add_origin/2:
%%   defensive {error,_} handlers that dialyzer thinks are unreachable because
%%   it infers the callee always returns {ok,_}; kept for robustness.
%%   maybe_add_origin/2: bip32_key clause is valid but dialyzer sees only
%%   const_key from call sites.
-dialyzer({nowarn_function, [derive/3, derive_key/2, derive_keys/3,
                              derive_tree/3, maybe_add_origin/2]}).

%% Public API
-export([parse/1, parse/2,
         derive/2, derive/3,
         expand/2, expand/3,
         checksum/1,
         add_checksum/1,
         verify_checksum/1]).

%% Descriptor info
-export([get_info/1,
         is_solvable/1,
         is_range/1,
         has_private_keys/1]).

%% Extended key encoding/decoding
-export([decode_xpub/1, decode_xprv/1,
         encode_xpub/3, encode_xprv/3]).

%% Internal exports for testing
-export([polymod/2, descriptor_checksum/1]).

-define(HARDENED, 16#80000000).

%%% -------------------------------------------------------------------
%%% Checksum constants (BIP380)
%%% -------------------------------------------------------------------

%% Character set for descriptor input (96 chars)
%% Positioned so case errors result in 32-bit offset for error detection
-define(INPUT_CHARSET,
    "0123456789()[],'/*abcdefgh@:$%{}"
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ").

%% Checksum character set (bech32 charset - 32 chars)
-define(CHECKSUM_CHARSET, "qpzry9x8gf2tvdw0s3jn54khce6mua7l").

%%% -------------------------------------------------------------------
%%% Descriptor record types
%%% -------------------------------------------------------------------

%% Key provider types
-record(const_key, {
    pubkey   :: binary(),          %% 33-byte compressed or 32-byte x-only
    privkey  :: binary() | undefined,
    xonly    :: boolean()          %% true for taproot internal keys
}).

-record(bip32_key, {
    extkey      :: {pub, binary(), binary()} | {priv, binary(), binary()},  %% {Type, Key, ChainCode}
    fingerprint :: binary(),       %% 4-byte parent fingerprint
    depth       :: non_neg_integer(),
    path        :: [non_neg_integer()],  %% derivation path from root
    derive_path :: [non_neg_integer()],  %% remaining path to derive
    derive_type :: non_ranged | unhardened | hardened,  %% wildcard type
    origin      :: {binary(), [non_neg_integer()]} | undefined  %% {fingerprint, path}
}).

%% Descriptor types
-record(desc_pk, {key :: #const_key{} | #bip32_key{}}).
-record(desc_pkh, {key :: #const_key{} | #bip32_key{}}).
-record(desc_wpkh, {key :: #const_key{} | #bip32_key{}}).
-record(desc_sh, {inner :: tuple()}).
-record(desc_wsh, {inner :: tuple()}).
-record(desc_multi, {threshold :: pos_integer(), keys :: [#const_key{} | #bip32_key{}], sorted :: boolean()}).
-record(desc_tr, {internal_key :: #const_key{} | #bip32_key{}, tree :: list()}).
-record(desc_addr, {address :: string()}).
-record(desc_raw, {script :: binary()}).
-record(desc_rawtr, {key :: #const_key{} | #bip32_key{}}).
-record(desc_combo, {key :: #const_key{} | #bip32_key{}}).

%%% ===================================================================
%%% Public API
%%% ===================================================================

%% @doc Parse a descriptor string.
%% Returns {ok, Descriptor} or {error, Reason}.
-spec parse(string() | binary()) -> {ok, tuple()} | {error, term()}.
parse(DescStr) ->
    parse(DescStr, #{}).

-spec parse(string() | binary(), map()) -> {ok, tuple()} | {error, term()}.
parse(DescStr, Opts) when is_binary(DescStr) ->
    parse(binary_to_list(DescStr), Opts);
parse(DescStr, Opts) ->
    case verify_and_strip_checksum(DescStr, Opts) of
        {ok, Stripped} ->
            parse_descriptor(Stripped);
        {error, _} = Err ->
            Err
    end.

%% @doc Derive a concrete scriptPubKey at a given index.
%% For non-ranged descriptors, index is ignored.
-spec derive(tuple(), non_neg_integer()) -> {ok, binary()} | {error, term()}.
derive(Desc, Index) ->
    derive(Desc, Index, mainnet).

-spec derive(tuple(), non_neg_integer(), atom()) -> {ok, binary()} | {error, term()}.
derive(Desc, Index, Network) ->
    case derive_key(Desc, Index) of
        {ok, DerivedDesc} ->
            script_from_desc(DerivedDesc, Network);
        {error, _} = Err ->
            Err
    end.

%% @doc Expand a descriptor over a range of indices.
%% Returns a list of {Index, ScriptPubKey} tuples.
-spec expand(tuple(), {non_neg_integer(), non_neg_integer()}) ->
    {ok, [{non_neg_integer(), binary()}]} | {error, term()}.
expand(Desc, Range) ->
    expand(Desc, Range, mainnet).

-spec expand(tuple(), {non_neg_integer(), non_neg_integer()}, atom()) ->
    {ok, [{non_neg_integer(), binary()}]} | {error, term()}.
expand(Desc, {Start, End}, Network) when Start =< End ->
    try
        Results = lists:map(fun(Idx) ->
            case derive(Desc, Idx, Network) of
                {ok, Script} -> {Idx, Script};
                {error, Reason} -> throw({derive_error, Idx, Reason})
            end
        end, lists:seq(Start, End)),
        {ok, Results}
    catch
        throw:{derive_error, Idx, Reason} ->
            {error, {derive_failed, Idx, Reason}}
    end.

%% @doc Compute the checksum for a descriptor string.
-spec checksum(string() | binary()) -> string().
checksum(DescStr) when is_binary(DescStr) ->
    checksum(binary_to_list(DescStr));
checksum(DescStr) ->
    descriptor_checksum(DescStr).

%% @doc Add checksum to a descriptor string.
-spec add_checksum(string() | binary()) -> string().
add_checksum(DescStr) when is_binary(DescStr) ->
    add_checksum(binary_to_list(DescStr));
add_checksum(DescStr) ->
    %% Strip existing checksum if present
    Stripped = case string:rchr(DescStr, $#) of
        0 -> DescStr;
        Pos -> string:substr(DescStr, 1, Pos - 1)
    end,
    Stripped ++ "#" ++ descriptor_checksum(Stripped).

%% @doc Verify the checksum of a descriptor string.
-spec verify_checksum(string() | binary()) -> boolean().
verify_checksum(DescStr) when is_binary(DescStr) ->
    verify_checksum(binary_to_list(DescStr));
verify_checksum(DescStr) ->
    case string:rchr(DescStr, $#) of
        0 -> false;
        Pos ->
            Body = string:substr(DescStr, 1, Pos - 1),
            Given = string:substr(DescStr, Pos + 1),
            Expected = descriptor_checksum(Body),
            Given =:= Expected
    end.

%% @doc Get descriptor information.
-spec get_info(tuple()) -> map().
get_info(Desc) ->
    #{
        descriptor => format_descriptor(Desc),
        checksum => descriptor_checksum(format_descriptor(Desc)),
        isrange => is_range(Desc),
        issolvable => is_solvable(Desc),
        hasprivatekeys => has_private_keys(Desc)
    }.

%% @doc Check if descriptor has wildcards (is ranged).
-spec is_range(tuple()) -> boolean().
is_range(#desc_pk{key = Key}) -> is_key_range(Key);
is_range(#desc_pkh{key = Key}) -> is_key_range(Key);
is_range(#desc_wpkh{key = Key}) -> is_key_range(Key);
is_range(#desc_sh{inner = Inner}) -> is_range(Inner);
is_range(#desc_wsh{inner = Inner}) -> is_range(Inner);
is_range(#desc_multi{keys = Keys}) -> lists:any(fun is_key_range/1, Keys);
is_range(#desc_tr{internal_key = Key, tree = Tree}) ->
    is_key_range(Key) orelse lists:any(fun({_, D}) -> is_range(D) end, Tree);
is_range(#desc_combo{key = Key}) -> is_key_range(Key);
is_range(#desc_rawtr{key = Key}) -> is_key_range(Key);
is_range(#desc_addr{}) -> false;
is_range(#desc_raw{}) -> false.

%% @doc Check if descriptor is solvable (can produce scripts).
-spec is_solvable(tuple()) -> boolean().
is_solvable(#desc_addr{}) -> false;
is_solvable(#desc_raw{}) -> false;
is_solvable(_) -> true.
%% Note: desc_rawtr is solvable (issolvable=true per BIP-386)

%% @doc Check if descriptor has private keys.
-spec has_private_keys(tuple()) -> boolean().
has_private_keys(#desc_pk{key = Key}) -> key_has_private(Key);
has_private_keys(#desc_pkh{key = Key}) -> key_has_private(Key);
has_private_keys(#desc_wpkh{key = Key}) -> key_has_private(Key);
has_private_keys(#desc_sh{inner = Inner}) -> has_private_keys(Inner);
has_private_keys(#desc_wsh{inner = Inner}) -> has_private_keys(Inner);
has_private_keys(#desc_multi{keys = Keys}) -> lists:any(fun key_has_private/1, Keys);
has_private_keys(#desc_tr{internal_key = Key, tree = Tree}) ->
    key_has_private(Key) orelse lists:any(fun({_, D}) -> has_private_keys(D) end, Tree);
has_private_keys(#desc_combo{key = Key}) -> key_has_private(Key);
has_private_keys(#desc_rawtr{key = Key}) -> key_has_private(Key);
has_private_keys(_) -> false.

%%% ===================================================================
%%% Checksum Algorithm (BIP380)
%%% ===================================================================

%% @doc Compute the polymod for the checksum.
%% This is a GF(32) polynomial reduction.
-spec polymod(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
polymod(C, Val) ->
    C0 = C bsr 35,
    C1 = ((C band 16#7ffffffff) bsl 5) bxor Val,
    C2 = if (C0 band 1) =/= 0 -> C1 bxor 16#f5dee51989; true -> C1 end,
    C3 = if (C0 band 2) =/= 0 -> C2 bxor 16#a9fdca3312; true -> C2 end,
    C4 = if (C0 band 4) =/= 0 -> C3 bxor 16#1bab10e32d; true -> C3 end,
    C5 = if (C0 band 8) =/= 0 -> C4 bxor 16#3706b1677a; true -> C4 end,
    if (C0 band 16) =/= 0 -> C5 bxor 16#644d626ffd; true -> C5 end.

%% @doc Compute the 8-character checksum for a descriptor string.
-spec descriptor_checksum(string()) -> string().
descriptor_checksum(Str) ->
    {C1, Cls1, ClsCount1} = lists:foldl(fun(Char, {C, Cls, ClsCount}) ->
        case char_position(Char) of
            error ->
                throw({invalid_char, Char});
            Pos ->
                C2 = polymod(C, Pos band 31),
                NewCls = Cls * 3 + (Pos bsr 5),
                NewClsCount = ClsCount + 1,
                case NewClsCount =:= 3 of
                    true ->
                        {polymod(C2, NewCls), 0, 0};
                    false ->
                        {C2, NewCls, NewClsCount}
                end
        end
    end, {1, 0, 0}, Str),
    %% Handle remaining group bits
    C2 = case ClsCount1 > 0 of
        true -> polymod(C1, Cls1);
        false -> C1
    end,
    %% Shift for final checksum (8 iterations)
    C3 = lists:foldl(fun(_, Acc) -> polymod(Acc, 0) end, C2, lists:seq(1, 8)),
    %% XOR with 1 to prevent appending zeros
    CFinal = C3 bxor 1,
    %% Extract 8 5-bit groups
    ChecksumCharset = ?CHECKSUM_CHARSET,
    [lists:nth(((CFinal bsr (5 * (7 - I))) band 31) + 1, ChecksumCharset)
     || I <- lists:seq(0, 7)].

%% Find position of character in INPUT_CHARSET
char_position(Char) ->
    char_position(Char, ?INPUT_CHARSET, 0).

char_position(_Char, [], _Pos) -> error;
char_position(Char, [Char | _], Pos) -> Pos;
char_position(Char, [_ | Rest], Pos) -> char_position(Char, Rest, Pos + 1).

%%% ===================================================================
%%% Descriptor Parsing
%%% ===================================================================

verify_and_strip_checksum(DescStr, Opts) ->
    RequireChecksum = maps:get(require_checksum, Opts, false),
    case string:rchr(DescStr, $#) of
        0 when RequireChecksum ->
            {error, missing_checksum};
        0 ->
            {ok, DescStr};
        Pos ->
            Body = string:substr(DescStr, 1, Pos - 1),
            Given = string:substr(DescStr, Pos + 1),
            Expected = descriptor_checksum(Body),
            case Given =:= Expected of
                true -> {ok, Body};
                false -> {error, bad_checksum}
            end
    end.

parse_descriptor(Str) ->
    case parse_expr(Str) of
        {ok, Desc, []} ->
            {ok, Desc};
        {ok, _, Remaining} ->
            {error, {unexpected_trailing, Remaining}};
        {error, _} = Err ->
            Err
    end.

parse_expr(Str) ->
    %% Try to match function name
    case take_func_name(Str) of
        {FuncName, "(" ++ Rest} ->
            parse_func(FuncName, Rest);
        _ ->
            {error, {invalid_descriptor, Str}}
    end.

take_func_name(Str) ->
    take_func_name(Str, []).

take_func_name([], Acc) ->
    {lists:reverse(Acc), []};
take_func_name("(" ++ _ = Rest, Acc) ->
    {lists:reverse(Acc), Rest};
take_func_name([C | Rest], Acc) when C >= $a, C =< $z; C >= $A, C =< $Z; C =:= $_; C >= $0, C =< $9 ->
    take_func_name(Rest, [C | Acc]);
take_func_name(Rest, Acc) ->
    {lists:reverse(Acc), Rest}.

parse_func("pk", Rest) ->
    case parse_key(Rest, false) of
        {ok, Key, ")" ++ Remaining} ->
            {ok, #desc_pk{key = Key}, Remaining};
        {ok, _, _} ->
            {error, pk_missing_close_paren};
        {error, _} = Err ->
            Err
    end;

parse_func("pkh", Rest) ->
    case parse_key(Rest, false) of
        {ok, Key, ")" ++ Remaining} ->
            {ok, #desc_pkh{key = Key}, Remaining};
        {ok, _, _} ->
            {error, pkh_missing_close_paren};
        {error, _} = Err ->
            Err
    end;

parse_func("wpkh", Rest) ->
    case parse_key(Rest, false) of
        {ok, Key, ")" ++ Remaining} ->
            {ok, #desc_wpkh{key = Key}, Remaining};
        {ok, _, _} ->
            {error, wpkh_missing_close_paren};
        {error, _} = Err ->
            Err
    end;

parse_func("sh", Rest) ->
    case parse_expr(Rest) of
        {ok, Inner, ")" ++ Remaining} ->
            validate_sh_inner(Inner, Remaining);
        {ok, _, _} ->
            {error, sh_missing_close_paren};
        {error, _} = Err ->
            Err
    end;

parse_func("wsh", Rest) ->
    case parse_expr(Rest) of
        {ok, Inner, ")" ++ Remaining} ->
            validate_wsh_inner(Inner, Remaining);
        {ok, _, _} ->
            {error, wsh_missing_close_paren};
        {error, _} = Err ->
            Err
    end;

parse_func("multi", Rest) ->
    parse_multi(Rest, false);

parse_func("sortedmulti", Rest) ->
    parse_multi(Rest, true);

parse_func("tr", Rest) ->
    parse_tr(Rest);

parse_func("addr", Rest) ->
    case take_until_paren(Rest) of
        {Addr, ")" ++ Remaining} ->
            {ok, #desc_addr{address = Addr}, Remaining};
        _ ->
            {error, addr_missing_close_paren}
    end;

parse_func("raw", Rest) ->
    case take_until_paren(Rest) of
        {HexStr, ")" ++ Remaining} ->
            case hex_to_binary(HexStr) of
                {ok, Script} ->
                    {ok, #desc_raw{script = Script}, Remaining};
                error ->
                    {error, raw_invalid_hex}
            end;
        _ ->
            {error, raw_missing_close_paren}
    end;

parse_func("combo", Rest) ->
    case parse_key(Rest, false) of
        {ok, Key, ")" ++ Remaining} ->
            {ok, #desc_combo{key = Key}, Remaining};
        {ok, _, _} ->
            {error, combo_missing_close_paren};
        {error, _} = Err ->
            Err
    end;

%% BIP-386: rawtr(XONLY_KEY) — x-only pubkey used directly as P2TR output key (no tweak)
parse_func("rawtr", Rest) ->
    case parse_key(Rest, true) of
        {ok, Key, ")" ++ Remaining} ->
            {ok, #desc_rawtr{key = Key}, Remaining};
        {ok, _, _} ->
            {error, rawtr_missing_close_paren};
        {error, _} = Err ->
            Err
    end;

parse_func(Unknown, _) ->
    {error, {unknown_descriptor_type, Unknown}}.

%% Validate inner descriptor for sh()
validate_sh_inner(#desc_wpkh{} = Inner, Remaining) ->
    {ok, #desc_sh{inner = Inner}, Remaining};
validate_sh_inner(#desc_wsh{} = Inner, Remaining) ->
    {ok, #desc_sh{inner = Inner}, Remaining};
validate_sh_inner(#desc_multi{} = Inner, Remaining) ->
    {ok, #desc_sh{inner = Inner}, Remaining};
validate_sh_inner(#desc_pk{} = Inner, Remaining) ->
    {ok, #desc_sh{inner = Inner}, Remaining};
validate_sh_inner(#desc_pkh{} = Inner, Remaining) ->
    {ok, #desc_sh{inner = Inner}, Remaining};
validate_sh_inner(_, _) ->
    {error, sh_invalid_inner}.

%% Validate inner descriptor for wsh()
validate_wsh_inner(#desc_multi{} = Inner, Remaining) ->
    {ok, #desc_wsh{inner = Inner}, Remaining};
validate_wsh_inner(#desc_pk{} = Inner, Remaining) ->
    {ok, #desc_wsh{inner = Inner}, Remaining};
validate_wsh_inner(#desc_pkh{} = Inner, Remaining) ->
    {ok, #desc_wsh{inner = Inner}, Remaining};
validate_wsh_inner(_, _) ->
    {error, wsh_invalid_inner}.

%% Parse multi(k, key1, key2, ...)
parse_multi(Str, Sorted) ->
    case take_number(Str) of
        {Threshold, "," ++ Rest} when Threshold > 0 ->
            case parse_multi_keys(Rest, []) of
                {ok, Keys, ")" ++ Remaining} when length(Keys) >= Threshold ->
                    {ok, #desc_multi{threshold = Threshold, keys = Keys, sorted = Sorted}, Remaining};
                {ok, Keys, ")" ++ _} ->
                    {error, {multi_threshold_exceeds_keys, Threshold, length(Keys)}};
                {ok, _, _} ->
                    {error, multi_missing_close_paren};
                {error, _} = Err ->
                    Err
            end;
        {_, "," ++ _} ->
            {error, multi_invalid_threshold};
        _ ->
            {error, multi_missing_threshold}
    end.

parse_multi_keys(Str, Acc) ->
    case parse_key(Str, false) of
        {ok, Key, "," ++ Rest} ->
            parse_multi_keys(Rest, [Key | Acc]);
        {ok, Key, ")" ++ _ = Rest} ->
            {ok, lists:reverse([Key | Acc]), Rest};
        {ok, _, Rest} ->
            {error, {multi_unexpected_char, Rest}};
        {error, _} = Err ->
            Err
    end.

%% Parse tr(internal_key) or tr(internal_key, tree)
parse_tr(Str) ->
    case parse_key(Str, true) of
        {ok, InternalKey, ")" ++ Remaining} ->
            {ok, #desc_tr{internal_key = InternalKey, tree = []}, Remaining};
        {ok, InternalKey, "," ++ Rest} ->
            case parse_tr_tree(Rest) of
                {ok, Tree, ")" ++ Remaining} ->
                    {ok, #desc_tr{internal_key = InternalKey, tree = Tree}, Remaining};
                {ok, _, _} ->
                    {error, tr_missing_close_paren};
                {error, _} = Err ->
                    Err
            end;
        {ok, _, _} ->
            {error, tr_missing_close_paren};
        {error, _} = Err ->
            Err
    end.

%% Parse taproot script tree: {script} or {{script, script}, script} etc
parse_tr_tree("{" ++ Rest) ->
    parse_tr_branch(Rest, []);
parse_tr_tree(Str) ->
    %% Single leaf script
    case parse_expr(Str) of
        {ok, Script, Remaining} ->
            {ok, [{0, Script}], Remaining};
        {error, _} = Err ->
            Err
    end.

parse_tr_branch(Str, Acc) ->
    case Str of
        "{" ++ Rest ->
            %% Nested branch
            case parse_tr_branch(Rest, []) of
                {ok, SubTree, "," ++ Rest2} ->
                    %% More branches to come
                    parse_tr_branch(Rest2, Acc ++ increment_depth(SubTree));
                {ok, SubTree, "}" ++ Rest2} ->
                    {ok, Acc ++ increment_depth(SubTree), Rest2};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            %% Script leaf
            case parse_expr(Str) of
                {ok, Script, "," ++ Rest} ->
                    parse_tr_branch(Rest, Acc ++ [{0, Script}]);
                {ok, Script, "}" ++ Rest} ->
                    {ok, Acc ++ [{0, Script}], Rest};
                {ok, _, _} ->
                    {error, tr_tree_unexpected_char};
                {error, _} = Err ->
                    Err
            end
    end.

increment_depth(Tree) ->
    [{D + 1, S} || {D, S} <- Tree].

%%% ===================================================================
%%% Key Parsing
%%% ===================================================================

%% Parse a key expression: hex pubkey, WIF, xpub, xprv with optional origin and path
parse_key(Str, XOnly) ->
    %% Check for key origin: [fingerprint/path]key
    case Str of
        "[" ++ Rest ->
            case parse_key_origin(Rest) of
                {ok, Origin, "]" ++ KeyRest} ->
                    parse_key_inner(KeyRest, XOnly, Origin);
                {error, _} = Err ->
                    Err
            end;
        _ ->
            parse_key_inner(Str, XOnly, undefined)
    end.

parse_key_origin(Str) ->
    %% Format: fingerprint/path or just fingerprint
    case take_hex_chars(Str, 8) of
        {FpHex, "/" ++ Rest} when length(FpHex) =:= 8 ->
            case hex_to_binary(FpHex) of
                {ok, Fp} ->
                    case parse_derivation_path(Rest, []) of
                        {ok, Path, Remaining} ->
                            {ok, {Fp, Path}, Remaining};
                        {error, _} = Err ->
                            Err
                    end;
                error ->
                    {error, invalid_fingerprint}
            end;
        {FpHex, "]" ++ _ = Remaining} when length(FpHex) =:= 8 ->
            case hex_to_binary(FpHex) of
                {ok, Fp} ->
                    {ok, {Fp, []}, Remaining};
                error ->
                    {error, invalid_fingerprint}
            end;
        _ ->
            {error, invalid_origin}
    end.

parse_key_inner(Str, XOnly, Origin) ->
    %% Try to identify key type
    case take_key_string(Str) of
        {KeyStr, Remaining} ->
            case identify_and_parse_key(KeyStr, XOnly, Origin) of
                {ok, Key} ->
                    {ok, Key, Remaining};
                {error, _} = Err ->
                    Err
            end
    end.

take_key_string(Str) ->
    %% Take characters until we hit a delimiter
    take_key_string(Str, []).

take_key_string([], Acc) ->
    {lists:reverse(Acc), []};
take_key_string([C | _] = Rest, Acc) when C =:= $); C =:= $,; C =:= $}; C =:= $] ->
    {lists:reverse(Acc), Rest};
take_key_string([C | Rest], Acc) ->
    take_key_string(Rest, [C | Acc]).

identify_and_parse_key(KeyStr, XOnly, Origin) ->
    %% Check for xpub/xprv/tpub/tprv prefix
    case KeyStr of
        "xpub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "xprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
        "tpub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "tprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
        _ ->
            %% Try hex pubkey or WIF
            case length(KeyStr) of
                N when N =:= 66 orelse N =:= 130 orelse N =:= 64 ->
                    %% Hex public key (compressed, uncompressed, or x-only)
                    parse_hex_pubkey(KeyStr, XOnly, Origin);
                N when N >= 51 andalso N =< 52 ->
                    %% WIF private key
                    parse_wif_key(KeyStr, XOnly, Origin);
                _ ->
                    {error, {unknown_key_format, KeyStr}}
            end
    end.

parse_hex_pubkey(HexStr, XOnly, Origin) ->
    case hex_to_binary(HexStr) of
        {ok, Bin} when byte_size(Bin) =:= 33 ->
            %% Compressed pubkey
            Key = #const_key{pubkey = Bin, privkey = undefined, xonly = XOnly},
            maybe_add_origin(Key, Origin);
        {ok, Bin} when byte_size(Bin) =:= 65 ->
            %% Uncompressed pubkey
            Key = #const_key{pubkey = Bin, privkey = undefined, xonly = XOnly},
            maybe_add_origin(Key, Origin);
        {ok, Bin} when byte_size(Bin) =:= 32, XOnly ->
            %% X-only pubkey (for taproot)
            Key = #const_key{pubkey = Bin, privkey = undefined, xonly = true},
            maybe_add_origin(Key, Origin);
        {ok, _} ->
            {error, invalid_pubkey_length};
        error ->
            {error, invalid_hex_pubkey}
    end.

parse_wif_key(WifStr, XOnly, Origin) ->
    case decode_wif(WifStr) of
        {ok, PrivKey, _Compressed} ->
            {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
            FinalPubKey = case XOnly of
                true ->
                    <<_:8, X:32/binary>> = PubKey,
                    X;
                false ->
                    PubKey
            end,
            Key = #const_key{pubkey = FinalPubKey, privkey = PrivKey, xonly = XOnly},
            maybe_add_origin(Key, Origin);
        {error, _} = Err ->
            Err
    end.

parse_extended_key(KeyStr, XOnly, Origin, Type) ->
    %% Split base key from derivation path
    case string:chr(KeyStr, $/) of
        0 ->
            %% No derivation path
            parse_xkey_base(KeyStr, [], non_ranged, XOnly, Origin, Type);
        Pos ->
            BaseKey = string:substr(KeyStr, 1, Pos - 1),
            PathStr = string:substr(KeyStr, Pos + 1),
            case parse_xkey_path(PathStr) of
                {ok, Path, DeriveType} ->
                    parse_xkey_base(BaseKey, Path, DeriveType, XOnly, Origin, Type);
                {error, _} = Err ->
                    Err
            end
    end.

parse_xkey_base(BaseKeyStr, Path, DeriveType, XOnly, Origin, ExpectedType) ->
    case decode_xkey(BaseKeyStr) of
        {ok, Type, Key, ChainCode, Depth, Fp, _ChildIdx} when Type =:= ExpectedType ->
            BIP32Key = #bip32_key{
                extkey = {Type, Key, ChainCode},
                fingerprint = Fp,
                depth = Depth,
                path = [],
                derive_path = Path,
                derive_type = DeriveType,
                origin = Origin
            },
            {ok, set_xonly(BIP32Key, XOnly)};
        {ok, _, _, _, _, _, _} ->
            {error, key_type_mismatch};
        {error, _} = Err ->
            Err
    end.

set_xonly(#bip32_key{} = Key, true) ->
    Key#bip32_key{derive_type = Key#bip32_key.derive_type};  %% Mark for x-only output
set_xonly(Key, _) ->
    Key.

parse_xkey_path(PathStr) ->
    parse_xkey_path(PathStr, [], non_ranged).

parse_xkey_path([], Acc, DeriveType) ->
    {ok, lists:reverse(Acc), DeriveType};
parse_xkey_path("*" ++ Rest, Acc, _DeriveType) ->
    %% Wildcard - check for hardened
    case Rest of
        "'" ++ Rest2 ->
            parse_xkey_path_after_wildcard(Rest2, Acc, hardened);
        "h" ++ Rest2 ->
            parse_xkey_path_after_wildcard(Rest2, Acc, hardened);
        _ ->
            parse_xkey_path_after_wildcard(Rest, Acc, unhardened)
    end;
parse_xkey_path(Str, Acc, DeriveType) ->
    case take_path_element(Str) of
        {Elem, Hardened, "/" ++ Rest} ->
            Idx = case Hardened of
                true -> Elem + ?HARDENED;
                false -> Elem
            end,
            parse_xkey_path(Rest, [Idx | Acc], DeriveType);
        {Elem, Hardened, Rest} ->
            Idx = case Hardened of
                true -> Elem + ?HARDENED;
                false -> Elem
            end,
            parse_xkey_path(Rest, [Idx | Acc], DeriveType);
        error ->
            {error, invalid_path_element}
    end.

parse_xkey_path_after_wildcard([], Acc, DeriveType) ->
    {ok, lists:reverse(Acc), DeriveType};
parse_xkey_path_after_wildcard("/" ++ Rest, Acc, DeriveType) ->
    %% Path continues after wildcard - this is the derive_path
    parse_xkey_path(Rest, Acc, DeriveType);
parse_xkey_path_after_wildcard(_, _, _) ->
    {error, invalid_path_after_wildcard}.

take_path_element(Str) ->
    case take_number(Str) of
        {N, "'" ++ Rest} -> {N, true, Rest};
        {N, "h" ++ Rest} -> {N, true, Rest};
        {N, Rest} -> {N, false, Rest};
        error -> error
    end.

maybe_add_origin(Key, undefined) ->
    {ok, Key};
maybe_add_origin(#const_key{} = Key, _Origin) ->
    %% Origins on const keys just get ignored for now
    {ok, Key};
maybe_add_origin(#bip32_key{} = Key, Origin) ->
    {ok, Key#bip32_key{origin = Origin}}.

%%% ===================================================================
%%% Derivation path parsing for origins
%%% ===================================================================

parse_derivation_path(Str, Acc) ->
    case take_path_element(Str) of
        {Elem, Hardened, "/" ++ Rest} ->
            Idx = case Hardened of
                true -> Elem + ?HARDENED;
                false -> Elem
            end,
            parse_derivation_path(Rest, [Idx | Acc]);
        {Elem, Hardened, Rest} ->
            Idx = case Hardened of
                true -> Elem + ?HARDENED;
                false -> Elem
            end,
            {ok, lists:reverse([Idx | Acc]), Rest};
        error when Acc =:= [] ->
            {ok, [], Str};
        error ->
            {error, invalid_derivation_path}
    end.

%%% ===================================================================
%%% Key derivation
%%% ===================================================================

derive_key(#desc_pk{key = Key} = Desc, Index) ->
    case derive_single_key(Key, Index) of
        {ok, DerivedKey} -> {ok, Desc#desc_pk{key = DerivedKey}};
        {error, _} = Err -> Err
    end;
derive_key(#desc_pkh{key = Key} = Desc, Index) ->
    case derive_single_key(Key, Index) of
        {ok, DerivedKey} -> {ok, Desc#desc_pkh{key = DerivedKey}};
        {error, _} = Err -> Err
    end;
derive_key(#desc_wpkh{key = Key} = Desc, Index) ->
    case derive_single_key(Key, Index) of
        {ok, DerivedKey} -> {ok, Desc#desc_wpkh{key = DerivedKey}};
        {error, _} = Err -> Err
    end;
derive_key(#desc_sh{inner = Inner} = Desc, Index) ->
    case derive_key(Inner, Index) of
        {ok, DerivedInner} -> {ok, Desc#desc_sh{inner = DerivedInner}};
        {error, _} = Err -> Err
    end;
derive_key(#desc_wsh{inner = Inner} = Desc, Index) ->
    case derive_key(Inner, Index) of
        {ok, DerivedInner} -> {ok, Desc#desc_wsh{inner = DerivedInner}};
        {error, _} = Err -> Err
    end;
derive_key(#desc_multi{keys = Keys} = Desc, Index) ->
    case derive_keys(Keys, Index) of
        {ok, DerivedKeys} -> {ok, Desc#desc_multi{keys = DerivedKeys}};
        {error, _} = Err -> Err
    end;
derive_key(#desc_tr{internal_key = Key, tree = Tree} = Desc, Index) ->
    case derive_single_key(Key, Index) of
        {ok, DerivedKey} ->
            case derive_tree(Tree, Index) of
                {ok, DerivedTree} ->
                    {ok, Desc#desc_tr{internal_key = DerivedKey, tree = DerivedTree}};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end;
derive_key(#desc_combo{key = Key} = Desc, Index) ->
    case derive_single_key(Key, Index) of
        {ok, DerivedKey} -> {ok, Desc#desc_combo{key = DerivedKey}};
        {error, _} = Err -> Err
    end;
derive_key(#desc_rawtr{key = Key} = Desc, Index) ->
    case derive_single_key(Key, Index) of
        {ok, DerivedKey} -> {ok, Desc#desc_rawtr{key = DerivedKey}};
        {error, _} = Err -> Err
    end;
derive_key(Desc, _Index) ->
    %% addr and raw don't need derivation
    {ok, Desc}.

derive_single_key(#const_key{} = Key, _Index) ->
    %% Const keys don't derive
    {ok, Key};
derive_single_key(#bip32_key{derive_type = non_ranged} = Key, _Index) ->
    %% Non-ranged just derives the static path
    derive_bip32_static(Key);
derive_single_key(#bip32_key{derive_type = DeriveType, derive_path = Path} = Key, Index) ->
    %% Ranged: derive path + index
    Idx = case DeriveType of
        unhardened -> Index;
        hardened -> Index + ?HARDENED
    end,
    derive_bip32_path(Key, Path ++ [Idx]).

derive_bip32_static(#bip32_key{derive_path = []} = Key) ->
    %% Already at the right position
    bip32_to_const(Key);
derive_bip32_static(#bip32_key{derive_path = Path} = Key) ->
    derive_bip32_path(Key, Path).

derive_bip32_path(#bip32_key{extkey = {Type, KeyData, ChainCode}}, Path) ->
    %% Implement BIP32 child key derivation inline
    {FinalKey, FinalChain, FinalPriv} = case Type of
        pub ->
            derive_bip32_pubkey_path(KeyData, ChainCode, Path);
        priv ->
            derive_bip32_privkey_path(KeyData, ChainCode, Path)
    end,
    PubKey = case Type of
        pub -> FinalKey;
        priv ->
            {ok, PK} = beamchain_crypto:pubkey_from_privkey(FinalKey),
            PK
    end,
    _ = FinalChain,  %% Not needed for const_key
    {ok, #const_key{pubkey = PubKey, privkey = FinalPriv, xonly = false}}.

%% Derive through path using public key only (unhardened only)
derive_bip32_pubkey_path(PubKey, ChainCode, []) ->
    {PubKey, ChainCode, undefined};
derive_bip32_pubkey_path(PubKey, ChainCode, [Index | Rest]) when Index < ?HARDENED ->
    %% Unhardened derivation with public key
    Data = <<PubKey/binary, Index:32/big>>,
    <<IL:32/binary, IR:32/binary>> = beamchain_crypto:hmac_sha512(ChainCode, Data),
    {ok, ChildPub} = beamchain_crypto:pubkey_tweak_add(PubKey, IL),
    derive_bip32_pubkey_path(ChildPub, IR, Rest);
derive_bip32_pubkey_path(_PubKey, _ChainCode, [Index | _]) when Index >= ?HARDENED ->
    %% Cannot do hardened derivation without private key
    throw(hardened_derivation_requires_private_key).

%% Derive through path using private key (can do hardened)
derive_bip32_privkey_path(PrivKey, ChainCode, []) ->
    {PrivKey, ChainCode, PrivKey};
derive_bip32_privkey_path(PrivKey, ChainCode, [Index | Rest]) ->
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    Data = case Index >= ?HARDENED of
        true -> <<0, PrivKey/binary, Index:32/big>>;
        false -> <<PubKey/binary, Index:32/big>>
    end,
    <<IL:32/binary, IR:32/binary>> = beamchain_crypto:hmac_sha512(ChainCode, Data),
    {ok, ChildPriv} = beamchain_crypto:seckey_tweak_add(PrivKey, IL),
    derive_bip32_privkey_path(ChildPriv, IR, Rest).

bip32_to_const(#bip32_key{extkey = {Type, KeyData, _ChainCode}}) ->
    case Type of
        pub ->
            {ok, #const_key{pubkey = KeyData, privkey = undefined, xonly = false}};
        priv ->
            {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(KeyData),
            {ok, #const_key{pubkey = PubKey, privkey = KeyData, xonly = false}}
    end.

derive_keys(Keys, Index) ->
    derive_keys(Keys, Index, []).

derive_keys([], _Index, Acc) ->
    {ok, lists:reverse(Acc)};
derive_keys([Key | Rest], Index, Acc) ->
    case derive_single_key(Key, Index) of
        {ok, Derived} -> derive_keys(Rest, Index, [Derived | Acc]);
        {error, _} = Err -> Err
    end.

derive_tree(Tree, Index) ->
    derive_tree(Tree, Index, []).

derive_tree([], _Index, Acc) ->
    {ok, lists:reverse(Acc)};
derive_tree([{Depth, Script} | Rest], Index, Acc) ->
    case derive_key(Script, Index) of
        {ok, Derived} -> derive_tree(Rest, Index, [{Depth, Derived} | Acc]);
        {error, _} = Err -> Err
    end.

%%% ===================================================================
%%% Script generation
%%% ===================================================================

script_from_desc(#desc_pk{key = Key}, _Network) ->
    PubKey = get_pubkey(Key),
    %% pk(KEY) -> <pubkey> OP_CHECKSIG
    {ok, <<(push_data(PubKey))/binary, 16#ac>>};

script_from_desc(#desc_pkh{key = Key}, _Network) ->
    PubKey = get_pubkey(Key),
    Hash = beamchain_crypto:hash160(PubKey),
    %% pkh(KEY) -> OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    {ok, <<16#76, 16#a9, 16#14, Hash/binary, 16#88, 16#ac>>};

script_from_desc(#desc_wpkh{key = Key}, _Network) ->
    PubKey = get_pubkey(Key),
    Hash = beamchain_crypto:hash160(PubKey),
    %% wpkh(KEY) -> OP_0 <20>
    {ok, <<16#00, 16#14, Hash/binary>>};

script_from_desc(#desc_sh{inner = Inner}, Network) ->
    case script_from_desc(Inner, Network) of
        {ok, InnerScript} ->
            Hash = beamchain_crypto:hash160(InnerScript),
            %% sh(SCRIPT) -> OP_HASH160 <20> OP_EQUAL
            {ok, <<16#a9, 16#14, Hash/binary, 16#87>>};
        {error, _} = Err ->
            Err
    end;

script_from_desc(#desc_wsh{inner = Inner}, Network) ->
    case script_from_desc(Inner, Network) of
        {ok, InnerScript} ->
            Hash = beamchain_crypto:sha256(InnerScript),
            %% wsh(SCRIPT) -> OP_0 <32>
            {ok, <<16#00, 16#20, Hash/binary>>};
        {error, _} = Err ->
            Err
    end;

script_from_desc(#desc_multi{threshold = K, keys = Keys, sorted = Sorted}, _Network) ->
    PubKeys = [get_pubkey(Key) || Key <- Keys],
    %% Sort if sortedmulti
    SortedPubKeys = case Sorted of
        true -> lists:sort(PubKeys);
        false -> PubKeys
    end,
    N = length(SortedPubKeys),
    %% multi(k, keys...) -> OP_k <pubkey1> ... <pubkeyn> OP_n OP_CHECKMULTISIG
    OpK = op_n(K),
    OpN = op_n(N),
    KeysPushes = iolist_to_binary([push_data(PK) || PK <- SortedPubKeys]),
    {ok, <<OpK, KeysPushes/binary, OpN, 16#ae>>};

script_from_desc(#desc_tr{internal_key = Key, tree = []}, _Network) ->
    %% Key-path only taproot
    PubKey = get_pubkey(Key),
    XOnly = case byte_size(PubKey) of
        33 -> <<_:8, X:32/binary>> = PubKey, X;
        32 -> PubKey
    end,
    %% Apply BIP341 tweak
    Tweak = beamchain_crypto:tagged_hash(<<"TapTweak">>, XOnly),
    {ok, OutputKey, _Parity} = beamchain_crypto:xonly_pubkey_tweak_add(XOnly, Tweak),
    %% tr(KEY) -> OP_1 <32>
    {ok, <<16#51, 16#20, OutputKey/binary>>};

script_from_desc(#desc_tr{internal_key = Key, tree = Tree}, _Network) ->
    %% Taproot with script tree
    PubKey = get_pubkey(Key),
    XOnly = case byte_size(PubKey) of
        33 -> <<_:8, X:32/binary>> = PubKey, X;
        32 -> PubKey
    end,
    %% Build Merkle root from tree
    MerkleRoot = build_taproot_merkle(Tree),
    %% Tweak with merkle root
    TweakData = <<XOnly/binary, MerkleRoot/binary>>,
    Tweak = beamchain_crypto:tagged_hash(<<"TapTweak">>, TweakData),
    {ok, OutputKey, _Parity} = beamchain_crypto:xonly_pubkey_tweak_add(XOnly, Tweak),
    {ok, <<16#51, 16#20, OutputKey/binary>>};

script_from_desc(#desc_rawtr{key = Key}, _Network) ->
    %% BIP-386: rawtr(KEY) -> OP_1 <32-byte-x-only-pubkey> (no tweak applied)
    PubKey = get_pubkey(Key),
    XOnly = case byte_size(PubKey) of
        33 -> <<_:8, X:32/binary>> = PubKey, X;
        32 -> PubKey
    end,
    {ok, <<16#51, 16#20, XOnly/binary>>};

script_from_desc(#desc_addr{address = Addr}, Network) ->
    beamchain_address:address_to_script(Addr, Network);

script_from_desc(#desc_raw{script = Script}, _Network) ->
    {ok, Script};

script_from_desc(#desc_combo{key = Key}, _Network) ->
    %% combo produces multiple scripts; return the most useful one (wpkh if compressed)
    PubKey = get_pubkey(Key),
    case byte_size(PubKey) of
        33 ->
            %% Compressed: return P2WPKH
            Hash = beamchain_crypto:hash160(PubKey),
            {ok, <<16#00, 16#14, Hash/binary>>};
        65 ->
            %% Uncompressed: return P2PKH
            Hash = beamchain_crypto:hash160(PubKey),
            {ok, <<16#76, 16#a9, 16#14, Hash/binary, 16#88, 16#ac>>};
        _ ->
            {error, invalid_pubkey_for_combo}
    end.

get_pubkey(#const_key{pubkey = PK}) -> PK;
get_pubkey(#bip32_key{extkey = {pub, PK, _}}) -> PK;
get_pubkey(#bip32_key{extkey = {priv, PrivKey, _}}) ->
    {ok, PK} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    PK.

push_data(Data) when byte_size(Data) =< 75 ->
    <<(byte_size(Data)), Data/binary>>;
push_data(Data) when byte_size(Data) =< 255 ->
    <<16#4c, (byte_size(Data)):8, Data/binary>>;
push_data(Data) when byte_size(Data) =< 65535 ->
    <<16#4d, (byte_size(Data)):16/little, Data/binary>>;
push_data(Data) ->
    <<16#4e, (byte_size(Data)):32/little, Data/binary>>.

op_n(N) when N >= 1, N =< 16 -> 16#50 + N;
op_n(0) -> 16#00.

build_taproot_merkle([]) ->
    <<0:256>>;
build_taproot_merkle([{_Depth, _Script}] = Leaves) ->
    %% Single leaf - compute its hash
    leaf_hash(Leaves);
build_taproot_merkle(Leaves) ->
    %% Build tree from leaves
    %% This is simplified - real implementation needs depth handling
    build_taproot_merkle_tree(Leaves).

leaf_hash([{_Depth, Script}]) ->
    %% TapLeaf hash
    case script_from_desc(Script, mainnet) of
        {ok, ScriptBytes} ->
            LeafData = <<16#c0, (compact_size(byte_size(ScriptBytes)))/binary, ScriptBytes/binary>>,
            beamchain_crypto:tagged_hash(<<"TapLeaf">>, LeafData);
        _ ->
            <<0:256>>
    end.

build_taproot_merkle_tree([{_, _} = Single]) ->
    leaf_hash([Single]);
build_taproot_merkle_tree(Leaves) ->
    %% Pair up leaves and hash
    Hashes = [leaf_hash([L]) || L <- Leaves],
    build_merkle_level(Hashes).

build_merkle_level([H]) -> H;
build_merkle_level(Hashes) ->
    Paired = pair_hashes(Hashes),
    build_merkle_level(Paired).

pair_hashes([]) -> [];
pair_hashes([H]) -> [H];
pair_hashes([H1, H2 | Rest]) ->
    %% Sort and hash
    {A, B} = case H1 < H2 of
        true -> {H1, H2};
        false -> {H2, H1}
    end,
    Combined = beamchain_crypto:tagged_hash(<<"TapBranch">>, <<A/binary, B/binary>>),
    [Combined | pair_hashes(Rest)].

compact_size(N) when N < 253 -> <<N>>;
compact_size(N) when N =< 16#ffff -> <<253, N:16/little>>;
compact_size(N) when N =< 16#ffffffff -> <<254, N:32/little>>;
compact_size(N) -> <<255, N:64/little>>.

%%% ===================================================================
%%% Extended Key Encoding/Decoding
%%% ===================================================================

%% Version bytes
-define(MAINNET_XPUB, <<16#04, 16#88, 16#b2, 16#1e>>).
-define(MAINNET_XPRV, <<16#04, 16#88, 16#ad, 16#e4>>).
-define(TESTNET_TPUB, <<16#04, 16#35, 16#87, 16#cf>>).
-define(TESTNET_TPRV, <<16#04, 16#35, 16#83, 16#94>>).

-spec decode_xpub(string()) -> {ok, binary(), binary()} | {error, term()}.
decode_xpub(Str) ->
    case decode_xkey(Str) of
        {ok, pub, Key, ChainCode, _D, _Fp, _Idx} -> {ok, Key, ChainCode};
        {ok, priv, _, _, _, _, _} -> {error, not_xpub};
        {error, _} = Err -> Err
    end.

-spec decode_xprv(string()) -> {ok, binary(), binary()} | {error, term()}.
decode_xprv(Str) ->
    case decode_xkey(Str) of
        {ok, priv, Key, ChainCode, _D, _Fp, _Idx} -> {ok, Key, ChainCode};
        {ok, pub, _, _, _, _, _} -> {error, not_xprv};
        {error, _} = Err -> Err
    end.

decode_xkey(Str) ->
    %% xpub/xprv uses 4-byte version prefix, not 1-byte like addresses
    %% So we need to re-decode the raw base58 without treating first byte as version
    case decode_base58_raw(Str) of
        {ok, RawBytes} when byte_size(RawBytes) =:= 82 ->
            %% 78 bytes data + 4 bytes checksum
            <<Data:78/binary, Checksum:4/binary>> = RawBytes,
            <<ExpectedCs:4/binary, _/binary>> = beamchain_crypto:hash256(Data),
            case Checksum =:= ExpectedCs of
                false ->
                    {error, bad_checksum};
                true ->
                    <<Version:4/binary, Depth:8, Fingerprint:4/binary,
                      ChildIndex:32/big, ChainCode:32/binary, KeyData:33/binary>> = Data,
                    case Version of
                        <<16#04, 16#88, 16#b2, 16#1e>> -> %% xpub
                            {ok, pub, KeyData, ChainCode, Depth, Fingerprint, ChildIndex};
                        <<16#04, 16#88, 16#ad, 16#e4>> -> %% xprv
                            <<0, PrivKey:32/binary>> = KeyData,
                            {ok, priv, PrivKey, ChainCode, Depth, Fingerprint, ChildIndex};
                        <<16#04, 16#35, 16#87, 16#cf>> -> %% tpub
                            {ok, pub, KeyData, ChainCode, Depth, Fingerprint, ChildIndex};
                        <<16#04, 16#35, 16#83, 16#94>> -> %% tprv
                            <<0, PrivKey:32/binary>> = KeyData,
                            {ok, priv, PrivKey, ChainCode, Depth, Fingerprint, ChildIndex};
                        _ ->
                            {error, unknown_xkey_version}
                    end
            end;
        {ok, _} ->
            {error, invalid_xkey_length};
        {error, _} = Err ->
            Err
    end.

%% Decode base58 string to raw bytes (no version/checksum handling)
decode_base58_raw(Str) ->
    Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    {LeadingOnes, Rest} = count_leading_ones(Str),
    case decode_base58_chars(Rest, Alphabet, 0) of
        {error, _} = E -> E;
        {ok, N} ->
            NumBytes = if N =:= 0 -> <<>>; true -> binary:encode_unsigned(N, big) end,
            Padding = binary:copy(<<0>>, LeadingOnes),
            {ok, <<Padding/binary, NumBytes/binary>>}
    end.

count_leading_ones([$1 | Rest]) ->
    {Count, Remaining} = count_leading_ones(Rest),
    {Count + 1, Remaining};
count_leading_ones(Str) ->
    {0, Str}.

decode_base58_chars([], _Alphabet, Acc) -> {ok, Acc};
decode_base58_chars([C | Rest], Alphabet, Acc) ->
    case base58_char_val(C, Alphabet) of
        error -> {error, {invalid_base58_char, C}};
        Val -> decode_base58_chars(Rest, Alphabet, Acc * 58 + Val)
    end.

base58_char_val(C, Alphabet) ->
    case string:chr(Alphabet, C) of
        0 -> error;
        Pos -> Pos - 1
    end.

-spec encode_xpub(binary(), binary(), atom()) -> string().
encode_xpub(PubKey, ChainCode, Network) when byte_size(PubKey) =:= 33, byte_size(ChainCode) =:= 32 ->
    Version = case Network of
        mainnet -> 16#0488b21e;
        _ -> 16#043587cf
    end,
    Payload = <<Version:32/big, 0, 0:32, 0:32, ChainCode/binary, PubKey/binary>>,
    base58check_encode_raw(Payload).

-spec encode_xprv(binary(), binary(), atom()) -> string().
encode_xprv(PrivKey, ChainCode, Network) when byte_size(PrivKey) =:= 32, byte_size(ChainCode) =:= 32 ->
    Version = case Network of
        mainnet -> 16#0488ade4;
        _ -> 16#04358394
    end,
    Payload = <<Version:32/big, 0, 0:32, 0:32, ChainCode/binary, 0, PrivKey/binary>>,
    base58check_encode_raw(Payload).

base58check_encode_raw(Data) ->
    <<Checksum:4/binary, _/binary>> = beamchain_crypto:hash256(Data),
    WithChecksum = <<Data/binary, Checksum/binary>>,
    LeadingZeros = count_leading_zeros(WithChecksum),
    Prefix = lists:duplicate(LeadingZeros, $1),
    N = binary:decode_unsigned(WithChecksum, big),
    Prefix ++ encode_base58_int(N).

count_leading_zeros(<<0, Rest/binary>>) -> 1 + count_leading_zeros(Rest);
count_leading_zeros(_) -> 0.

encode_base58_int(0) -> [];
encode_base58_int(N) ->
    Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    encode_base58_int(N, Alphabet, []).

encode_base58_int(0, _, Acc) -> Acc;
encode_base58_int(N, Alphabet, Acc) ->
    Rem = N rem 58,
    Char = lists:nth(Rem + 1, Alphabet),
    encode_base58_int(N div 58, Alphabet, [Char | Acc]).

%%% ===================================================================
%%% WIF Decoding
%%% ===================================================================

decode_wif(WifStr) ->
    case beamchain_address:base58check_decode(WifStr) of
        {ok, {16#80, <<PrivKey:32/binary, 16#01>>}} ->
            %% Mainnet compressed
            {ok, PrivKey, true};
        {ok, {16#80, <<PrivKey:32/binary>>}} ->
            %% Mainnet uncompressed
            {ok, PrivKey, false};
        {ok, {16#ef, <<PrivKey:32/binary, 16#01>>}} ->
            %% Testnet compressed
            {ok, PrivKey, true};
        {ok, {16#ef, <<PrivKey:32/binary>>}} ->
            %% Testnet uncompressed
            {ok, PrivKey, false};
        {ok, _} ->
            {error, invalid_wif_format};
        {error, _} = Err ->
            Err
    end.

%%% ===================================================================
%%% Descriptor formatting
%%% ===================================================================

format_descriptor(#desc_pk{key = Key}) ->
    "pk(" ++ format_key(Key) ++ ")";
format_descriptor(#desc_pkh{key = Key}) ->
    "pkh(" ++ format_key(Key) ++ ")";
format_descriptor(#desc_wpkh{key = Key}) ->
    "wpkh(" ++ format_key(Key) ++ ")";
format_descriptor(#desc_sh{inner = Inner}) ->
    "sh(" ++ format_descriptor(Inner) ++ ")";
format_descriptor(#desc_wsh{inner = Inner}) ->
    "wsh(" ++ format_descriptor(Inner) ++ ")";
format_descriptor(#desc_multi{threshold = K, keys = Keys, sorted = Sorted}) ->
    Func = case Sorted of true -> "sortedmulti"; false -> "multi" end,
    KeyStrs = [format_key(Key) || Key <- Keys],
    Func ++ "(" ++ integer_to_list(K) ++ "," ++ string:join(KeyStrs, ",") ++ ")";
format_descriptor(#desc_tr{internal_key = Key, tree = []}) ->
    "tr(" ++ format_key(Key) ++ ")";
format_descriptor(#desc_tr{internal_key = Key, tree = Tree}) ->
    "tr(" ++ format_key(Key) ++ "," ++ format_tree(Tree) ++ ")";
format_descriptor(#desc_addr{address = Addr}) ->
    "addr(" ++ Addr ++ ")";
format_descriptor(#desc_raw{script = Script}) ->
    "raw(" ++ binary_to_hex(Script) ++ ")";
format_descriptor(#desc_rawtr{key = Key}) ->
    "rawtr(" ++ format_key(Key) ++ ")";
format_descriptor(#desc_combo{key = Key}) ->
    "combo(" ++ format_key(Key) ++ ")".

format_key(#const_key{pubkey = PK}) ->
    binary_to_hex(PK);
format_key(#bip32_key{extkey = {Type, Key, ChainCode}, derive_path = Path, derive_type = DeriveType}) ->
    %% Simplified - would need full xpub encoding
    BaseKey = case Type of
        pub -> encode_xpub(Key, ChainCode, mainnet);
        priv -> encode_xprv(Key, ChainCode, mainnet)
    end,
    PathStr = format_derive_path(Path, DeriveType),
    BaseKey ++ PathStr.

format_derive_path([], non_ranged) -> "";
format_derive_path(Path, DeriveType) ->
    PathParts = [format_path_element(P) || P <- Path],
    Wildcard = case DeriveType of
        non_ranged -> "";
        unhardened -> "/*";
        hardened -> "/*'"
    end,
    "/" ++ string:join(PathParts, "/") ++ Wildcard.

format_path_element(N) when N >= ?HARDENED ->
    integer_to_list(N - ?HARDENED) ++ "'";
format_path_element(N) ->
    integer_to_list(N).

format_tree([]) -> "";
format_tree([{_, Script}]) ->
    format_descriptor(Script);
format_tree(Tree) ->
    %% Simplified tree formatting
    Parts = [format_descriptor(S) || {_, S} <- Tree],
    "{" ++ string:join(Parts, ",") ++ "}".

%%% ===================================================================
%%% Helper functions
%%% ===================================================================

is_key_range(#const_key{}) -> false;
is_key_range(#bip32_key{derive_type = non_ranged}) -> false;
is_key_range(#bip32_key{}) -> true.

key_has_private(#const_key{privkey = undefined}) -> false;
key_has_private(#const_key{}) -> true;
key_has_private(#bip32_key{extkey = {priv, _, _}}) -> true;
key_has_private(#bip32_key{}) -> false.

take_until_paren(Str) ->
    take_until_paren(Str, []).

take_until_paren([], Acc) ->
    {lists:reverse(Acc), []};
take_until_paren(")" ++ _ = Rest, Acc) ->
    {lists:reverse(Acc), Rest};
take_until_paren([C | Rest], Acc) ->
    take_until_paren(Rest, [C | Acc]).

take_number(Str) ->
    take_number(Str, 0, false).

take_number([], Acc, true) -> {Acc, []};
take_number([], _, false) -> error;
take_number([C | Rest], Acc, _) when C >= $0, C =< $9 ->
    take_number(Rest, Acc * 10 + (C - $0), true);
take_number(Rest, Acc, true) ->
    {Acc, Rest};
take_number(_, _, false) ->
    error.

take_hex_chars(Str, Max) ->
    take_hex_chars(Str, Max, []).

take_hex_chars([], _Max, Acc) ->
    {lists:reverse(Acc), []};
take_hex_chars(Rest, 0, Acc) ->
    {lists:reverse(Acc), Rest};
take_hex_chars([C | Rest], Max, Acc) when (C >= $0 andalso C =< $9);
                                           (C >= $a andalso C =< $f);
                                           (C >= $A andalso C =< $F) ->
    take_hex_chars(Rest, Max - 1, [C | Acc]);
take_hex_chars(Rest, _Max, Acc) ->
    {lists:reverse(Acc), Rest}.

hex_to_binary(HexStr) ->
    try
        Bin = list_to_binary([list_to_integer([H1, H2], 16)
                              || [H1, H2] <- chunk_pairs(HexStr)]),
        {ok, Bin}
    catch
        _:_ -> error
    end.

chunk_pairs([]) -> [];
chunk_pairs([A, B | Rest]) -> [[A, B] | chunk_pairs(Rest)];
chunk_pairs([_]) -> throw(odd_hex_length).

binary_to_hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).
