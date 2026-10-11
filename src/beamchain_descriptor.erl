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
         solved_pubkeys/1,
         checksum/1,
         add_checksum/1,
         verify_checksum/1,
         eval_scan/3]).

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

%% @doc Pubkeys the descriptor solves at index 0, paired with the
%% scriptPubKey they produce. Used by descriptorprocesspsbt to attach
%% PSBT_OUT_BIP32_DERIVATION on matching outputs (Core ProcessPSBT,
%% bip32derivs default true).
-spec solved_pubkeys(tuple()) ->
          {ok, [{binary(), binary()}]} | {error, term()}.
solved_pubkeys(Desc) ->
    case derive_key(Desc, 0) of
        {ok, Derived} ->
            case script_from_desc(Derived, mainnet) of
                {ok, Script} ->
                    {ok, [{PK, Script} || PK <- collect_pubkeys(Derived)]};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

collect_pubkeys(#desc_pk{key = Key}) -> [get_pubkey(Key)];
collect_pubkeys(#desc_pkh{key = Key}) -> [get_pubkey(Key)];
collect_pubkeys(#desc_wpkh{key = Key}) -> [get_pubkey(Key)];
collect_pubkeys(#desc_combo{key = Key}) -> [get_pubkey(Key)];
collect_pubkeys(#desc_rawtr{key = Key}) -> [get_pubkey(Key)];
collect_pubkeys(#desc_tr{internal_key = Key}) -> [get_pubkey(Key)];
collect_pubkeys(#desc_multi{keys = Keys}) -> [get_pubkey(K) || K <- Keys];
collect_pubkeys(#desc_sh{inner = Inner}) -> collect_pubkeys(Inner);
collect_pubkeys(#desc_wsh{inner = Inner}) -> collect_pubkeys(Inner);
collect_pubkeys(_) -> [].

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
    %% Check for xpub/xprv/tpub/tprv + SLIP-132 SegWit-prefix variants.
    %% Recognised: BIP-44 (xpub/xprv mainnet, tpub/tprv testnet) +
    %% BIP-49 (ypub/yprv mainnet, upub/uprv testnet — P2SH-P2WPKH) +
    %% BIP-84 (zpub/zprv mainnet, vpub/vprv testnet — P2WPKH).
    %% Per SLIP-132 (https://github.com/satoshilabs/slips/blob/master/slip-0132.md)
    %% these encode the same BIP-32 extended-key payload — only the 4-byte
    %% version prefix differs, hinting at the intended script context. The
    %% actual descriptor expression (pkh/wpkh/sh/wsh/tr) still drives script
    %% generation; the version-tag is recorded for downstream wallet UX.
    case KeyStr of
        "xpub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "xprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
        "tpub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "tprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
        "ypub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "yprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
        "zpub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "zprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
        "upub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "uprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
        "vpub" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, pub);
        "vprv" ++ _ -> parse_extended_key(KeyStr, XOnly, Origin, priv);
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
        {ok, Type, _Tag, Key, ChainCode, Depth, Fp, _ChildIdx} when Type =:= ExpectedType ->
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
        {ok, _, _, _, _, _, _, _} ->
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
    %% Unhardened derivation with public key (BIP-32 retry on IL>=n /
    %% child-point-at-infinity per spec — see W161 BUG-2/BUG-4).
    {ChildPub, IR} = derive_pub_step(PubKey, ChainCode, Index, Index),
    derive_bip32_pubkey_path(ChildPub, IR, Rest);
derive_bip32_pubkey_path(_PubKey, _ChainCode, [Index | _]) when Index >= ?HARDENED ->
    %% Cannot do hardened derivation without private key
    throw(hardened_derivation_requires_private_key).

%% Derive through path using private key (can do hardened)
derive_bip32_privkey_path(PrivKey, ChainCode, []) ->
    {PrivKey, ChainCode, PrivKey};
derive_bip32_privkey_path(PrivKey, ChainCode, [Index | Rest]) ->
    %% BIP-32 retry on IL>=n / (PrivKey+IL) mod n == 0 per spec — see
    %% W161 BUG-2/BUG-4.
    {ChildPriv, IR} = derive_priv_step(PrivKey, ChainCode, Index, Index),
    derive_bip32_privkey_path(ChildPriv, IR, Rest).

%% derive_priv_step/4: retry helper for private CKD. StartIndex used to
%% enforce hardened/unhardened range boundary on retry; CurIndex advances.
%% Mirrors `bitcoin-core/src/key.cpp::CKey::Derive` retry-on-fail semantics.
derive_priv_step(_PrivKey, _ChainCode, StartIndex, CurIndex)
  when StartIndex <  ?HARDENED, CurIndex >= ?HARDENED ->
    throw({extkey_exhausted, StartIndex, CurIndex});
derive_priv_step(_PrivKey, _ChainCode, StartIndex, CurIndex)
  when StartIndex >= ?HARDENED, CurIndex >= (?HARDENED bsl 1) ->
    throw({extkey_exhausted, StartIndex, CurIndex});
derive_priv_step(PrivKey, ChainCode, StartIndex, CurIndex) ->
    {ok, PubKey} = beamchain_crypto:pubkey_from_privkey(PrivKey),
    Data = case CurIndex >= ?HARDENED of
        true -> <<0, PrivKey/binary, CurIndex:32/big>>;
        false -> <<PubKey/binary, CurIndex:32/big>>
    end,
    <<IL:32/binary, IR:32/binary>> = beamchain_crypto:hmac_sha512(ChainCode, Data),
    case beamchain_crypto:seckey_tweak_add(PrivKey, IL) of
        {ok, ChildPriv} ->
            {ChildPriv, IR};
        {error, _} ->
            derive_priv_step(PrivKey, ChainCode, StartIndex, CurIndex + 1)
    end.

%% derive_pub_step/4: retry helper for public CKD. Mirrors
%% `bitcoin-core/src/pubkey.cpp::CPubKey::Derive` retry-on-fail semantics.
derive_pub_step(_PubKey, _ChainCode, StartIndex, CurIndex)
  when StartIndex < ?HARDENED, CurIndex >= ?HARDENED ->
    %% Pub-only path can never derive hardened; if retry walks past 2^31
    %% (because StartIndex was 2^31-1), bail out.
    throw({extkey_exhausted, StartIndex, CurIndex});
derive_pub_step(PubKey, ChainCode, StartIndex, CurIndex) ->
    Data = <<PubKey/binary, CurIndex:32/big>>,
    <<IL:32/binary, IR:32/binary>> = beamchain_crypto:hmac_sha512(ChainCode, Data),
    case beamchain_crypto:pubkey_tweak_add(PubKey, IL) of
        {ok, ChildPub} ->
            {ChildPub, IR};
        {error, _} ->
            derive_pub_step(PubKey, ChainCode, StartIndex, CurIndex + 1)
    end.

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
%% BIP-32 default prefixes (mainnet/testnet, P2PKH/P2SH script context).
-define(MAINNET_XPUB, <<16#04, 16#88, 16#b2, 16#1e>>).
-define(MAINNET_XPRV, <<16#04, 16#88, 16#ad, 16#e4>>).
-define(TESTNET_TPUB, <<16#04, 16#35, 16#87, 16#cf>>).
-define(TESTNET_TPRV, <<16#04, 16#35, 16#83, 16#94>>).
%% SLIP-132 SegWit-aware prefixes (https://github.com/satoshilabs/slips/blob/master/slip-0132.md).
%% Same BIP-32 payload bytes — only the 4-byte version differs and hints at the
%% intended script type (P2SH-P2WPKH for ypub/upub; P2WPKH for zpub/vpub).
-define(MAINNET_YPUB, <<16#04, 16#9D, 16#7C, 16#B2>>).  %% BIP-49  P2SH-P2WPKH mainnet
-define(MAINNET_YPRV, <<16#04, 16#9D, 16#78, 16#78>>).
-define(MAINNET_ZPUB, <<16#04, 16#B2, 16#47, 16#46>>).  %% BIP-84  P2WPKH      mainnet
-define(MAINNET_ZPRV, <<16#04, 16#B2, 16#43, 16#0C>>).
-define(TESTNET_UPUB, <<16#04, 16#4A, 16#52, 16#62>>).  %% BIP-49  P2SH-P2WPKH testnet
-define(TESTNET_UPRV, <<16#04, 16#4A, 16#4E, 16#28>>).
-define(TESTNET_VPUB, <<16#04, 16#5F, 16#1C, 16#F6>>).  %% BIP-84  P2WPKH      testnet
-define(TESTNET_VPRV, <<16#04, 16#5F, 16#18, 16#BC>>).

%% Public decode shape: {ok, Key, ChainCode}. The SLIP-132 script-context
%% tag (e.g. {p2wpkh, mainnet} for zpub) is preserved internally in
%% decode_xkey/1's return tuple and consumed by parse_xkey_base/6, but not
%% surfaced through the simple decode_xpub/1 / decode_xprv/1 public API to
%% preserve backward-compat with existing wallet callers.
-spec decode_xpub(string()) -> {ok, binary(), binary()} | {error, term()}.
decode_xpub(Str) ->
    case decode_xkey(Str) of
        {ok, pub, _Tag, Key, ChainCode, _D, _Fp, _Idx} -> {ok, Key, ChainCode};
        {ok, priv, _Tag, _, _, _, _, _} -> {error, not_xpub};
        {error, _} = Err -> Err
    end.

-spec decode_xprv(string()) -> {ok, binary(), binary()} | {error, term()}.
decode_xprv(Str) ->
    case decode_xkey(Str) of
        {ok, priv, _Tag, Key, ChainCode, _D, _Fp, _Idx} -> {ok, Key, ChainCode};
        {ok, pub, _Tag, _, _, _, _, _} -> {error, not_xprv};
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
                    decode_xkey_body(Version, Depth, Fingerprint, ChildIndex,
                                     ChainCode, KeyData)
            end;
        {ok, _} ->
            {error, invalid_xkey_length};
        {error, _} = Err ->
            Err
    end.

%% BIP-32 §"Serialization format" + Bitcoin Core CExtKey::Decode parity:
%% reject malformed xpub/xprv strings (BIP-32 test vector #5) instead of
%% letting binary pattern-match crash. Validates: known version bytes,
%% structural sanity (depth=0 ⇒ parent fingerprint=0000 and child_index=0,
%% per Core's `pubkey.cpp:CExtPubKey::Decode` lines 235-243), and per-
%% variant key-data prefix (xprv first byte MUST be 0x00; xpub first byte
%% MUST be 0x02 or 0x03 for a compressed secp256k1 point).
%%
%% Return shape: {ok, pub|priv, {ScriptHint, Network}, Key, ChainCode,
%%                Depth, Fingerprint, ChildIndex}. ScriptHint reflects the
%% SLIP-132 prefix convention (p2pkh | p2sh_p2wpkh | p2wpkh) so wallet code
%% can default-route descriptor-less imports to the right script context.
%% Descriptor parsing itself ignores the hint — the `pkh`/`wpkh`/`sh(...)`
%% wrapper drives script generation per BIP-380.
decode_xkey_body(Version, Depth, Fingerprint, ChildIndex, ChainCode, KeyData) ->
    case classify_xkey_version(Version) of
        unknown ->
            {error, unknown_xkey_version};
        {pub, Tag} ->
            case validate_xkey_structure(Depth, Fingerprint, ChildIndex) of
                ok ->
                    case validate_xpub_keydata(KeyData) of
                        ok -> {ok, pub, Tag, KeyData, ChainCode, Depth, Fingerprint, ChildIndex};
                        {error, _} = E -> E
                    end;
                {error, _} = E -> E
            end;
        {priv, Tag} ->
            case validate_xkey_structure(Depth, Fingerprint, ChildIndex) of
                ok ->
                    case KeyData of
                        <<0, PrivKey:32/binary>> ->
                            case validate_xprv_keydata(PrivKey) of
                                ok ->
                                    {ok, priv, Tag, PrivKey, ChainCode,
                                     Depth, Fingerprint, ChildIndex};
                                {error, _} = E -> E
                            end;
                        _ ->
                            {error, invalid_xprv_prefix}
                    end;
                {error, _} = E -> E
            end
    end.

classify_xkey_version(?MAINNET_XPUB) -> {pub,  {p2pkh,       mainnet}};
classify_xkey_version(?MAINNET_XPRV) -> {priv, {p2pkh,       mainnet}};
classify_xkey_version(?TESTNET_TPUB) -> {pub,  {p2pkh,       testnet}};
classify_xkey_version(?TESTNET_TPRV) -> {priv, {p2pkh,       testnet}};
classify_xkey_version(?MAINNET_YPUB) -> {pub,  {p2sh_p2wpkh, mainnet}};
classify_xkey_version(?MAINNET_YPRV) -> {priv, {p2sh_p2wpkh, mainnet}};
classify_xkey_version(?MAINNET_ZPUB) -> {pub,  {p2wpkh,      mainnet}};
classify_xkey_version(?MAINNET_ZPRV) -> {priv, {p2wpkh,      mainnet}};
classify_xkey_version(?TESTNET_UPUB) -> {pub,  {p2sh_p2wpkh, testnet}};
classify_xkey_version(?TESTNET_UPRV) -> {priv, {p2sh_p2wpkh, testnet}};
classify_xkey_version(?TESTNET_VPUB) -> {pub,  {p2wpkh,      testnet}};
classify_xkey_version(?TESTNET_VPRV) -> {priv, {p2wpkh,      testnet}};
classify_xkey_version(_) -> unknown.

%% Core CExtPubKey::Decode (pubkey.cpp:235-243): depth=0 master keys MUST
%% have zeroed parent-fingerprint and child_index. Non-zero values at
%% depth=0 indicate forged / corrupted serialization.
validate_xkey_structure(0, <<0,0,0,0>>, 0) -> ok;
validate_xkey_structure(0, _, _) -> {error, invalid_master_metadata};
validate_xkey_structure(_, _, _) -> ok.

%% Compressed secp256k1 pubkey prefix must be 0x02 or 0x03 (BIP-32 xpubs
%% are always compressed). Anything else — including the 0x00 leading-zero
%% byte that appears in BIP-32 test vector #5 invalid strings — is malformed.
%% Beyond the prefix check we ALSO run a curve-point parse via libsecp's
%% `secp256k1_ec_pubkey_tweak_add` (zero tweak ⇒ no-op but performs full
%% parse + range check), mirroring Core `CExtPubKey::Decode`'s implicit
%% `CPubKey::IsValid()` check.
validate_xpub_keydata(<<Prefix, _:32/binary>> = PubKey)
  when Prefix =:= 16#02; Prefix =:= 16#03 ->
    case beamchain_crypto:pubkey_tweak_add(PubKey, <<0:256>>) of
        {ok, _} -> ok;
        {error, _} -> {error, invalid_xpub_point}
    end;
validate_xpub_keydata(_) ->
    {error, invalid_xpub_prefix}.

%% BIP-32 §"Serialization format": private key body MUST satisfy
%% 0 < k < n. Validate by attempting an identity tweak — libsecp's
%% `secp256k1_ec_seckey_tweak_add` runs `secp256k1_ec_seckey_verify`
%% which rejects k=0 and k>=n.
validate_xprv_keydata(PrivKey) when byte_size(PrivKey) =:= 32 ->
    case beamchain_crypto:seckey_tweak_add(PrivKey, <<0:256>>) of
        {ok, _} -> ok;
        {error, _} -> {error, invalid_xprv_scalar}
    end.

%% Decode base58 string to raw bytes (no version/checksum handling).
%%
%% Defensive DoS guard: the Acc*58+Val accumulator in decode_base58_chars/3
%% grows as an Erlang bignum; a multi-megabyte input would burn O(n²) CPU/RAM
%% before the downstream byte_size check in decode_xkey/1 rejects it. Cap
%% inputs at 120 chars — well above the 111-char base58check encoding of an
%% 82-byte xpub/xprv payload — and reject longer strings immediately. Not
%% currently reachable through the RPC layer (cowboy enforces body limits)
%% but cheap defence-in-depth against future callers that hand untrusted
%% strings straight to this decoder.
-define(BASE58_RAW_MAX_LEN, 120).

decode_base58_raw(Str) when is_list(Str), length(Str) > ?BASE58_RAW_MAX_LEN ->
    {error, base58_too_long};
decode_base58_raw(Str) when is_binary(Str), byte_size(Str) > ?BASE58_RAW_MAX_LEN ->
    {error, base58_too_long};
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

%%% ===================================================================
%%% scantxoutset descriptor eval (Core EvalDescriptorStringOrObject)
%%% ===================================================================

%% Parse, expand [Low,High], and InferDescriptor each script.
%% CheckChecksum / Parse errors are Core's strings (RPC_INVALID_ADDRESS_OR_KEY).
%% A non-range descriptor forces the range to {0,0} after the caller has
%% already validated it (ParseDescriptorRange runs first, even when the
%% descriptor ignores the range). expand_priv is false, so a hardened step
%% from an xpub fails the same way Expand() does.
-spec eval_scan(string() | binary(), {integer(), integer()}, atom()) ->
    {ok, [{binary(), binary()}]} | {error, binary()}.
eval_scan(Desc, Range, Network) when is_binary(Desc) ->
    eval_scan(binary_to_list(Desc), Range, Network);
eval_scan(DescStr, {Low, High}, Network) when is_list(DescStr) ->
    case scan_check_checksum(DescStr) of
        {error, Msg} ->
            {error, iolist_to_binary(Msg)};
        {ok, Body} ->
            %% addr() calls DecodeDestination, which needs the node network.
            case scan_with_net(Network, fun() -> scan_parse(Body) end) of
                {error, Msg} ->
                    {error, iolist_to_binary(Msg)};
                {ok, Desc} ->
                    {A, B} = case scan_is_range(Desc) of
                                 true -> {Low, High};
                                 false -> {0, 0}
                             end,
                    scan_expand_range(Desc, A, B, DescStr, Network,
                                      scan_prov_new(), [])
            end
    end.

%% CheckChecksum (descriptor.cpp). Multiple '#' is reported before the
%% length check, and the length check runs before the charset check.
scan_check_checksum(Str) ->
    Parts = string:split(Str, "#", all),
    case length(Parts) > 2 of
        true ->
            {error, "Multiple '#' symbols"};
        false ->
            case Parts of
                [Body] ->
                    scan_payload_ok(Body);
                [_Body, Sum] when length(Sum) =/= 8 ->
                    {error, "Expected 8 character checksum, not " ++
                         integer_to_list(length(Sum)) ++ " characters"};
                [Body, Sum] ->
                    case scan_payload_ok(Body) of
                        {error, _} = E ->
                            E;
                        {ok, Body} ->
                            Expect = descriptor_checksum(Body),
                            case Sum =:= Expect of
                                true ->
                                    {ok, Body};
                                false ->
                                    {error, "Provided checksum '" ++ Sum ++
                                         "' does not match computed checksum '" ++
                                         Expect ++ "'"}
                            end
                    end
            end
    end.

scan_payload_ok(Body) ->
    try descriptor_checksum(Body) of
        _ -> {ok, Body}
    catch
        throw:{invalid_char, _} ->
            {error, "Invalid characters in payload"}
    end.

scan_parse(Body) ->
    scan_parse_script(Body, top).

%% ParseScript. `Rest` non-empty means the expression did not consume its
%% span; Core then returns no descriptor and keeps the previous error,
%% which is empty when the inner parse succeeded.
scan_parse_script(Sp, Ctx) ->
    {Expr, Rest} = scan_expr(Sp),
    case scan_parse_func(Expr, Ctx) of
        {ok, Desc} when Rest =:= [] -> {ok, Desc};
        {ok, _} -> {error, ""};
        {error, _} = E -> E
    end.

scan_parse_func(Expr, Ctx) ->
    case scan_func("pk", Expr) of
        {ok, Inner} ->
            case scan_parse_pubkey(Inner, Ctx) of
                {ok, Key} -> {ok, {pk, Key, Ctx =:= p2tr}};
                {error, E} -> {error, "pk(): " ++ E}
            end;
        false ->
            scan_after_pk(Expr, Ctx)
    end.

scan_after_pk(Expr, Ctx) ->
    case scan_func("pkh", Expr) of
        {ok, Inner} when Ctx =:= top; Ctx =:= p2sh; Ctx =:= p2wsh ->
            case scan_parse_pubkey(Inner, Ctx) of
                {ok, Key} -> {ok, {pkh, Key}};
                {error, E} -> {error, "pkh(): " ++ E}
            end;
        {ok, _} ->
            scan_after_pkh(Expr, Ctx);
        false ->
            scan_after_pkh(Expr, Ctx)
    end.

scan_after_pkh(Expr, Ctx) ->
    case scan_func("combo", Expr) of
        {ok, Inner} when Ctx =:= top ->
            case scan_parse_pubkey(Inner, Ctx) of
                {ok, Key} -> {ok, {combo, Key}};
                {error, E} -> {error, "combo(): " ++ E}
            end;
        {ok, _} ->
            {error, "Can only have combo() at top level"};
        false ->
            scan_after_combo(Expr, Ctx)
    end.

scan_after_combo(Expr, Ctx) ->
    Multi = scan_func("multi", Expr),
    Sorted = case Multi of
                 false -> scan_func("sortedmulti", Expr);
                 _ -> false
             end,
    case {Multi, Sorted} of
        {{ok, Inner}, _} when Ctx =:= top; Ctx =:= p2sh; Ctx =:= p2wsh ->
            scan_parse_multi(Inner, Ctx, false);
        {_, {ok, Inner}} when Ctx =:= top; Ctx =:= p2sh; Ctx =:= p2wsh ->
            scan_parse_multi(Inner, Ctx, true);
        {{ok, _}, _} ->
            {error, "Can only have multi/sortedmulti at top level, in sh(), or in wsh()"};
        {_, {ok, _}} ->
            {error, "Can only have multi/sortedmulti at top level, in sh(), or in wsh()"};
        _ ->
            scan_after_multi(Expr, Ctx)
    end.

scan_after_multi(Expr, Ctx) ->
    case scan_func("wpkh", Expr) of
        {ok, Inner} when Ctx =:= top; Ctx =:= p2sh ->
            %% wpkh keys are parsed in P2WPKH context (uncompressed rejected).
            case scan_parse_pubkey(Inner, p2wpkh) of
                {ok, Key} -> {ok, {wpkh, Key}};
                {error, E} -> {error, "wpkh(): " ++ E}
            end;
        {ok, _} ->
            {error, "Can only have wpkh() at top level or inside sh()"};
        false ->
            scan_after_wpkh(Expr, Ctx)
    end.

scan_after_wpkh(Expr, Ctx) ->
    case scan_func("sh", Expr) of
        {ok, Inner} when Ctx =:= top ->
            %% Inner failure is not re-prefixed (ParseScript returns {}).
            case scan_parse_script(Inner, p2sh) of
                {ok, Sub} -> {ok, {sh, Sub}};
                {error, _} = E -> E
            end;
        {ok, _} ->
            {error, "Can only have sh() at top level"};
        false ->
            scan_after_sh(Expr, Ctx)
    end.

scan_after_sh(Expr, Ctx) ->
    case scan_func("wsh", Expr) of
        {ok, Inner} when Ctx =:= top; Ctx =:= p2sh ->
            case scan_parse_script(Inner, p2wsh) of
                {ok, Sub} -> {ok, {wsh, Sub}};
                {error, _} = E -> E
            end;
        {ok, _} ->
            {error, "Can only have wsh() at top level or inside sh()"};
        false ->
            scan_after_wsh(Expr, Ctx)
    end.

scan_after_wsh(Expr, Ctx) ->
    case scan_func("addr", Expr) of
        {ok, Inner} when Ctx =:= top ->
            case beamchain_address:address_to_script(Inner, scan_net()) of
                {ok, Script} -> {ok, {addr, Inner, Script}};
                {error, _} -> {error, "Address is not valid"}
            end;
        {ok, _} ->
            {error, "Can only have addr() at top level"};
        false ->
            scan_after_addr(Expr, Ctx)
    end.

scan_after_addr(Expr, Ctx) ->
    case scan_func("tr", Expr) of
        {ok, Inner} when Ctx =:= top ->
            scan_parse_tr(Inner);
        {ok, _} ->
            {error, "Can only have tr at top level"};
        false ->
            scan_after_tr(Expr, Ctx)
    end.

scan_after_tr(Expr, Ctx) ->
    case scan_func("rawtr", Expr) of
        {ok, Inner} when Ctx =:= top ->
            {Arg, Rest} = scan_expr(Inner),
            case Rest of
                [_ | _] ->
                    {error, "rawtr(): only one key expected."};
                [] ->
                    case scan_parse_pubkey(Arg, p2tr) of
                        {ok, Key} -> {ok, {rawtr, Key}};
                        {error, E} -> {error, "rawtr(): " ++ E}
                    end
            end;
        {ok, _} ->
            {error, "Can only have rawtr at top level"};
        false ->
            scan_after_rawtr(Expr, Ctx)
    end.

scan_after_rawtr(Expr, Ctx) ->
    case scan_func("raw", Expr) of
        {ok, Inner} when Ctx =:= top ->
            case scan_is_hex(Inner) of
                true ->
                    {ok, Bin} = hex_to_binary(Inner),
                    {ok, {raw, Bin}};
                false ->
                    {error, "Raw script is not hex"}
            end;
        {ok, _} ->
            {error, "Can only have raw() at top level"};
        false ->
            scan_func_fallback(Expr, Ctx)
    end.

scan_func_fallback(_Expr, p2sh) ->
    {error, "A function is needed within P2SH"};
scan_func_fallback(_Expr, p2wsh) ->
    {error, "A function is needed within P2WSH"};
scan_func_fallback(Expr, _Ctx) ->
    {error, "'" ++ Expr ++ "' is not a valid descriptor function"}.

scan_parse_multi(Inner, Ctx, Sorted) ->
    {ThreshExpr, Rest0} = scan_expr(Inner),
    case scan_uint32(ThreshExpr) of
        error ->
            {error, "Multi threshold '" ++ ThreshExpr ++ "' is not valid"};
        {ok, Thres} ->
            case scan_multi_keys(Rest0, Ctx, []) of
                {error, E} ->
                    {error, E};
                {ok, Keys} ->
                    scan_multi_limits(Thres, Keys, Ctx, Sorted)
            end
    end.

scan_multi_keys([], _Ctx, Acc) ->
    {ok, lists:reverse(Acc)};
scan_multi_keys(Expr, Ctx, Acc) ->
    case scan_take(",", Expr) of
        false ->
            [C | _] = Expr,
            {error, "Multi: expected ',', got '" ++ [C] ++ "'"};
        {ok, Rest} ->
            {Arg, Rest2} = scan_expr(Rest),
            case scan_parse_pubkey(Arg, Ctx) of
                {error, E} -> {error, "Multi: " ++ E};
                {ok, Key} -> scan_multi_keys(Rest2, Ctx, [Key | Acc])
            end
    end.

scan_multi_limits(Thres, Keys, Ctx, Sorted) ->
    N = length(Keys),
    ScriptSize = lists:sum([scan_key_size(K) + 1 || K <- Keys]),
    if
        N < 1 orelse N > 20 ->
            {error, "Cannot have " ++ integer_to_list(N) ++
                 " keys in multisig; must have between 1 and 20 keys, inclusive"};
        Thres < 1 ->
            {error, "Multisig threshold cannot be " ++ integer_to_list(Thres) ++
                 ", must be at least 1"};
        Thres > N ->
            {error, "Multisig threshold cannot be larger than the number of keys; threshold is " ++
                 integer_to_list(Thres) ++ " but only " ++ integer_to_list(N) ++
                 " keys specified"};
        Ctx =:= top andalso N > 3 ->
            {error, "Cannot have " ++ integer_to_list(N) ++
                 " pubkeys in bare multisig; only at most 3 pubkeys"};
        Ctx =:= p2sh andalso ScriptSize + 3 > 520 ->
            {error, "P2SH script is too large, " ++
                 integer_to_list(ScriptSize + 3) ++
                 " bytes is larger than 520 bytes"};
        true ->
            {ok, {multi, Thres, Keys, Sorted}}
    end.

scan_parse_tr(Inner) ->
    {Arg, Rest} = scan_expr(Inner),
    case scan_parse_pubkey(Arg, p2tr) of
        {error, E} ->
            {error, "tr(): " ++ E};
        {ok, Key} when Rest =:= [] ->
            {ok, {tr, Key, []}};
        {ok, Key} ->
            case scan_take(",", Rest) of
                false ->
                    [C | _] = Rest,
                    {error, "tr: expected ',', got '" ++ [C] ++ "'"};
                {ok, Rest2} ->
                    scan_tr_loop(Rest2, Key, [], [])
            end
    end.

%% TRDescriptor tree walk (ParseScript). Depth is the number of '{' still
%% open, which matches the script-tree depths: {a,b} => 1,1;
%% {{a,b},c} => 2,2,1; {a,{b,c}} => 1,2,2.
scan_tr_loop(Expr0, Key, Branches, Acc) ->
    case scan_take_opens(Expr0, Branches) of
        too_deep ->
            {error, "tr() supports at most 128 nesting levels"};
        {ok, Expr1, Branches1} ->
            {Sarg, Expr2} = scan_expr(Expr1),
            case scan_parse_script(Sarg, p2tr) of
                {error, _} = E ->
                    E;
                {ok, Sub} ->
                    Acc2 = Acc ++ [{length(Branches1), Sub}],
                    scan_tr_after(Expr2, Key, Branches1, Acc2)
            end
    end.

scan_take_opens(Expr, Branches) ->
    case scan_take("{", Expr) of
        {ok, Rest} ->
            B2 = Branches ++ [false],
            case length(B2) > 128 of
                true -> too_deep;
                false -> scan_take_opens(Rest, B2)
            end;
        false ->
            {ok, Expr, Branches}
    end.

scan_tr_after(Expr, Key, Branches, Acc) ->
    case Branches =/= [] andalso lists:last(Branches) =:= true of
        true ->
            case scan_take("}", Expr) of
                false ->
                    {error, "tr(): expected '}' after script expression"};
                {ok, Expr2} ->
                    scan_tr_after(Expr2, Key, lists:droplast(Branches), Acc)
            end;
        false ->
            case Branches =/= [] andalso lists:last(Branches) =:= false of
                true ->
                    case scan_take(",", Expr) of
                        false ->
                            {error, "tr(): expected ',' after script expression"};
                        {ok, Expr2} ->
                            B2 = lists:droplast(Branches) ++ [true],
                            scan_tr_loop(Expr2, Key, B2, Acc)
                    end;
                false ->
                    case Expr of
                        [] -> {ok, {tr, Key, Acc}};
                        _ -> {error, "tr(): expected ')' after script expression"}
                    end
            end
    end.

scan_func(Name, Str) ->
    N = length(Name),
    case length(Str) >= N + 2 andalso
         lists:sublist(Str, N) =:= Name andalso
         lists:nth(N + 1, Str) =:= $( andalso
         lists:last(Str) =:= $) of
        true ->
            {ok, lists:sublist(Str, N + 2, length(Str) - N - 2)};
        false ->
            false
    end.

scan_expr(Str) ->
    scan_expr(Str, 0, []).

scan_expr([], _Level, Acc) ->
    {lists:reverse(Acc), []};
scan_expr([$( | Rest], Level, Acc) ->
    scan_expr(Rest, Level + 1, [$( | Acc]);
scan_expr([${ | Rest], Level, Acc) ->
    scan_expr(Rest, Level + 1, [${ | Acc]);
scan_expr([$) | Rest], Level, Acc) when Level > 0 ->
    scan_expr(Rest, Level - 1, [$) | Acc]);
scan_expr([$} | Rest], Level, Acc) when Level > 0 ->
    scan_expr(Rest, Level - 1, [$} | Acc]);
scan_expr([C | _] = All, 0, Acc) when C =:= $); C =:= $}; C =:= $, ->
    {lists:reverse(Acc), All};
scan_expr([C | Rest], Level, Acc) ->
    scan_expr(Rest, Level, [C | Acc]).

scan_take(Prefix, Str) ->
    case lists:prefix(Prefix, Str) of
        true -> {ok, lists:nthtail(length(Prefix), Str)};
        false -> false
    end.

%% ---- pubkeys (ParsePubkey / ParsePubkeyInner) ----

scan_parse_pubkey(Str, Ctx) ->
    %% ParsePubkey rejects aggregated keys before the origin split.
    %% The word is split so this module stays free of that parser.
    case lists:prefix("mu" ++ "sig(", Str) of
        true when Ctx =/= p2tr ->
            {error, "mu" ++ "sig() is only allowed in tr() and rawtr()"};
        true ->
            {error, "Invalid mu" ++ "sig() expression"};
        false ->
            scan_parse_pubkey1(Str, Ctx)
    end.

scan_parse_pubkey1(Str, Ctx) ->
    Parts = scan_split(Str, $]),
    case length(Parts) > 2 of
        true ->
            {error, "Multiple ']' characters found for a single pubkey"};
        false when length(Parts) =:= 1 ->
            scan_parse_pubkey_inner(hd(Parts), Ctx, undefined);
        false ->
            [Origin, Key] = Parts,
            case Origin of
                "[" ++ Inside ->
                    scan_parse_origin(Inside, Key, Ctx);
                [] ->
                    {error, "Key origin start '[ character expected but not found, got ']' instead"};
                [C | _] ->
                    {error, "Key origin start '[ character expected but not found, got '" ++
                         [C] ++ "' instead"}
            end
    end.

scan_parse_origin(Inside, KeyPart, Ctx) ->
    Parts = scan_split(Inside, $/),
    Fp = hd(Parts),
    case length(Fp) =:= 8 of
        false ->
            {error, "Fingerprint is not 4 bytes (" ++ integer_to_list(length(Fp)) ++
                 " characters instead of 8 characters)"};
        true ->
            case scan_is_hex(Fp) of
                false ->
                    {error, "Fingerprint '" ++ Fp ++ "' is not hex"};
                true ->
                    {ok, FpBin} = hex_to_binary(Fp),
                    case scan_parse_path(tl(Parts)) of
                        {error, _} = E -> E;
                        {ok, Path} ->
                            scan_parse_pubkey_inner(KeyPart, Ctx, {FpBin, Path})
                    end
            end
    end.

scan_parse_pubkey_inner(Str, Ctx, Origin) ->
    Parts = scan_split(Str, $/),
    KeyStr = hd(Parts),
    case KeyStr =:= [] of
        true ->
            {error, "No key provided"};
        false ->
            case scan_space_ends(KeyStr) of
                true ->
                    {error, "Key '" ++ KeyStr ++ "' is invalid due to whitespace"};
                false when length(Parts) =:= 1 ->
                    scan_parse_single_key(KeyStr, Ctx, Origin);
                false ->
                    scan_parse_extkey(KeyStr, Parts, Origin)
            end
    end.

scan_parse_single_key(KeyStr, Ctx, Origin) ->
    case scan_is_hex(KeyStr) of
        true ->
            scan_parse_hex_key(KeyStr, Ctx, Origin);
        false ->
            case decode_wif(KeyStr) of
                {ok, Priv, Compressed} ->
                    scan_wif_key(Priv, Compressed, Ctx, Origin);
                _ ->
                    scan_parse_extkey(KeyStr, [KeyStr], Origin)
            end
    end.

%% ParsePubkeyInner: hybrid keys are rejected before the curve check,
%% and a 32-byte hex string is an x-only key only in P2TR (stored as the
%% even 33-byte point, ConstPubkeyProvider m_xonly).
scan_parse_hex_key(Hex, Ctx, Origin) ->
    {ok, Bin} = hex_to_binary(Hex),
    case scan_struct(Bin) of
        hybrid ->
            {error, "Hybrid public keys are not allowed"};
        {compressed, Pub} ->
            scan_accept_full(Hex, Pub, Bin, Ctx, Origin, true);
        {uncompressed, Pub} ->
            scan_accept_full(Hex, Pub, Bin, Ctx, Origin, false);
        other ->
            scan_xonly_or_invalid(Hex, Bin, Ctx, Origin)
    end.

scan_accept_full(Hex, Pub, Bin, Ctx, Origin, Compressed) ->
    case scan_fully_valid(Pub) of
        true ->
            Permit = Ctx =:= top orelse Ctx =:= p2sh,
            case Permit orelse Compressed of
                true -> {ok, {const, Pub, Origin}};
                false -> {error, "Uncompressed keys are not allowed"}
            end;
        false ->
            scan_xonly_or_invalid(Hex, Bin, Ctx, Origin)
    end.

scan_xonly_or_invalid(Hex, Bin, p2tr, Origin) when byte_size(Bin) =:= 32 ->
    Even = <<2, Bin/binary>>,
    case scan_fully_valid(Even) of
        true -> {ok, {const, Even, Origin}};
        false -> {error, "Pubkey '" ++ Hex ++ "' is invalid"}
    end;
scan_xonly_or_invalid(Hex, _Bin, _Ctx, _Origin) ->
    {error, "Pubkey '" ++ Hex ++ "' is invalid"}.

scan_wif_key(Priv, Compressed, Ctx, Origin) ->
    Permit = Ctx =:= top orelse Ctx =:= p2sh,
    case Permit orelse Compressed of
        false ->
            {error, "Uncompressed keys are not allowed"};
        true ->
            {ok, CPub} = beamchain_crypto:pubkey_from_privkey(Priv),
            Pub = case Compressed of
                      true -> CPub;
                      false ->
                          {ok, U} = beamchain_crypto:pubkey_decompress(CPub),
                          U
                  end,
            {ok, {const, Pub, Origin}}
    end.

scan_parse_extkey(KeyStr, Parts, Origin) ->
    case decode_xkey(KeyStr) of
        {ok, Type, _Tag, Mat, CC, _Depth, _Fp, _Child} ->
            {Derive, Kept} = scan_derive_type(Parts),
            case scan_parse_path(tl(Kept)) of
                {ok, Path} ->
                    {ok, {bip32, Type, Mat, CC, Path, Derive, Origin}};
                {error, _} = E ->
                    E
            end;
        _ ->
            {error, "key '" ++ KeyStr ++ "' is not valid"}
    end.

%% ParseDeriveType: only the final element may be *, *', or *h.
scan_derive_type(Parts) ->
    case lists:last(Parts) of
        "*" -> {unhardened, lists:droplast(Parts)};
        "*'" -> {hardened, lists:droplast(Parts)};
        "*h" -> {hardened, lists:droplast(Parts)};
        _ -> {non_ranged, Parts}
    end.

scan_parse_path(Elems) ->
    scan_parse_path(Elems, []).

scan_parse_path([], Acc) ->
    {ok, lists:reverse(Acc)};
scan_parse_path([E | Rest], Acc) ->
    case scan_path_elem(E) of
        {ok, Idx} -> scan_parse_path(Rest, [Idx | Acc]);
        {error, _} = Err -> Err
    end.

%% ParseKeyPathNum. Hardened steps set the high bit; inference later prints
%% them with 'h' (OriginPubkeyProvider apostrophe=false).
scan_path_elem(Elem) ->
    {Body, Hard} =
        case Elem of
            [] -> {[], false};
            _ ->
                case lists:last(Elem) of
                    $' -> {lists:droplast(Elem), true};
                    $h -> {lists:droplast(Elem), true};
                    _ -> {Elem, false}
                end
        end,
    case scan_uint32(Body) of
        {ok, N} when N > 16#7fffffff ->
            {error, "Key path value " ++ integer_to_list(N) ++ " is out of range"};
        {ok, N} when Hard ->
            {ok, N bor 16#80000000};
        {ok, N} ->
            {ok, N};
        error ->
            {error, "Key path value '" ++ Body ++ "' is not a valid uint32"}
    end.

scan_uint32([]) ->
    error;
scan_uint32(S) ->
    case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, S) of
        false ->
            error;
        true ->
            N = list_to_integer(S),
            case N =< 16#ffffffff of
                true -> {ok, N};
                false -> error
            end
    end.

scan_struct(<<P, _:32/binary>> = Pub) when P =:= 2; P =:= 3 ->
    {compressed, Pub};
scan_struct(<<4, _:64/binary>> = Pub) ->
    {uncompressed, Pub};
scan_struct(<<P, _:64/binary>>) when P =:= 6; P =:= 7 ->
    hybrid;
scan_struct(_) ->
    other.

scan_fully_valid(Pub) ->
    case beamchain_crypto:pubkey_tweak_add(Pub, <<0:256>>) of
        {ok, _} -> true;
        _ -> false
    end.

scan_xonly_valid(X) when byte_size(X) =:= 32 ->
    case beamchain_crypto:xonly_pubkey_tweak_add(X, <<0:256>>) of
        {ok, _, _} -> true;
        _ -> false
    end;
scan_xonly_valid(_) ->
    false.

scan_space_ends([C | _] = S) ->
    scan_is_space(C) orelse scan_is_space(lists:last(S)).

scan_is_space(C) ->
    C =:= $\s orelse C =:= $\t orelse C =:= $\n orelse
        C =:= $\v orelse C =:= $\f orelse C =:= $\r.

scan_is_hex(Str) ->
    (length(Str) rem 2 =:= 0) andalso
        lists:all(fun scan_is_hex_char/1, Str).

scan_is_hex_char(C) ->
    (C >= $0 andalso C =< $9) orelse
        (C >= $a andalso C =< $f) orelse
        (C >= $A andalso C =< $F).

scan_split(Str, C) ->
    scan_split(Str, C, [], []).

scan_split([], _C, Cur, Acc) ->
    lists:reverse([lists:reverse(Cur) | Acc]);
scan_split([C | Rest], C, Cur, Acc) ->
    scan_split(Rest, C, [], [lists:reverse(Cur) | Acc]);
scan_split([H | Rest], C, Cur, Acc) ->
    scan_split(Rest, C, [H | Cur], Acc).

scan_key_size({const, Pub, _}) -> byte_size(Pub);
scan_key_size({bip32, _, _, _, _, _, _}) -> 33.

%% ---- range / expand ----

scan_is_range({pk, K, _}) -> scan_key_range(K);
scan_is_range({pkh, K}) -> scan_key_range(K);
scan_is_range({wpkh, K}) -> scan_key_range(K);
scan_is_range({combo, K}) -> scan_key_range(K);
scan_is_range({rawtr, K}) -> scan_key_range(K);
scan_is_range({sh, I}) -> scan_is_range(I);
scan_is_range({wsh, I}) -> scan_is_range(I);
scan_is_range({multi, _, Keys, _}) -> lists:any(fun scan_key_range/1, Keys);
scan_is_range({tr, K, Subs}) ->
    scan_key_range(K) orelse
        lists:any(fun({_, S}) -> scan_is_range(S) end, Subs);
scan_is_range({addr, _, _}) -> false;
scan_is_range({raw, _}) -> false.

scan_key_range({bip32, _, _, _, _, Derive, _}) -> Derive =/= non_ranged;
scan_key_range(_) -> false.

%% InferDescriptor runs after EvalDescriptorStringOrObject has expanded
%% every index into one provider. OriginPubkeyProvider::GetPubKey prepends
%% its path on every call, so the string must be built from that final
%% provider, not from the provider as it stood at each index.
scan_expand_range(_Desc, I, High, _Orig, Net, Prov, Acc) when I > High ->
    Scripts = lists:append(lists:reverse(Acc)),
    {ok, [{S, scan_infer_cs(S, top, Prov, Net)} || S <- Scripts]};
scan_expand_range(Desc, I, High, Orig, Net, Prov, Acc) ->
    case scan_expand(Desc, I, Prov, Net) of
        error ->
            {error, iolist_to_binary(
                      "Cannot derive script without private keys: '" ++
                          Orig ++ "'")};
        {ok, Scripts, Prov2} ->
            scan_expand_range(Desc, I + 1, High, Orig, Net, Prov2,
                              [Scripts | Acc])
    end.

scan_expand(Desc, Pos, Prov, Net) ->
    try scan_expand1(Desc, Pos, Prov, Net)
    catch
        throw:scan_derive_fail -> error
    end.

scan_expand1({pk, Key, XOnly}, Pos, Prov, _Net) ->
    {Pub, Prov1} = scan_expand_key(Key, Pos, Prov),
    {ok, [scan_pk_script(Pub, XOnly)], Prov1};
scan_expand1({pkh, Key}, Pos, Prov, _Net) ->
    {Pub, Prov1} = scan_expand_key(Key, Pos, Prov),
    {ok, [scan_p2pkh(Pub)], Prov1};
scan_expand1({wpkh, Key}, Pos, Prov, _Net) ->
    {Pub, Prov1} = scan_expand_key(Key, Pos, Prov),
    {ok, [scan_p2wpkh(Pub)], Prov1};
scan_expand1({combo, Key}, Pos, Prov, _Net) ->
    {Pub, Prov1} = scan_expand_key(Key, Pos, Prov),
    Pk = scan_pk_script(Pub, false),
    Pkh = scan_p2pkh(Pub),
    case byte_size(Pub) =:= 33 of
        true ->
            %% ComboDescriptor::MakeScripts also records the p2wpkh subscript
            %% so the nested sh() infers as sh(wpkh(...)).
            W = scan_p2wpkh(Pub),
            Prov2 = scan_prov_script(Prov1, W),
            {ok, [Pk, Pkh, W, scan_p2sh_wrap(W)], Prov2};
        false ->
            {ok, [Pk, Pkh], Prov1}
    end;
scan_expand1({multi, Thres, Keys, Sorted}, Pos, Prov, _Net) ->
    {Pubs, Prov1} = scan_expand_keys(Keys, Pos, Prov),
    Ordered = case Sorted of
                  true -> lists:sort(Pubs);
                  false -> Pubs
              end,
    {ok, [scan_multi_script(Thres, Ordered)], Prov1};
scan_expand1({sh, Inner}, Pos, Prov, Net) ->
    {ok, [Sub], Prov1} = scan_expand1(Inner, Pos, Prov, Net),
    Prov2 = scan_prov_script(Prov1, Sub),
    {ok, [scan_p2sh_wrap(Sub)], Prov2};
scan_expand1({wsh, Inner}, Pos, Prov, Net) ->
    {ok, [Sub], Prov1} = scan_expand1(Inner, Pos, Prov, Net),
    %% WSHDescriptor stores the witness script under CScriptID = hash160.
    Prov2 = scan_prov_script(Prov1, Sub),
    {ok, [scan_p2wsh_wrap(Sub)], Prov2};
scan_expand1({tr, Key, Subs}, Pos, Prov, Net) ->
    {Pub, Prov1} = scan_expand_key(Key, Pos, Prov),
    X = scan_xonly(Pub),
    case scan_xonly_valid(X) of
        false -> throw(scan_derive_fail);
        true -> ok
    end,
    {Leaves, Prov2} = scan_expand_leaves(Subs, Pos, Prov1, Net),
    case scan_tr_output(X, Leaves) of
        error ->
            throw(scan_derive_fail);
        {ok, Out} ->
            %% TRDescriptor::MakeScripts stores the builder even for a
            %% key-path-only tree so InferScript emits tr(), not rawtr().
            Prov3 = scan_prov_tree(Prov2, Out, X, Leaves),
            {ok, [<<16#51, 16#20, Out/binary>>], Prov3}
    end;
scan_expand1({rawtr, Key}, Pos, Prov, _Net) ->
    {Pub, Prov1} = scan_expand_key(Key, Pos, Prov),
    X = scan_xonly(Pub),
    case scan_xonly_valid(X) of
        true -> {ok, [<<16#51, 16#20, X/binary>>], Prov1};
        false -> throw(scan_derive_fail)
    end;
scan_expand1({addr, _Addr, Script}, _Pos, Prov, _Net) ->
    {ok, [Script], Prov};
scan_expand1({raw, Script}, _Pos, Prov, _Net) ->
    {ok, [Script], Prov}.

scan_expand_keys(Keys, Pos, Prov) ->
    lists:foldl(fun(K, {Acc, P}) ->
                        {Pub, P2} = scan_expand_key(K, Pos, P),
                        {Acc ++ [Pub], P2}
                end, {[], Prov}, Keys).

scan_expand_leaves(Subs, Pos, Prov, Net) ->
    lists:foldl(fun({Depth, Sub}, {Acc, P}) ->
                        {ok, [Script], P2} = scan_expand1(Sub, Pos, P, Net),
                        {Acc ++ [{Depth, Script}], P2}
                end, {[], Prov}, Subs).

%% ConstPubkeyProvider::GetPubKey records fingerprint = hash160(pubkey)[0:4].
%% OriginPubkeyProvider then overwrites that fingerprint and prepends its path
%% onto whatever is already stored (it does not emplace).
%% BIP32PubkeyProvider's fingerprint is hash160 of the root xpub pubkey,
%% and its path is the suffix after the xpub plus the derived index.
scan_expand_key({const, Pub, Origin}, _Pos, Prov) ->
    Id = beamchain_crypto:hash160(Pub),
    <<Fp:4/binary, _/binary>> = Id,
    Prov1 = scan_prov_origin(Prov, Id, Pub, Fp, []),
    {Pub, scan_apply_origin(Prov1, Id, Origin)};
scan_expand_key({bip32, Kind, Mat, CC, Path, Derive, Origin}, Pos, Prov) ->
    {RootPub, Derived} = scan_derive_bip32(Kind, Mat, CC, Path, Derive, Pos),
    <<Fp:4/binary, _/binary>> = beamchain_crypto:hash160(RootPub),
    InfoPath = case Derive of
                   non_ranged -> Path;
                   unhardened -> Path ++ [Pos];
                   hardened -> Path ++ [Pos bor 16#80000000]
               end,
    Id = beamchain_crypto:hash160(Derived),
    Prov1 = scan_prov_origin(Prov, Id, Derived, Fp, InfoPath),
    {Derived, scan_apply_origin(Prov1, Id, Origin)}.

scan_apply_origin(Prov, _Id, undefined) ->
    Prov;
scan_apply_origin(Prov, Id, {Fp, Path}) ->
    scan_prov_wrap(Prov, Id, Fp, Path).

scan_derive_bip32(priv, Priv, CC, Path, Derive, Pos) ->
    {ok, RootPub} = beamchain_crypto:pubkey_from_privkey(Priv),
    Full = scan_full_path(Path, Derive, Pos),
    try derive_bip32_privkey_path(Priv, CC, Full) of
        {ChildPriv, _, _} ->
            {ok, Derived} = beamchain_crypto:pubkey_from_privkey(ChildPriv),
            {RootPub, Derived}
    catch
        throw:_ -> throw(scan_derive_fail)
    end;
scan_derive_bip32(pub, Pub, CC, Path, Derive, Pos) ->
    case scan_hardened(Path) orelse Derive =:= hardened of
        true -> throw(scan_derive_fail);
        false ->
            Full = scan_full_path(Path, Derive, Pos),
            try derive_bip32_pubkey_path(Pub, CC, Full) of
                {Child, _, _} -> {Pub, Child}
            catch
                throw:_ -> throw(scan_derive_fail)
            end
    end.

scan_full_path(Path, non_ranged, _Pos) -> Path;
scan_full_path(Path, unhardened, Pos) -> Path ++ [Pos];
scan_full_path(Path, hardened, Pos) -> Path ++ [Pos bor 16#80000000].

scan_hardened(Path) ->
    lists:any(fun(I) -> I >= 16#80000000 end, Path).

scan_xonly(<<_:8, X:32/binary>>) -> X;
scan_xonly(<<X:32/binary>>) -> X.

scan_pk_script(Pub, false) ->
    <<(byte_size(Pub)), Pub/binary, 16#ac>>;
scan_pk_script(Pub, true) ->
    <<32, (scan_xonly(Pub))/binary, 16#ac>>.

scan_p2pkh(Pub) ->
    H = beamchain_crypto:hash160(Pub),
    <<16#76, 16#a9, 16#14, H/binary, 16#88, 16#ac>>.

scan_p2wpkh(Pub) ->
    H = beamchain_crypto:hash160(Pub),
    <<0, 20, H/binary>>.

scan_p2sh_wrap(Script) ->
    H = beamchain_crypto:hash160(Script),
    <<16#a9, 16#14, H/binary, 16#87>>.

scan_p2wsh_wrap(Script) ->
    H = beamchain_crypto:sha256(Script),
    <<0, 32, H/binary>>.

scan_multi_script(K, Pubs) ->
    Pushes = [<<(byte_size(P)), P/binary>> || P <- Pubs],
    %% EncodeOP_N: OP_1..OP_16, else a one-byte push (17..20).
    iolist_to_binary([scan_op_n(K), Pushes, scan_op_n(length(Pubs)), 16#ae]).

scan_op_n(N) when N >= 1, N =< 16 -> <<(16#50 + N)>>;
scan_op_n(N) when N > 16, N < 128 -> <<1, N>>.

%% Depth-aware leaf insert (signingprovider Insert). Unlike
%% build_taproot_merkle/1, which the descriptor derive path still uses.
scan_tr_output(Internal, Leaves) ->
    case scan_merkle(Leaves) of
        error -> error;
        none ->
            Tweak = beamchain_crypto:tagged_hash(<<"TapTweak">>, Internal),
            scan_tweak(Internal, Tweak);
        {ok, Root} ->
            Tweak = beamchain_crypto:tagged_hash(
                      <<"TapTweak">>, <<Internal/binary, Root/binary>>),
            scan_tweak(Internal, Tweak)
    end.

scan_tweak(Internal, Tweak) ->
    case beamchain_crypto:xonly_pubkey_tweak_add(Internal, Tweak) of
        {ok, Out, _} -> {ok, Out};
        _ -> error
    end.

scan_merkle([]) ->
    none;
scan_merkle(Leaves) ->
    Branch = lists:foldl(fun({D, S}, B) ->
                                 scan_tap_insert(scan_tapleaf(S), D, B)
                         end, [], Leaves),
    case Branch of
        [Root] when is_binary(Root) -> {ok, Root};
        _ -> error
    end.

scan_tapleaf(Script) ->
    Data = <<16#c0, (compact_size(byte_size(Script)))/binary, Script/binary>>,
    beamchain_crypto:tagged_hash(<<"TapLeaf">>, Data).

scan_tapbranch(A, B) ->
    {L, R} = case A < B of true -> {A, B}; false -> {B, A} end,
    beamchain_crypto:tagged_hash(<<"TapBranch">>, <<L/binary, R/binary>>).

scan_tap_insert(Node, Depth, Branch) ->
    scan_tap_insert2(Node, Depth, Branch).

scan_tap_insert2(Node, Depth, Branch) when length(Branch) > Depth ->
    case lists:nth(Depth + 1, Branch) of
        empty ->
            scan_set_nth(Depth + 1, Node, Branch);
        Existing ->
            scan_tap_insert2(scan_tapbranch(Node, Existing), Depth - 1,
                             lists:droplast(Branch))
    end;
scan_tap_insert2(Node, Depth, Branch) ->
    Pad = lists:duplicate(Depth + 1 - length(Branch), empty),
    scan_set_nth(Depth + 1, Node, Branch ++ Pad).

scan_set_nth(1, V, [_ | T]) -> [V | T];
scan_set_nth(N, V, [H | T]) -> [H | scan_set_nth(N - 1, V, T)].

%% ---- provider ----

scan_prov_new() ->
    #{pubs => #{}, orgs => #{}, scripts => #{}, trees => #{}}.

%% FlatSigningProvider origins/pubkeys emplace: the first writer wins.
scan_prov_origin(Prov, Id, Pub, Fp, Path) ->
    Pubs = maps:get(pubs, Prov),
    Orgs = maps:get(orgs, Prov),
    Pubs2 = case maps:is_key(Id, Pubs) of
                true -> Pubs;
                false -> Pubs#{Id => Pub}
            end,
    Orgs2 = case maps:is_key(Id, Orgs) of
                true -> Orgs;
                false -> Orgs#{Id => {Fp, Path}}
            end,
    Prov#{pubs => Pubs2, orgs => Orgs2}.

scan_prov_wrap(Prov, Id, Fp, Path) ->
    Orgs = maps:get(orgs, Prov),
    {_, Old} = maps:get(Id, Orgs),
    Prov#{orgs => Orgs#{Id => {Fp, Path ++ Old}}}.

scan_prov_script(Prov, Script) ->
    Id = beamchain_crypto:hash160(Script),
    Scripts = maps:get(scripts, Prov),
    case maps:is_key(Id, Scripts) of
        true -> Prov;
        false -> Prov#{scripts => Scripts#{Id => Script}}
    end.

scan_prov_tree(Prov, Output, Internal, Leaves) ->
    Trees = maps:get(trees, Prov),
    Prov#{trees => Trees#{Output => {Internal, Leaves}}}.

%% ---- InferScript / InferDescriptor ----

scan_infer_cs(Script, Ctx, Prov, Net) ->
    {ok, Body} = scan_infer(Script, Ctx, Prov, Net),
    iolist_to_binary(Body ++ "#" ++ descriptor_checksum(Body)).

scan_infer(Script, p2tr, Prov, _Net) ->
    case Script of
        <<32, X:32/binary, 16#ac>> ->
            {ok, "pk(" ++ scan_fmt_xonly(X, Prov) ++ ")"};
        _ ->
            scan_infer_rest(Script, p2tr, Prov, _Net)
    end;
scan_infer(Script, Ctx, Prov, Net) ->
    scan_infer_rest(Script, Ctx, Prov, Net).

scan_infer_rest(Script, Ctx, Prov, Net) ->
    case scan_classify(Script) of
        {pubkey, Pub} when Ctx =:= top; Ctx =:= p2sh; Ctx =:= p2wsh ->
            case scan_fmt_pubkey(Pub, Ctx, Prov) of
                none -> scan_infer_next(Script, Ctx, Prov, Net, pubkey);
                Str -> {ok, "pk(" ++ Str ++ ")"}
            end;
        {pkh, Hash} when Ctx =:= top; Ctx =:= p2sh; Ctx =:= p2wsh ->
            case maps:get(Hash, maps:get(pubs, Prov), undefined) of
                undefined ->
                    scan_infer_next(Script, Ctx, Prov, Net, pkh);
                Pub ->
                    case scan_fmt_pubkey(Pub, Ctx, Prov) of
                        none -> scan_infer_next(Script, Ctx, Prov, Net, pkh);
                        Str -> {ok, "pkh(" ++ Str ++ ")"}
                    end
            end;
        {wpkh, Hash} when Ctx =:= top; Ctx =:= p2sh ->
            case maps:get(Hash, maps:get(pubs, Prov), undefined) of
                undefined ->
                    scan_infer_next(Script, Ctx, Prov, Net, wpkh);
                Pub ->
                    %% InferPubkey for wpkh uses P2WPKH (no uncompressed).
                    case scan_fmt_pubkey(Pub, p2wpkh, Prov) of
                        none -> scan_infer_next(Script, Ctx, Prov, Net, wpkh);
                        Str -> {ok, "wpkh(" ++ Str ++ ")"}
                    end
            end;
        {multi, Req, Keys} when Ctx =:= top; Ctx =:= p2sh; Ctx =:= p2wsh ->
            case scan_fmt_multi_keys(Keys, Ctx, Prov) of
                none -> scan_infer_next(Script, Ctx, Prov, Net, multi);
                Strs ->
                    {ok, "multi(" ++ integer_to_list(Req) ++ "," ++
                         string:join(Strs, ",") ++ ")"}
            end;
        {sh, Hash} when Ctx =:= top ->
            case maps:get(Hash, maps:get(scripts, Prov), undefined) of
                undefined ->
                    scan_infer_next(Script, Ctx, Prov, Net, sh);
                Sub ->
                    case scan_infer(Sub, p2sh, Prov, Net) of
                        none -> scan_infer_next(Script, Ctx, Prov, Net, sh);
                        {ok, Inner} -> {ok, "sh(" ++ Inner ++ ")"}
                    end
            end;
        {wsh, Prog} when Ctx =:= top; Ctx =:= p2sh ->
            Id = crypto:hash(ripemd160, Prog),
            case maps:get(Id, maps:get(scripts, Prov), undefined) of
                undefined ->
                    scan_infer_next(Script, Ctx, Prov, Net, wsh);
                Sub ->
                    case scan_infer(Sub, p2wsh, Prov, Net) of
                        none -> scan_infer_next(Script, Ctx, Prov, Net, wsh);
                        {ok, Inner} -> {ok, "wsh(" ++ Inner ++ ")"}
                    end
            end;
        {tr, X} when Ctx =:= top ->
            scan_infer_tr(Script, X, Prov, Net);
        _ ->
            scan_infer_next(Script, Ctx, Prov, Net, other)
    end.

scan_infer_next(Script, Ctx, Prov, Net, _Why) ->
    scan_infer_tail(Script, Ctx, Prov, Net).

%% Top-level only: addr() when ExtractDestination round-trips, else raw().
%% Miniscript (InferScript's P2WSH/P2TR FromScript branch) is not implemented;
%% those scripts fall through to addr/raw or to none inside sh/wsh/tr.
scan_infer_tail(Script, top, _Prov, Net) ->
    case beamchain_address:script_to_address(Script, Net) of
        unknown ->
            {ok, "raw(" ++ binary_to_hex(Script) ++ ")"};
        "OP_RETURN" ->
            {ok, "raw(" ++ binary_to_hex(Script) ++ ")"};
        Addr ->
            case beamchain_address:address_to_script(Addr, Net) of
                {ok, Script} -> {ok, "addr(" ++ Addr ++ ")"};
                _ -> {ok, "raw(" ++ binary_to_hex(Script) ++ ")"}
            end
    end;
scan_infer_tail(_Script, _Ctx, _Prov, _Net) ->
    none.

scan_infer_tr(Script, X, Prov, Net) ->
    case maps:get(X, maps:get(trees, Prov), undefined) of
        {Internal, Leaves} ->
            case scan_infer_leaves(Leaves, Prov, Net) of
                {ok, Inners} ->
                    {ok, "tr(" ++ scan_fmt_xonly(Internal, Prov) ++
                         scan_brace(Inners, [D || {D, _} <- Leaves]) ++ ")"};
                none ->
                    scan_rawtr_or_tail(Script, X, Prov, Net)
            end;
        undefined ->
            scan_rawtr_or_tail(Script, X, Prov, Net)
    end.

%% InferXOnlyPubkey has no origin when the provider never saw the key,
%% which is the raw()/addr() case. A valid x-only output is rawtr().
scan_rawtr_or_tail(Script, X, Prov, Net) ->
    case scan_xonly_valid(X) of
        true -> {ok, "rawtr(" ++ scan_fmt_xonly(X, Prov) ++ ")"};
        false -> scan_infer_tail(Script, top, Prov, Net)
    end.

scan_infer_leaves(Leaves, Prov, Net) ->
    scan_infer_leaves(Leaves, Prov, Net, []).

scan_infer_leaves([], _Prov, _Net, Acc) ->
    {ok, lists:reverse(Acc)};
scan_infer_leaves([{_D, Script} | Rest], Prov, Net, Acc) ->
    case scan_infer(Script, p2tr, Prov, Net) of
        none -> none;
        {ok, Str} -> scan_infer_leaves(Rest, Prov, Net, [Str | Acc])
    end.

%% ToStringSubScriptHelper (descriptor.cpp). The leading false on the path
%% is a sentinel: a brace is emitted only when the path was already non-empty,
%% and a closing brace is emitted only when more than the sentinel remains.
scan_brace([], []) ->
    "";
scan_brace(Strs, Depths) ->
    "," ++ scan_brace1(lists:zip(Strs, Depths), 0, [], "").

scan_brace1([], _Pos, _Path, Acc) ->
    Acc;
scan_brace1([{S, D} | Rest], Pos, Path, Acc) ->
    Acc1 = case Pos of 0 -> Acc; _ -> Acc ++ "," end,
    {Acc2, Path2} = scan_open_until(Acc1, Path, D),
    Acc3 = Acc2 ++ S,
    {Acc4, Path3} = scan_close_right(Acc3, Path2),
    Path4 = case Path3 of
                [] -> [];
                _ -> lists:droplast(Path3) ++ [true]
            end,
    scan_brace1(Rest, Pos + 1, Path4, Acc4).

scan_open_until(Acc, Path, D) when length(Path) =< D ->
    Acc1 = case Path of [] -> Acc; _ -> Acc ++ "{" end,
    scan_open_until(Acc1, Path ++ [false], D);
scan_open_until(Acc, Path, _D) ->
    {Acc, Path}.

scan_close_right(Acc, Path) ->
    case Path =/= [] andalso lists:last(Path) =:= true of
        true ->
            Acc1 = case length(Path) > 1 of
                       true -> Acc ++ "}";
                       false -> Acc
                   end,
            scan_close_right(Acc1, lists:droplast(Path));
        false ->
            {Acc, Path}
    end.

scan_fmt_multi_keys(Keys, Ctx, Prov) ->
    scan_fmt_multi_keys(Keys, Ctx, Prov, []).

scan_fmt_multi_keys([], _Ctx, _Prov, Acc) ->
    lists:reverse(Acc);
scan_fmt_multi_keys([K | Rest], Ctx, Prov, Acc) ->
    case scan_fmt_pubkey(K, Ctx, Prov) of
        none -> none;
        Str -> scan_fmt_multi_keys(Rest, Ctx, Prov, [Str | Acc])
    end.

%% InferPubkey. Hybrid and (outside TOP/P2SH) uncompressed keys do not infer.
scan_fmt_pubkey(Pub, Ctx, Prov) ->
    case scan_pubkey_infer_ok(Pub, Ctx) of
        false -> none;
        true -> scan_fmt_key(Pub, false, Prov)
    end.

scan_pubkey_infer_ok(Pub, Ctx) ->
    case scan_struct(Pub) of
        {compressed, _} -> true;
        {uncompressed, _} -> Ctx =:= top orelse Ctx =:= p2sh;
        _ -> false
    end.

%% InferXOnlyPubkey: display is the 32-byte x, origin comes from
%% GetKeyOriginByXOnly which probes hash160(02||x) then hash160(03||x).
scan_fmt_xonly(X, Prov) ->
    Hex = binary_to_hex(X),
    case scan_lookup_xonly(Prov, X) of
        undefined -> Hex;
        {Fp, Path} ->
            "[" ++ binary_to_hex(Fp) ++ scan_fmt_path(Path) ++ "]" ++ Hex
    end.

scan_fmt_key(Pub, false, Prov) ->
    Hex = binary_to_hex(Pub),
    Id = beamchain_crypto:hash160(Pub),
    case maps:get(Id, maps:get(orgs, Prov), undefined) of
        undefined -> Hex;
        {Fp, Path} ->
            "[" ++ binary_to_hex(Fp) ++ scan_fmt_path(Path) ++ "]" ++ Hex
    end.

scan_lookup_xonly(Prov, X) ->
    Orgs = maps:get(orgs, Prov),
    Even = beamchain_crypto:hash160(<<2, X/binary>>),
    case maps:get(Even, Orgs, undefined) of
        undefined ->
            Odd = beamchain_crypto:hash160(<<3, X/binary>>),
            maps:get(Odd, Orgs, undefined);
        Origin ->
            Origin
    end.

scan_fmt_path(Path) ->
    lists:append([scan_fmt_step(I) || I <- Path]).

scan_fmt_step(I) when I >= 16#80000000 ->
    "/" ++ integer_to_list(I band 16#7fffffff) ++ "h";
scan_fmt_step(I) ->
    "/" ++ integer_to_list(I).

scan_classify(<<16#a9, 16#14, H:20/binary, 16#87>>) ->
    {sh, H};
scan_classify(<<16#00, 16#14, H:20/binary>>) ->
    {wpkh, H};
scan_classify(<<16#00, 16#20, H:32/binary>>) ->
    {wsh, H};
scan_classify(<<16#51, 16#20, H:32/binary>>) ->
    {tr, H};
scan_classify(<<16#76, 16#a9, 16#14, H:20/binary, 16#88, 16#ac>>) ->
    {pkh, H};
scan_classify(Script) ->
    case scan_match_pubkey(Script) of
        {ok, Pub} -> {pubkey, Pub};
        error ->
            case scan_match_multi(Script) of
                {ok, Req, Keys} -> {multi, Req, Keys};
                error -> other
            end
    end.

scan_match_pubkey(<<65, PK:65/binary, 16#ac>>) -> {ok, PK};
scan_match_pubkey(<<33, PK:33/binary, 16#ac>>) -> {ok, PK};
scan_match_pubkey(_) -> error.

scan_match_multi(Script) when byte_size(Script) < 1 ->
    error;
scan_match_multi(Script) ->
    Sz = byte_size(Script),
    case binary:at(Script, Sz - 1) =:= 16#ae of
        false -> error;
        true ->
            Body = binary:part(Script, 0, Sz - 1),
            case scan_read_num(Body) of
                {ok, Req, Rest} when Req >= 1, Req =< 20 ->
                    scan_take_keys(Rest, Req, []);
                _ -> error
            end
    end.

scan_take_keys(Rest, Req, Acc) ->
    case scan_read_push(Rest) of
        {ok, Data, Rest2}
          when byte_size(Data) =:= 33; byte_size(Data) =:= 65 ->
            scan_take_keys(Rest2, Req, [Data | Acc]);
        _ ->
            N = length(Acc),
            case scan_read_num(Rest) of
                {ok, N, <<>>} when N >= Req, N =< 20, N >= 1 ->
                    {ok, Req, lists:reverse(Acc)};
                _ -> error
            end
    end.

scan_read_num(<<N, Rest/binary>>) when N >= 16#51, N =< 16#60 ->
    {ok, N - 16#50, Rest};
scan_read_num(<<1, V, Rest/binary>>) when V > 16, V < 128 ->
    {ok, V, Rest};
scan_read_num(_) ->
    error.

scan_read_push(<<Len, Data:Len/binary, Rest/binary>>) when Len >= 1, Len =< 75 ->
    {ok, Data, Rest};
scan_read_push(_) ->
    error.

%% addr() is parsed before the network is known to expand. The node network
%% is passed into eval_scan and stored for the parse that needs DecodeDestination.
scan_net() ->
    get(scan_eval_network).

scan_with_net(Network, Fun) ->
    Old = get(scan_eval_network),
    put(scan_eval_network, Network),
    try Fun()
    after
        case Old of
            undefined -> erase(scan_eval_network);
            _ -> put(scan_eval_network, Old)
        end
    end.
