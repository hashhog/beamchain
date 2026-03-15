-module(beamchain_miniscript).

%% Miniscript implementation for Bitcoin Script.
%% Based on the Miniscript specification and Bitcoin Core's implementation.
%% Reference: /home/max/hashhog/bitcoin/src/script/miniscript.cpp

%% Public API
-export([from_string/1, compile/1, satisfy/2]).
-export([type_check/1, get_type/1, get_properties/1]).
-export([script_size/1, max_witness_size/1, max_stack_size/1]).
-export([to_string/1]).

%% Internal exports for testing
-export([compute_type/1, validate_type/1]).

%%% -------------------------------------------------------------------
%%% Miniscript AST Types
%%% -------------------------------------------------------------------
%%
%% The miniscript AST is represented as tagged tuples:
%%
%% Leaf nodes:
%%   {pk_k, PubKey}                 - Public key (33 bytes compressed)
%%   {pk_h, PubKeyHash}             - Public key hash (20 bytes)
%%   {older, N}                     - Relative timelock (BIP68)
%%   {after_, N}                    - Absolute timelock (CLTV)
%%   {sha256, Hash}                 - SHA256 preimage check (32 bytes)
%%   {hash256, Hash}                - HASH256 preimage check (32 bytes)
%%   {ripemd160, Hash}              - RIPEMD160 preimage check (20 bytes)
%%   {hash160, Hash}                - HASH160 preimage check (20 bytes)
%%   just_1                         - OP_1 (always true)
%%   just_0                         - OP_0 (always false)
%%
%% Wrappers (single subexpression):
%%   {wrap_a, X}                    - OP_TOALTSTACK [X] OP_FROMALTSTACK
%%   {wrap_s, X}                    - OP_SWAP [X]
%%   {wrap_c, X}                    - [X] OP_CHECKSIG
%%   {wrap_d, X}                    - OP_DUP OP_IF [X] OP_ENDIF
%%   {wrap_v, X}                    - [X] OP_VERIFY (or merged)
%%   {wrap_j, X}                    - OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
%%   {wrap_n, X}                    - [X] OP_0NOTEQUAL
%%
%% Combinators (two subexpressions):
%%   {and_v, X, Y}                  - [X] [Y]
%%   {and_b, X, Y}                  - [X] [Y] OP_BOOLAND
%%   {or_b, X, Y}                   - [X] [Y] OP_BOOLOR
%%   {or_c, X, Y}                   - [X] OP_NOTIF [Y] OP_ENDIF
%%   {or_d, X, Y}                   - [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
%%   {or_i, X, Y}                   - OP_IF [X] OP_ELSE [Y] OP_ENDIF
%%   {andor, X, Y, Z}               - [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
%%
%% Threshold:
%%   {thresh, K, [Sub]}             - threshold with K of N satisfaction
%%   {multi, K, [Key]}              - OP_CHECKMULTISIG (P2WSH only)
%%   {multi_a, K, [Key]}            - OP_CHECKSIGADD (Tapscript only)
%%
%%% -------------------------------------------------------------------

%%% -------------------------------------------------------------------
%%% Type System
%%% -------------------------------------------------------------------
%%
%% Type (one of): B, V, K, W
%% Properties: z, o, n, d, u, e, f, s, m, x, k (and timelock: g, h, i, j)
%%
%% Represented as a map:
%% #{type => B|V|K|W, z => bool, o => bool, ...}
%%

-define(OP_0, 16#00).
-define(OP_PUSHDATA1, 16#4c).
-define(OP_PUSHDATA2, 16#4d).
-define(OP_PUSHDATA4, 16#4e).
-define(OP_1NEGATE, 16#4f).
-define(OP_1, 16#51).
-define(OP_16, 16#60).

-define(OP_NOP, 16#61).
-define(OP_IF, 16#63).
-define(OP_NOTIF, 16#64).
-define(OP_ELSE, 16#67).
-define(OP_ENDIF, 16#68).
-define(OP_VERIFY, 16#69).
-define(OP_RETURN, 16#6a).

-define(OP_TOALTSTACK, 16#6b).
-define(OP_FROMALTSTACK, 16#6c).
-define(OP_2DROP, 16#6d).
-define(OP_2DUP, 16#6e).
-define(OP_DROP, 16#75).
-define(OP_DUP, 16#76).
-define(OP_IFDUP, 16#73).
-define(OP_SWAP, 16#7c).
-define(OP_SIZE, 16#82).

-define(OP_EQUAL, 16#87).
-define(OP_EQUALVERIFY, 16#88).

-define(OP_0NOTEQUAL, 16#92).
-define(OP_ADD, 16#93).
-define(OP_BOOLAND, 16#9a).
-define(OP_BOOLOR, 16#9b).
-define(OP_NUMEQUAL, 16#9c).
-define(OP_NUMEQUALVERIFY, 16#9d).

-define(OP_RIPEMD160, 16#a6).
-define(OP_SHA256, 16#a8).
-define(OP_HASH160, 16#a9).
-define(OP_HASH256, 16#aa).
-define(OP_CHECKSIG, 16#ac).
-define(OP_CHECKSIGVERIFY, 16#ad).
-define(OP_CHECKMULTISIG, 16#ae).
-define(OP_CHECKMULTISIGVERIFY, 16#af).

-define(OP_CHECKLOCKTIMEVERIFY, 16#b1).
-define(OP_CHECKSEQUENCEVERIFY, 16#b2).
-define(OP_CHECKSIGADD, 16#ba).

%%% ===================================================================
%%% Public API
%%% ===================================================================

%% @doc Parse a miniscript string into an AST.
%% Returns {ok, AST} or {error, Reason}.
-spec from_string(string() | binary()) -> {ok, term()} | {error, term()}.
from_string(Str) when is_binary(Str) ->
    from_string(binary_to_list(Str));
from_string(Str) ->
    case parse_expr(Str) of
        {ok, AST, []} ->
            case type_check(AST) of
                {ok, _Type} -> {ok, AST};
                {error, _} = Err -> Err
            end;
        {ok, _, Remaining} ->
            {error, {unexpected_trailing, Remaining}};
        {error, _} = Err ->
            Err
    end.

%% @doc Compile an AST to Bitcoin Script.
-spec compile(term()) -> binary().
compile(AST) ->
    iolist_to_binary(compile_node(AST, false)).

%% @doc Generate a witness that satisfies the miniscript given available data.
%% Env is a map with keys: sigs, preimages, locktime, sequence
%% Returns {ok, WitnessStack} or {error, Reason}.
-spec satisfy(term(), map()) -> {ok, [binary()]} | {error, term()}.
satisfy(AST, Env) ->
    case produce_satisfaction(AST, Env) of
        {ok, Sat, _Dissatisfied} when Sat =/= unavailable ->
            {ok, Sat};
        _ ->
            {error, unsatisfiable}
    end.

%% @doc Type-check a miniscript AST.
%% Returns {ok, Type} or {error, Reason}.
-spec type_check(term()) -> {ok, map()} | {error, term()}.
type_check(AST) ->
    try
        Type = compute_type(AST),
        case validate_type(Type) of
            ok -> {ok, Type};
            {error, _} = Err -> Err
        end
    catch
        throw:{type_error, Reason} -> {error, Reason}
    end.

%% @doc Get the type of a miniscript node.
-spec get_type(term()) -> atom().
get_type(AST) ->
    Type = compute_type(AST),
    maps:get(type, Type).

%% @doc Get all properties of a miniscript node.
-spec get_properties(term()) -> map().
get_properties(AST) ->
    compute_type(AST).

%% @doc Calculate the script size in bytes.
-spec script_size(term()) -> non_neg_integer().
script_size(AST) ->
    byte_size(compile(AST)).

%% @doc Calculate the maximum witness size in bytes.
-spec max_witness_size(term()) -> non_neg_integer().
max_witness_size(AST) ->
    {Max, _} = witness_size(AST),
    Max.

%% @doc Calculate the maximum stack size during execution.
-spec max_stack_size(term()) -> non_neg_integer().
max_stack_size(_AST) ->
    %% Simplified: return a conservative estimate
    %% Real implementation would track stack depth through execution
    201.  %% P2WSH limit

%% @doc Convert AST back to miniscript string notation.
-spec to_string(term()) -> string().
to_string(AST) ->
    ast_to_string(AST).

%%% ===================================================================
%%% Type Computation
%%% ===================================================================

compute_type({pk_k, _Key}) ->
    %% pk_k: Pushes key, needs sig -> K type
    %% Properties: o, n, u, d, e, m, s, x, k
    #{type => 'K', z => false, o => true, n => true, d => true, u => true,
      e => true, f => false, s => true, m => true, x => true, k => true,
      g => false, h => false, i => false, j => false};

compute_type({pk_h, _Hash}) ->
    %% pk_h: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY -> K type
    %% Properties: n, u, d, e, m, s, k
    #{type => 'K', z => false, o => false, n => true, d => true, u => true,
      e => true, f => false, s => true, m => true, x => false, k => true,
      g => false, h => false, i => false, j => false};

compute_type({older, N}) when is_integer(N), N >= 1, N < 16#80000000 ->
    %% older: <n> OP_CHECKSEQUENCEVERIFY -> B type
    %% Always dissatisfiable, forced
    %% Timelock: g if time-based (bit 22 set), h if height-based
    IsTime = (N band 16#400000) =/= 0,
    #{type => 'B', z => true, o => false, n => false, d => false, u => false,
      e => false, f => true, s => false, m => true, x => true, k => true,
      g => IsTime, h => not IsTime, i => false, j => false};

compute_type({after_, N}) when is_integer(N), N >= 1, N < 16#80000000 ->
    %% after: <n> OP_CHECKLOCKTIMEVERIFY -> B type
    %% Timelock: i if time-based (>= 500000000), j if height-based
    IsTime = N >= 500000000,
    #{type => 'B', z => true, o => false, n => false, d => false, u => false,
      e => false, f => true, s => false, m => true, x => true, k => true,
      g => false, h => false, i => IsTime, j => not IsTime};

compute_type({sha256, Hash}) when byte_size(Hash) =:= 32 ->
    %% sha256: OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL -> B type
    #{type => 'B', z => false, o => true, n => true, d => true, u => true,
      e => false, f => false, s => false, m => true, x => false, k => true,
      g => false, h => false, i => false, j => false};

compute_type({hash256, Hash}) when byte_size(Hash) =:= 32 ->
    #{type => 'B', z => false, o => true, n => true, d => true, u => true,
      e => false, f => false, s => false, m => true, x => false, k => true,
      g => false, h => false, i => false, j => false};

compute_type({ripemd160, Hash}) when byte_size(Hash) =:= 20 ->
    #{type => 'B', z => false, o => true, n => true, d => true, u => true,
      e => false, f => false, s => false, m => true, x => false, k => true,
      g => false, h => false, i => false, j => false};

compute_type({hash160, Hash}) when byte_size(Hash) =:= 20 ->
    #{type => 'B', z => false, o => true, n => true, d => true, u => true,
      e => false, f => false, s => false, m => true, x => false, k => true,
      g => false, h => false, i => false, j => false};

compute_type(just_1) ->
    %% OP_1: Always true, B type
    #{type => 'B', z => true, o => false, n => false, d => false, u => true,
      e => false, f => true, s => false, m => true, x => true, k => true,
      g => false, h => false, i => false, j => false};

compute_type(just_0) ->
    %% OP_0: Always false, B type
    #{type => 'B', z => true, o => false, n => false, d => true, u => true,
      e => true, f => false, s => false, m => true, x => true, k => true,
      g => false, h => false, i => false, j => false};

compute_type({wrap_a, X}) ->
    %% a:X = OP_TOALTSTACK [X] OP_FROMALTSTACK
    %% Converts B to W
    Tx = compute_type(X),
    require_type(Tx, 'B'),
    #{type => 'W',
      z => false,
      o => prop(Tx, o),
      n => false,  %% W cannot be n
      d => prop(Tx, d),
      u => prop(Tx, u),
      e => prop(Tx, e),
      f => prop(Tx, f),
      s => prop(Tx, s),
      m => prop(Tx, m),
      x => true,
      k => prop(Tx, k),
      g => prop(Tx, g), h => prop(Tx, h), i => prop(Tx, i), j => prop(Tx, j)};

compute_type({wrap_s, X}) ->
    %% s:X = OP_SWAP [X]
    %% Converts Bo to W
    Tx = compute_type(X),
    require_type(Tx, 'B'),
    case prop(Tx, o) of
        false -> throw({type_error, {wrap_s_requires_o, X}});
        true -> ok
    end,
    #{type => 'W',
      z => false,
      o => prop(Tx, o),
      n => false,
      d => prop(Tx, d),
      u => prop(Tx, u),
      e => prop(Tx, e),
      f => prop(Tx, f),
      s => prop(Tx, s),
      m => prop(Tx, m),
      x => prop(Tx, x),
      k => prop(Tx, k),
      g => prop(Tx, g), h => prop(Tx, h), i => prop(Tx, i), j => prop(Tx, j)};

compute_type({wrap_c, X}) ->
    %% c:X = [X] OP_CHECKSIG
    %% Converts K to B
    Tx = compute_type(X),
    require_type(Tx, 'K'),
    #{type => 'B',
      z => false,
      o => prop(Tx, o),
      n => prop(Tx, n),
      d => prop(Tx, d),
      u => true,  %% CHECKSIG always pushes 0 or 1
      e => prop(Tx, e),
      f => prop(Tx, f),
      s => true,  %% Requires signature
      m => prop(Tx, m),
      x => false,  %% CHECKSIG allows verify optimization
      k => prop(Tx, k),
      g => prop(Tx, g), h => prop(Tx, h), i => prop(Tx, i), j => prop(Tx, j)};

compute_type({wrap_d, X}) ->
    %% d:X = OP_DUP OP_IF [X] OP_ENDIF
    %% Converts Vz to B
    Tx = compute_type(X),
    require_type(Tx, 'V'),
    case prop(Tx, z) of
        false -> throw({type_error, {wrap_d_requires_z, X}});
        true -> ok
    end,
    #{type => 'B',
      z => false,
      o => prop(Tx, z),  %% o if X is z
      n => true,
      d => true,
      u => false,  %% Can leave non-unit on stack
      e => false,
      f => false,
      s => prop(Tx, s),
      m => prop(Tx, m),
      x => true,
      k => prop(Tx, k),
      g => prop(Tx, g), h => prop(Tx, h), i => prop(Tx, i), j => prop(Tx, j)};

compute_type({wrap_v, X}) ->
    %% v:X = [X] OP_VERIFY (or merged into last opcode)
    %% Converts B to V
    Tx = compute_type(X),
    require_type(Tx, 'B'),
    #{type => 'V',
      z => prop(Tx, z),
      o => prop(Tx, o),
      n => prop(Tx, n),
      d => false,  %% V cannot be dissatisfied
      u => false,  %% V pushes nothing
      e => false,
      f => true,   %% V is forced (can't dissatisfy)
      s => prop(Tx, s),
      m => prop(Tx, m),
      x => true,   %% Ends with VERIFY (expensive)
      k => prop(Tx, k),
      g => prop(Tx, g), h => prop(Tx, h), i => prop(Tx, i), j => prop(Tx, j)};

compute_type({wrap_j, X}) ->
    %% j:X = OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    %% Converts Bn to B (adds dissatisfiability with empty input)
    Tx = compute_type(X),
    require_type(Tx, 'B'),
    case prop(Tx, n) of
        false -> throw({type_error, {wrap_j_requires_n, X}});
        true -> ok
    end,
    #{type => 'B',
      z => false,
      o => prop(Tx, o),
      n => false,
      d => true,   %% Can dissatisfy with empty
      u => prop(Tx, u),
      e => prop(Tx, f),  %% e if X is f (no non-canonical dissatisfaction)
      f => false,
      s => prop(Tx, s),
      m => prop(Tx, m),
      x => true,
      k => prop(Tx, k),
      g => prop(Tx, g), h => prop(Tx, h), i => prop(Tx, i), j => prop(Tx, j)};

compute_type({wrap_n, X}) ->
    %% n:X = [X] OP_0NOTEQUAL
    %% Adds u property
    Tx = compute_type(X),
    require_type(Tx, 'B'),
    Tx#{u => true, x => true};

compute_type({and_v, X, Y}) ->
    %% [X] [Y] - X must be V, result type is Y's type
    Tx = compute_type(X),
    Ty = compute_type(Y),
    require_type(Tx, 'V'),
    YType = maps:get(type, Ty),
    #{type => YType,
      z => prop(Tx, z) andalso prop(Ty, z),
      o => (prop(Tx, z) andalso prop(Ty, o)) orelse (prop(Tx, o) andalso prop(Ty, z)),
      n => prop(Tx, n) orelse (prop(Tx, z) andalso prop(Ty, n)),
      d => false,  %% V is forced, so and_v is forced if X is V
      u => prop(Ty, u),
      e => false,
      f => true,   %% X is V (forced), so whole thing is forced
      s => prop(Tx, s) orelse prop(Ty, s),
      m => prop(Tx, m) andalso prop(Ty, m),
      x => prop(Ty, x),
      k => prop(Tx, k) andalso prop(Ty, k) andalso not timelock_conflict(Tx, Ty),
      g => prop(Tx, g) orelse prop(Ty, g),
      h => prop(Tx, h) orelse prop(Ty, h),
      i => prop(Tx, i) orelse prop(Ty, i),
      j => prop(Tx, j) orelse prop(Ty, j)};

compute_type({and_b, X, Y}) ->
    %% [X] [Y] OP_BOOLAND - X must be B, Y must be W
    Tx = compute_type(X),
    Ty = compute_type(Y),
    require_type(Tx, 'B'),
    require_type(Ty, 'W'),
    #{type => 'B',
      z => prop(Tx, z) andalso prop(Ty, z),
      o => (prop(Tx, z) andalso prop(Ty, o)) orelse (prop(Tx, o) andalso prop(Ty, z)),
      n => prop(Tx, n) orelse (prop(Tx, z) andalso prop(Ty, n)),
      d => prop(Tx, d) andalso prop(Ty, d),
      u => false,  %% BOOLAND can return 0 or 1, but not guaranteed unit
      e => prop(Tx, e) andalso prop(Ty, e) andalso (prop(Tx, s) orelse prop(Ty, s)),
      f => (prop(Tx, f) andalso prop(Ty, f)) orelse
           (prop(Tx, f) andalso prop(Tx, s)) orelse
           (prop(Ty, f) andalso prop(Ty, s)),
      s => prop(Tx, s) orelse prop(Ty, s),
      m => prop(Tx, m) andalso prop(Ty, m),
      x => true,
      k => prop(Tx, k) andalso prop(Ty, k) andalso not timelock_conflict(Tx, Ty),
      g => prop(Tx, g) orelse prop(Ty, g),
      h => prop(Tx, h) orelse prop(Ty, h),
      i => prop(Tx, i) orelse prop(Ty, i),
      j => prop(Tx, j) orelse prop(Ty, j)};

compute_type({or_b, X, Y}) ->
    %% [X] [Y] OP_BOOLOR - X must be Bd, Y must be Wd
    Tx = compute_type(X),
    Ty = compute_type(Y),
    require_type(Tx, 'B'),
    require_type(Ty, 'W'),
    require_prop(Tx, d, or_b_requires_d_x),
    require_prop(Ty, d, or_b_requires_d_y),
    #{type => 'B',
      z => prop(Tx, z) andalso prop(Ty, z),
      o => (prop(Tx, z) andalso prop(Ty, o)) orelse (prop(Tx, o) andalso prop(Ty, z)),
      n => false,
      d => true,
      u => false,
      e => prop(Tx, e) andalso prop(Ty, e),
      f => false,
      s => prop(Tx, s) andalso prop(Ty, s),
      m => prop(Tx, m) andalso prop(Ty, m) andalso prop(Tx, e) andalso prop(Ty, e),
      x => true,
      k => prop(Tx, k) andalso prop(Ty, k),  %% OR doesn't require both, so no conflict
      g => prop(Tx, g) orelse prop(Ty, g),
      h => prop(Tx, h) orelse prop(Ty, h),
      i => prop(Tx, i) orelse prop(Ty, i),
      j => prop(Tx, j) orelse prop(Ty, j)};

compute_type({or_c, X, Y}) ->
    %% [X] OP_NOTIF [Y] OP_ENDIF - X must be Bdu, Y must be V
    Tx = compute_type(X),
    Ty = compute_type(Y),
    require_type(Tx, 'B'),
    require_type(Ty, 'V'),
    require_prop(Tx, d, or_c_requires_d),
    require_prop(Tx, u, or_c_requires_u),
    #{type => 'V',
      z => prop(Tx, z) andalso prop(Ty, z),
      o => prop(Tx, o) andalso prop(Ty, z),
      n => false,
      d => false,
      u => false,
      e => false,
      f => true,
      s => prop(Tx, s) orelse prop(Ty, s),
      m => prop(Tx, m) andalso prop(Ty, m) andalso prop(Tx, e),
      x => true,
      k => prop(Tx, k) andalso prop(Ty, k),
      g => prop(Tx, g) orelse prop(Ty, g),
      h => prop(Tx, h) orelse prop(Ty, h),
      i => prop(Tx, i) orelse prop(Ty, i),
      j => prop(Tx, j) orelse prop(Ty, j)};

compute_type({or_d, X, Y}) ->
    %% [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF - X must be Bdu, Y must be B
    Tx = compute_type(X),
    Ty = compute_type(Y),
    require_type(Tx, 'B'),
    require_type(Ty, 'B'),
    require_prop(Tx, d, or_d_requires_d),
    require_prop(Tx, u, or_d_requires_u),
    #{type => 'B',
      z => prop(Tx, z) andalso prop(Ty, z),
      o => prop(Tx, o) andalso prop(Ty, z),
      n => false,
      d => prop(Ty, d),
      u => prop(Ty, u),
      e => prop(Ty, e),
      f => prop(Ty, f),
      s => prop(Tx, s) orelse prop(Ty, s),
      m => prop(Tx, m) andalso prop(Ty, m) andalso prop(Tx, e),
      x => true,
      k => prop(Tx, k) andalso prop(Ty, k),
      g => prop(Tx, g) orelse prop(Ty, g),
      h => prop(Tx, h) orelse prop(Ty, h),
      i => prop(Tx, i) orelse prop(Ty, i),
      j => prop(Tx, j) orelse prop(Ty, j)};

compute_type({or_i, X, Y}) ->
    %% OP_IF [X] OP_ELSE [Y] OP_ENDIF
    %% X and Y must have same type (B, V, or K)
    Tx = compute_type(X),
    Ty = compute_type(Y),
    XType = maps:get(type, Tx),
    YType = maps:get(type, Ty),
    case XType =:= YType of
        false -> throw({type_error, {or_i_type_mismatch, XType, YType}});
        true -> ok
    end,
    #{type => XType,
      z => false,
      o => prop(Tx, o) andalso prop(Ty, o),  %% Changed: both must be o
      n => false,
      d => prop(Tx, d) orelse prop(Ty, d),
      u => prop(Tx, u) andalso prop(Ty, u),
      e => (prop(Tx, e) andalso prop(Ty, f)) orelse (prop(Tx, f) andalso prop(Ty, e)),
      f => prop(Tx, f) andalso prop(Ty, f),
      s => prop(Tx, s) orelse prop(Ty, s),
      m => prop(Tx, m) andalso prop(Ty, m) andalso (prop(Tx, s) orelse prop(Ty, s)),
      x => true,
      k => prop(Tx, k) andalso prop(Ty, k),
      g => prop(Tx, g) orelse prop(Ty, g),
      h => prop(Tx, h) orelse prop(Ty, h),
      i => prop(Tx, i) orelse prop(Ty, i),
      j => prop(Tx, j) orelse prop(Ty, j)};

compute_type({andor, X, Y, Z}) ->
    %% [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    %% X must be Bdu, Y and Z must have same type (B, V, or K)
    Tx = compute_type(X),
    Ty = compute_type(Y),
    Tz = compute_type(Z),
    require_type(Tx, 'B'),
    require_prop(Tx, d, andor_requires_d),
    require_prop(Tx, u, andor_requires_u),
    YType = maps:get(type, Ty),
    ZType = maps:get(type, Tz),
    case YType =:= ZType of
        false -> throw({type_error, {andor_type_mismatch, YType, ZType}});
        true -> ok
    end,
    #{type => YType,
      z => prop(Tx, z) andalso prop(Ty, z) andalso prop(Tz, z),
      o => (prop(Tx, z) andalso prop(Ty, o) andalso prop(Tz, o)) orelse
           (prop(Tx, o) andalso prop(Ty, z) andalso prop(Tz, z)),
      n => prop(Tx, n) orelse (prop(Tx, z) andalso prop(Ty, n) andalso prop(Tz, n)),
      d => (prop(Ty, d) orelse prop(Tz, d)),
      u => prop(Ty, u) andalso prop(Tz, u),
      e => prop(Tz, e) andalso (prop(Tx, e) orelse prop(Ty, f)),
      f => prop(Tz, f) andalso (prop(Tx, f) orelse prop(Ty, f)),
      s => prop(Tz, s) orelse (prop(Tx, s) andalso prop(Ty, s)),
      m => prop(Tx, m) andalso prop(Ty, m) andalso prop(Tz, m) andalso
           prop(Tx, e) andalso (prop(Tx, s) orelse prop(Ty, s) orelse prop(Tz, s)),
      x => true,
      k => prop(Tx, k) andalso prop(Ty, k) andalso prop(Tz, k) andalso
           not timelock_conflict(Tx, Ty),
      g => prop(Tx, g) orelse prop(Ty, g) orelse prop(Tz, g),
      h => prop(Tx, h) orelse prop(Ty, h) orelse prop(Tz, h),
      i => prop(Tx, i) orelse prop(Ty, i) orelse prop(Tz, i),
      j => prop(Tx, j) orelse prop(Ty, j) orelse prop(Tz, j)};

compute_type({thresh, K, Subs}) when is_integer(K), K >= 1, is_list(Subs), length(Subs) >= K ->
    %% [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
    %% All subs must be Bdu
    Types = [compute_type(S) || S <- Subs],
    lists:foreach(fun(T) ->
        require_type(T, 'B'),
        require_prop(T, d, thresh_requires_d),
        require_prop(T, u, thresh_requires_u)
    end, Types),

    AllZ = lists:all(fun(T) -> prop(T, z) end, Types),
    NumNonZ = length([T || T <- Types, not prop(T, z)]),
    AllO = NumNonZ =< 1,

    AllS = lists:all(fun(T) -> prop(T, s) end, Types),
    AllE = lists:all(fun(T) -> prop(T, e) end, Types),
    AllM = lists:all(fun(T) -> prop(T, m) end, Types),

    %% Nonmalleable only if all are e and m, and k = 1 or k = n
    NonMall = AllE andalso AllM andalso (K =:= 1 orelse K =:= length(Subs)),

    #{type => 'B',
      z => AllZ,
      o => AllO,
      n => false,
      d => true,
      u => true,
      e => AllE,
      f => false,
      s => AllS,
      m => NonMall,
      x => true,
      k => check_thresh_timelocks(Types, K),
      g => lists:any(fun(T) -> prop(T, g) end, Types),
      h => lists:any(fun(T) -> prop(T, h) end, Types),
      i => lists:any(fun(T) -> prop(T, i) end, Types),
      j => lists:any(fun(T) -> prop(T, j) end, Types)};

compute_type({multi, K, Keys}) when is_integer(K), K >= 1, is_list(Keys), length(Keys) >= K ->
    %% [k] [key1] ... [keyn] [n] OP_CHECKMULTISIG
    N = length(Keys),
    #{type => 'B',
      z => false,
      o => false,
      n => true,
      d => true,
      u => true,
      e => true,
      f => false,
      s => true,
      m => true,
      x => false,  %% CHECKMULTISIG allows verify optimization
      k => true,
      g => false, h => false, i => false, j => false,
      %% Extra info for witness size calculation
      k_threshold => K, n_keys => N};

compute_type({multi_a, K, Keys}) when is_integer(K), K >= 1, is_list(Keys), length(Keys) >= K ->
    %% [key1] OP_CHECKSIG ([keyn] OP_CHECKSIGADD)* [k] OP_NUMEQUAL
    N = length(Keys),
    #{type => 'B',
      z => false,
      o => false,
      n => false,
      d => true,
      u => true,
      e => true,
      f => false,
      s => true,
      m => true,
      x => false,  %% NUMEQUAL allows verify optimization
      k => true,
      g => false, h => false, i => false, j => false,
      k_threshold => K, n_keys => N}.

%% Validate that the top-level type is acceptable
validate_type(#{type := 'B'}) -> ok;
validate_type(#{type := Type}) -> {error, {invalid_top_level_type, Type}}.

%% Property helpers
prop(Type, P) -> maps:get(P, Type, false).

require_type(Type, Expected) ->
    case maps:get(type, Type) of
        Expected -> ok;
        Got -> throw({type_error, {expected_type, Expected, got, Got}})
    end.

require_prop(Type, P, ErrAtom) ->
    case prop(Type, P) of
        true -> ok;
        false -> throw({type_error, ErrAtom})
    end.

%% Check for timelock conflicts (mixing height and time in same branch)
timelock_conflict(T1, T2) ->
    %% Conflict if one has height and other has time of same category
    (prop(T1, g) andalso prop(T2, h)) orelse
    (prop(T1, h) andalso prop(T2, g)) orelse
    (prop(T1, i) andalso prop(T2, j)) orelse
    (prop(T1, j) andalso prop(T2, i)).

%% Check thresh timelock compatibility
check_thresh_timelocks(Types, _K) ->
    %% For thresh to be valid, we need at least K subs with compatible timelocks
    %% This is a simplified check
    HasConflict = lists:any(fun(T) ->
        (prop(T, g) andalso prop(T, h)) orelse
        (prop(T, i) andalso prop(T, j))
    end, Types),
    not HasConflict.

%%% ===================================================================
%%% Script Compilation
%%% ===================================================================

%% compile_node(AST, VerifyOpt) -> iolist
%% VerifyOpt indicates whether we can use *VERIFY variants
compile_node({pk_k, Key}, _Verify) when byte_size(Key) =:= 33 ->
    %% Push the public key (33 bytes compressed)
    [push_data(Key)];

compile_node({pk_h, Hash}, _Verify) when byte_size(Hash) =:= 20 ->
    %% OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
    [?OP_DUP, ?OP_HASH160, push_data(Hash), ?OP_EQUALVERIFY];

compile_node({older, N}, _Verify) ->
    %% <n> OP_CHECKSEQUENCEVERIFY
    [push_num(N), ?OP_CHECKSEQUENCEVERIFY];

compile_node({after_, N}, _Verify) ->
    %% <n> OP_CHECKLOCKTIMEVERIFY
    [push_num(N), ?OP_CHECKLOCKTIMEVERIFY];

compile_node({sha256, Hash}, Verify) when byte_size(Hash) =:= 32 ->
    %% OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL[VERIFY]
    EqOp = case Verify of true -> ?OP_EQUALVERIFY; false -> ?OP_EQUAL end,
    [?OP_SIZE, push_num(32), ?OP_EQUALVERIFY, ?OP_SHA256, push_data(Hash), EqOp];

compile_node({hash256, Hash}, Verify) when byte_size(Hash) =:= 32 ->
    EqOp = case Verify of true -> ?OP_EQUALVERIFY; false -> ?OP_EQUAL end,
    [?OP_SIZE, push_num(32), ?OP_EQUALVERIFY, ?OP_HASH256, push_data(Hash), EqOp];

compile_node({ripemd160, Hash}, Verify) when byte_size(Hash) =:= 20 ->
    EqOp = case Verify of true -> ?OP_EQUALVERIFY; false -> ?OP_EQUAL end,
    [?OP_SIZE, push_num(32), ?OP_EQUALVERIFY, ?OP_RIPEMD160, push_data(Hash), EqOp];

compile_node({hash160, Hash}, Verify) when byte_size(Hash) =:= 20 ->
    EqOp = case Verify of true -> ?OP_EQUALVERIFY; false -> ?OP_EQUAL end,
    [?OP_SIZE, push_num(32), ?OP_EQUALVERIFY, ?OP_HASH160, push_data(Hash), EqOp];

compile_node(just_1, _Verify) ->
    [?OP_1];

compile_node(just_0, _Verify) ->
    [?OP_0];

compile_node({wrap_a, X}, _Verify) ->
    %% OP_TOALTSTACK [X] OP_FROMALTSTACK
    [?OP_TOALTSTACK, compile_node(X, false), ?OP_FROMALTSTACK];

compile_node({wrap_s, X}, Verify) ->
    %% OP_SWAP [X]
    [?OP_SWAP, compile_node(X, Verify)];

compile_node({wrap_c, X}, Verify) ->
    %% [X] OP_CHECKSIG[VERIFY]
    Op = case Verify of true -> ?OP_CHECKSIGVERIFY; false -> ?OP_CHECKSIG end,
    [compile_node(X, false), Op];

compile_node({wrap_d, X}, _Verify) ->
    %% OP_DUP OP_IF [X] OP_ENDIF
    [?OP_DUP, ?OP_IF, compile_node(X, false), ?OP_ENDIF];

compile_node({wrap_v, X}, _Verify) ->
    %% [X] OP_VERIFY, or merge with last opcode
    Tx = compute_type(X),
    case prop(Tx, x) of
        false ->
            %% Can merge: last opcode becomes *VERIFY variant
            compile_node(X, true);
        true ->
            %% Must add explicit OP_VERIFY
            [compile_node(X, false), ?OP_VERIFY]
    end;

compile_node({wrap_j, X}, _Verify) ->
    %% OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    [?OP_SIZE, ?OP_0NOTEQUAL, ?OP_IF, compile_node(X, false), ?OP_ENDIF];

compile_node({wrap_n, X}, _Verify) ->
    %% [X] OP_0NOTEQUAL
    [compile_node(X, false), ?OP_0NOTEQUAL];

compile_node({and_v, X, Y}, Verify) ->
    %% [X] [Y]
    [compile_node(X, false), compile_node(Y, Verify)];

compile_node({and_b, X, Y}, Verify) ->
    %% [X] [Y] OP_BOOLAND
    %% Note: BOOLAND doesn't have a VERIFY variant, so we add OP_VERIFY if needed
    case Verify of
        true -> [compile_node(X, false), compile_node(Y, false), ?OP_BOOLAND, ?OP_VERIFY];
        false -> [compile_node(X, false), compile_node(Y, false), ?OP_BOOLAND]
    end;

compile_node({or_b, X, Y}, Verify) ->
    %% [X] [Y] OP_BOOLOR
    case Verify of
        true -> [compile_node(X, false), compile_node(Y, false), ?OP_BOOLOR, ?OP_VERIFY];
        false -> [compile_node(X, false), compile_node(Y, false), ?OP_BOOLOR]
    end;

compile_node({or_c, X, Y}, _Verify) ->
    %% [X] OP_NOTIF [Y] OP_ENDIF
    [compile_node(X, false), ?OP_NOTIF, compile_node(Y, false), ?OP_ENDIF];

compile_node({or_d, X, Y}, Verify) ->
    %% [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    [compile_node(X, false), ?OP_IFDUP, ?OP_NOTIF, compile_node(Y, Verify), ?OP_ENDIF];

compile_node({or_i, X, Y}, Verify) ->
    %% OP_IF [X] OP_ELSE [Y] OP_ENDIF
    [?OP_IF, compile_node(X, Verify), ?OP_ELSE, compile_node(Y, Verify), ?OP_ENDIF];

compile_node({andor, X, Y, Z}, Verify) ->
    %% [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    [compile_node(X, false), ?OP_NOTIF, compile_node(Z, Verify),
     ?OP_ELSE, compile_node(Y, Verify), ?OP_ENDIF];

compile_node({thresh, K, Subs}, Verify) ->
    %% [X1] ([Xn] OP_ADD)* [k] OP_EQUAL[VERIFY]
    [First | Rest] = Subs,
    FirstCompiled = compile_node(First, false),
    RestCompiled = [[compile_node(S, false), ?OP_ADD] || S <- Rest],
    EqOp = case Verify of true -> ?OP_EQUALVERIFY; false -> ?OP_EQUAL end,
    [FirstCompiled, RestCompiled, push_num(K), EqOp];

compile_node({multi, K, Keys}, Verify) ->
    %% [k] [key1] ... [keyn] [n] OP_CHECKMULTISIG[VERIFY]
    N = length(Keys),
    Op = case Verify of true -> ?OP_CHECKMULTISIGVERIFY; false -> ?OP_CHECKMULTISIG end,
    [push_num(K), [push_data(Key) || Key <- Keys], push_num(N), Op];

compile_node({multi_a, K, Keys}, Verify) ->
    %% [key1] OP_CHECKSIG ([keyn] OP_CHECKSIGADD)* [k] OP_NUMEQUAL[VERIFY]
    [First | Rest] = Keys,
    FirstPart = [push_data(First), ?OP_CHECKSIG],
    RestPart = [[push_data(Key), ?OP_CHECKSIGADD] || Key <- Rest],
    EqOp = case Verify of true -> ?OP_NUMEQUALVERIFY; false -> ?OP_NUMEQUAL end,
    [FirstPart, RestPart, push_num(K), EqOp].

%% Push a number as script
push_num(0) -> [?OP_0];
push_num(N) when N >= 1, N =< 16 -> [?OP_1 + N - 1];
push_num(N) when N =:= -1 -> [?OP_1NEGATE];
push_num(N) ->
    %% Encode as CScriptNum (little-endian with sign bit)
    Bytes = encode_script_num(N),
    push_data(Bytes).

encode_script_num(0) -> <<>>;
encode_script_num(N) when N > 0 ->
    Bytes = encode_le_positive(N),
    Last = lists:last(Bytes),
    case Last band 16#80 of
        0 -> list_to_binary(Bytes);
        _ -> list_to_binary(Bytes ++ [16#00])
    end;
encode_script_num(N) when N < 0 ->
    Bytes = encode_le_positive(-N),
    Last = lists:last(Bytes),
    case Last band 16#80 of
        0 -> list_to_binary(lists:droplast(Bytes) ++ [Last bor 16#80]);
        _ -> list_to_binary(Bytes ++ [16#80])
    end.

encode_le_positive(0) -> [];
encode_le_positive(N) ->
    [N band 16#ff | encode_le_positive(N bsr 8)].

%% Push data with appropriate opcode
push_data(Data) when is_binary(Data) ->
    Len = byte_size(Data),
    if
        Len =< 75 -> [Len, Data];
        Len =< 255 -> [?OP_PUSHDATA1, Len, Data];
        Len =< 65535 -> [?OP_PUSHDATA2, <<Len:16/little>>, Data];
        true -> [?OP_PUSHDATA4, <<Len:32/little>>, Data]
    end.

%%% ===================================================================
%%% String Parsing
%%% ===================================================================

parse_expr(Str) ->
    Str1 = skip_whitespace(Str),
    case take_identifier(Str1) of
        {Name, "(" ++ Rest} ->
            parse_func(Name, Rest);
        {"0", Rest} ->
            {ok, just_0, Rest};
        {"1", Rest} ->
            {ok, just_1, Rest};
        {Name, ":" ++ Rest} ->
            %% Wrapper syntax: v:pk(...) or cv:pk(...)
            case parse_wrapper(Name) of
                {ok, Wrappers} ->
                    case parse_expr(Rest) of
                        {ok, Inner, Remaining} ->
                            Wrapped = apply_wrappers(Wrappers, Inner),
                            {ok, Wrapped, Remaining};
                        Err -> Err
                    end;
                error ->
                    {error, {invalid_wrapper, Name}}
            end;
        _ ->
            {error, {invalid_expression, Str1}}
    end.

parse_func("pk_k", Rest) -> parse_single_key("pk_k", Rest);
parse_func("pk_h", Rest) -> parse_single_hash("pk_h", 20, Rest);
parse_func("pk", Rest) ->
    %% pk(KEY) is shorthand for c:pk_k(KEY)
    case parse_single_key("pk_k", Rest) of
        {ok, {pk_k, Key}, Remaining} ->
            {ok, {wrap_c, {pk_k, Key}}, Remaining};
        Err -> Err
    end;
parse_func("pkh", Rest) ->
    %% pkh(KEYHASH) is shorthand for c:pk_h(HASH)
    case parse_single_hash("pk_h", 20, Rest) of
        {ok, {pk_h, Hash}, Remaining} ->
            {ok, {wrap_c, {pk_h, Hash}}, Remaining};
        Err -> Err
    end;
parse_func("older", Rest) -> parse_single_num("older", Rest, fun(N) -> {older, N} end);
parse_func("after", Rest) -> parse_single_num("after", Rest, fun(N) -> {after_, N} end);
parse_func("sha256", Rest) -> parse_single_hash("sha256", 32, Rest);
parse_func("hash256", Rest) -> parse_single_hash("hash256", 32, Rest);
parse_func("ripemd160", Rest) -> parse_single_hash("ripemd160", 20, Rest);
parse_func("hash160", Rest) -> parse_single_hash("hash160", 20, Rest);

parse_func("and_v", Rest) -> parse_two_args("and_v", Rest, fun(X, Y) -> {and_v, X, Y} end);
parse_func("and_b", Rest) -> parse_two_args("and_b", Rest, fun(X, Y) -> {and_b, X, Y} end);
parse_func("or_b", Rest) -> parse_two_args("or_b", Rest, fun(X, Y) -> {or_b, X, Y} end);
parse_func("or_c", Rest) -> parse_two_args("or_c", Rest, fun(X, Y) -> {or_c, X, Y} end);
parse_func("or_d", Rest) -> parse_two_args("or_d", Rest, fun(X, Y) -> {or_d, X, Y} end);
parse_func("or_i", Rest) -> parse_two_args("or_i", Rest, fun(X, Y) -> {or_i, X, Y} end);
parse_func("andor", Rest) -> parse_three_args("andor", Rest, fun(X, Y, Z) -> {andor, X, Y, Z} end);

parse_func("thresh", Rest) -> parse_thresh(Rest);
parse_func("multi", Rest) -> parse_multi(Rest, multi);
parse_func("multi_a", Rest) -> parse_multi(Rest, multi_a);

%% Wrappers with colon syntax: a:X, s:X, etc.
parse_func(Name, Rest) ->
    case parse_wrapper(Name) of
        {ok, Wrappers} ->
            case parse_expr(Rest) of
                {ok, Inner, ")" ++ Remaining} ->
                    Wrapped = apply_wrappers(Wrappers, Inner),
                    {ok, Wrapped, Remaining};
                {ok, _, _} ->
                    {error, missing_close_paren};
                Err -> Err
            end;
        error ->
            {error, {unknown_function, Name}}
    end.

%% Parse wrapper prefix like "vc" -> [wrap_v, wrap_c]
parse_wrapper(Name) ->
    parse_wrapper_chars(Name, []).

parse_wrapper_chars([], []) -> error;
parse_wrapper_chars([], Acc) -> {ok, lists:reverse(Acc)};
parse_wrapper_chars([$a | Rest], Acc) -> parse_wrapper_chars(Rest, [wrap_a | Acc]);
parse_wrapper_chars([$s | Rest], Acc) -> parse_wrapper_chars(Rest, [wrap_s | Acc]);
parse_wrapper_chars([$c | Rest], Acc) -> parse_wrapper_chars(Rest, [wrap_c | Acc]);
parse_wrapper_chars([$d | Rest], Acc) -> parse_wrapper_chars(Rest, [wrap_d | Acc]);
parse_wrapper_chars([$v | Rest], Acc) -> parse_wrapper_chars(Rest, [wrap_v | Acc]);
parse_wrapper_chars([$j | Rest], Acc) -> parse_wrapper_chars(Rest, [wrap_j | Acc]);
parse_wrapper_chars([$n | Rest], Acc) -> parse_wrapper_chars(Rest, [wrap_n | Acc]);
%% Also handle t: (alias for and_v(X, 1)) and l: (alias for or_i(0, X))
parse_wrapper_chars([$t | Rest], Acc) -> parse_wrapper_chars(Rest, [{alias_t} | Acc]);
parse_wrapper_chars([$u | Rest], Acc) -> parse_wrapper_chars(Rest, [{alias_u} | Acc]);
parse_wrapper_chars([$l | Rest], Acc) -> parse_wrapper_chars(Rest, [{alias_l} | Acc]);
parse_wrapper_chars(_, _) -> error.

apply_wrappers([], X) -> X;
apply_wrappers([{alias_t} | Rest], X) ->
    %% t:X = and_v(X, 1)
    apply_wrappers(Rest, {and_v, X, just_1});
apply_wrappers([{alias_u} | Rest], X) ->
    %% u:X = or_i(X, 0)
    apply_wrappers(Rest, {or_i, X, just_0});
apply_wrappers([{alias_l} | Rest], X) ->
    %% l:X = or_i(0, X)
    apply_wrappers(Rest, {or_i, just_0, X});
apply_wrappers([W | Rest], X) ->
    apply_wrappers(Rest, {W, X}).

parse_single_key(Name, Str) ->
    case take_hex(Str) of
        {HexStr, ")" ++ Remaining} when length(HexStr) =:= 66 ->
            case hex_to_binary(HexStr) of
                {ok, Key} when byte_size(Key) =:= 33 ->
                    case Name of
                        "pk_k" -> {ok, {pk_k, Key}, Remaining};
                        _ -> {error, {invalid_key_function, Name}}
                    end;
                _ -> {error, invalid_pubkey}
            end;
        _ ->
            {error, {invalid_args, Name}}
    end.

parse_single_hash(Name, ExpectedLen, Str) ->
    case take_hex(Str) of
        {HexStr, ")" ++ Remaining} ->
            case hex_to_binary(HexStr) of
                {ok, Hash} when byte_size(Hash) =:= ExpectedLen ->
                    case Name of
                        "pk_h" -> {ok, {pk_h, Hash}, Remaining};
                        "sha256" -> {ok, {sha256, Hash}, Remaining};
                        "hash256" -> {ok, {hash256, Hash}, Remaining};
                        "ripemd160" -> {ok, {ripemd160, Hash}, Remaining};
                        "hash160" -> {ok, {hash160, Hash}, Remaining};
                        _ -> {error, {invalid_hash_function, Name}}
                    end;
                _ -> {error, {invalid_hash_length, Name, ExpectedLen}}
            end;
        _ ->
            {error, {invalid_args, Name}}
    end.

parse_single_num(Name, Str, Constructor) ->
    case take_number(Str) of
        {N, ")" ++ Remaining} when N >= 1 ->
            {ok, Constructor(N), Remaining};
        _ ->
            {error, {invalid_args, Name}}
    end.

parse_two_args(_Name, Str, Constructor) ->
    case parse_expr(Str) of
        {ok, X, "," ++ Rest1} ->
            case parse_expr(skip_whitespace(Rest1)) of
                {ok, Y, ")" ++ Remaining} ->
                    {ok, Constructor(X, Y), Remaining};
                {ok, _, _} -> {error, missing_close_paren};
                Err -> Err
            end;
        {ok, _, _} -> {error, missing_comma};
        Err -> Err
    end.

parse_three_args(_Name, Str, Constructor) ->
    case parse_expr(Str) of
        {ok, X, "," ++ Rest1} ->
            case parse_expr(skip_whitespace(Rest1)) of
                {ok, Y, "," ++ Rest2} ->
                    case parse_expr(skip_whitespace(Rest2)) of
                        {ok, Z, ")" ++ Remaining} ->
                            {ok, Constructor(X, Y, Z), Remaining};
                        {ok, _, _} -> {error, missing_close_paren};
                        Err -> Err
                    end;
                {ok, _, _} -> {error, missing_comma};
                Err -> Err
            end;
        {ok, _, _} -> {error, missing_comma};
        Err -> Err
    end.

parse_thresh(Str) ->
    case take_number(Str) of
        {K, "," ++ Rest} when K >= 1 ->
            parse_thresh_subs(skip_whitespace(Rest), K, []);
        _ ->
            {error, thresh_invalid_k}
    end.

parse_thresh_subs(Str, K, Acc) ->
    case parse_expr(Str) of
        {ok, Sub, "," ++ Rest} ->
            parse_thresh_subs(skip_whitespace(Rest), K, [Sub | Acc]);
        {ok, Sub, ")" ++ Remaining} ->
            Subs = lists:reverse([Sub | Acc]),
            case length(Subs) >= K of
                true -> {ok, {thresh, K, Subs}, Remaining};
                false -> {error, {thresh_k_exceeds_n, K, length(Subs)}}
            end;
        {ok, _, _} ->
            {error, thresh_missing_close};
        Err -> Err
    end.

parse_multi(Str, Type) ->
    case take_number(Str) of
        {K, "," ++ Rest} when K >= 1 ->
            parse_multi_keys(skip_whitespace(Rest), K, Type, []);
        _ ->
            {error, multi_invalid_k}
    end.

parse_multi_keys(Str, K, Type, Acc) ->
    case take_hex(Str) of
        {HexStr, "," ++ Rest} when length(HexStr) =:= 66 ->
            case hex_to_binary(HexStr) of
                {ok, Key} ->
                    parse_multi_keys(skip_whitespace(Rest), K, Type, [Key | Acc]);
                error ->
                    {error, multi_invalid_key}
            end;
        {HexStr, ")" ++ Remaining} when length(HexStr) =:= 66 ->
            case hex_to_binary(HexStr) of
                {ok, Key} ->
                    Keys = lists:reverse([Key | Acc]),
                    case length(Keys) >= K of
                        true -> {ok, {Type, K, Keys}, Remaining};
                        false -> {error, {multi_k_exceeds_n, K, length(Keys)}}
                    end;
                error ->
                    {error, multi_invalid_key}
            end;
        _ ->
            {error, multi_missing_key}
    end.

%% Lexer helpers
skip_whitespace([$ | Rest]) -> skip_whitespace(Rest);
skip_whitespace([$\t | Rest]) -> skip_whitespace(Rest);
skip_whitespace([$\n | Rest]) -> skip_whitespace(Rest);
skip_whitespace(Str) -> Str.

take_identifier(Str) ->
    take_identifier(Str, []).

take_identifier([], Acc) -> {lists:reverse(Acc), []};
take_identifier([C | _] = Rest, Acc) when C =:= $(; C =:= $); C =:= $,; C =:= $ ; C =:= $\t ->
    {lists:reverse(Acc), Rest};
take_identifier([C | Rest], Acc) when (C >= $a andalso C =< $z);
                                       (C >= $A andalso C =< $Z);
                                       (C >= $0 andalso C =< $9);
                                       C =:= $_ ->
    take_identifier(Rest, [C | Acc]);
take_identifier(Rest, Acc) ->
    {lists:reverse(Acc), Rest}.

take_number(Str) ->
    take_number(Str, 0, false).

take_number([], Acc, true) -> {Acc, []};
take_number([], _, false) -> error;
take_number([C | Rest], Acc, _) when C >= $0, C =< $9 ->
    take_number(Rest, Acc * 10 + (C - $0), true);
take_number(Rest, Acc, true) -> {Acc, Rest};
take_number(_, _, false) -> error.

take_hex(Str) ->
    take_hex(Str, []).

take_hex([], Acc) -> {lists:reverse(Acc), []};
take_hex([C | Rest], Acc) when (C >= $0 andalso C =< $9);
                                (C >= $a andalso C =< $f);
                                (C >= $A andalso C =< $F) ->
    take_hex(Rest, [C | Acc]);
take_hex(Rest, Acc) -> {lists:reverse(Acc), Rest}.

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

%%% ===================================================================
%%% Satisfaction Logic
%%% ===================================================================

%% produce_satisfaction(AST, Env) -> {ok, SatStack, DissatStack} | unavailable
%% SatStack/DissatStack are lists of binaries, or 'unavailable'

produce_satisfaction({pk_k, Key}, Env) ->
    Sig = get_sig(Key, Env),
    Dissat = [<<>>],  %% Empty sig for dissatisfaction
    case Sig of
        unavailable -> {ok, unavailable, Dissat};
        SigBin -> {ok, [SigBin], Dissat}
    end;

produce_satisfaction({pk_h, Hash}, Env) ->
    %% Need both sig and key
    case get_key_for_hash(Hash, Env) of
        unavailable ->
            {ok, unavailable, [<<>>, <<>>]};  %% Needs key even for dissat
        Key ->
            Sig = get_sig(Key, Env),
            case Sig of
                unavailable -> {ok, unavailable, [<<>>, Key]};
                SigBin -> {ok, [SigBin, Key], [<<>>, Key]}
            end
    end;

produce_satisfaction({older, N}, Env) ->
    %% Timelocks can't be dissatisfied
    Seq = maps:get(sequence, Env, 0),
    case check_sequence(N, Seq) of
        true -> {ok, [], unavailable};
        false -> {ok, unavailable, unavailable}
    end;

produce_satisfaction({after_, N}, Env) ->
    Locktime = maps:get(locktime, Env, 0),
    case check_locktime(N, Locktime) of
        true -> {ok, [], unavailable};
        false -> {ok, unavailable, unavailable}
    end;

produce_satisfaction({sha256, Hash}, Env) ->
    Preimage = get_preimage(sha256, Hash, Env),
    Dissat = [<<0:256>>],  %% 32-byte zero (malleable)
    case Preimage of
        unavailable -> {ok, unavailable, Dissat};
        Pre -> {ok, [Pre], Dissat}
    end;

produce_satisfaction({hash256, Hash}, Env) ->
    Preimage = get_preimage(hash256, Hash, Env),
    Dissat = [<<0:256>>],
    case Preimage of
        unavailable -> {ok, unavailable, Dissat};
        Pre -> {ok, [Pre], Dissat}
    end;

produce_satisfaction({ripemd160, Hash}, Env) ->
    Preimage = get_preimage(ripemd160, Hash, Env),
    Dissat = [<<0:256>>],  %% 32-byte zero (for size check)
    case Preimage of
        unavailable -> {ok, unavailable, Dissat};
        Pre -> {ok, [Pre], Dissat}
    end;

produce_satisfaction({hash160, Hash}, Env) ->
    Preimage = get_preimage(hash160, Hash, Env),
    Dissat = [<<0:256>>],
    case Preimage of
        unavailable -> {ok, unavailable, Dissat};
        Pre -> {ok, [Pre], Dissat}
    end;

produce_satisfaction(just_1, _Env) ->
    {ok, [], unavailable};

produce_satisfaction(just_0, _Env) ->
    {ok, unavailable, []};

produce_satisfaction({wrap_a, X}, Env) ->
    produce_satisfaction(X, Env);

produce_satisfaction({wrap_s, X}, Env) ->
    produce_satisfaction(X, Env);

produce_satisfaction({wrap_c, X}, Env) ->
    produce_satisfaction(X, Env);

produce_satisfaction({wrap_d, X}, Env) ->
    case produce_satisfaction(X, Env) of
        {ok, Sat, _Dissat} ->
            SatStack = case Sat of
                unavailable -> unavailable;
                _ -> Sat ++ [<<1>>]
            end,
            {ok, SatStack, [<<>>]};
        Err -> Err
    end;

produce_satisfaction({wrap_v, X}, Env) ->
    case produce_satisfaction(X, Env) of
        {ok, Sat, _Dissat} ->
            {ok, Sat, unavailable};  %% V type can't be dissatisfied
        Err -> Err
    end;

produce_satisfaction({wrap_j, X}, Env) ->
    case produce_satisfaction(X, Env) of
        {ok, Sat, _Dissat} ->
            {ok, Sat, [<<>>]};  %% Dissatisfy with empty
        Err -> Err
    end;

produce_satisfaction({wrap_n, X}, Env) ->
    produce_satisfaction(X, Env);

produce_satisfaction({and_v, X, Y}, Env) ->
    case produce_satisfaction(X, Env) of
        {ok, SatX, _} when SatX =/= unavailable ->
            case produce_satisfaction(Y, Env) of
                {ok, SatY, _} when SatY =/= unavailable ->
                    {ok, SatY ++ SatX, unavailable};
                {ok, _, _} ->
                    {ok, unavailable, unavailable};
                Err -> Err
            end;
        {ok, _, _} ->
            {ok, unavailable, unavailable};
        Err -> Err
    end;

produce_satisfaction({and_b, X, Y}, Env) ->
    case {produce_satisfaction(X, Env), produce_satisfaction(Y, Env)} of
        {{ok, SatX, DissatX}, {ok, SatY, DissatY}} ->
            Sat = case SatX =/= unavailable andalso SatY =/= unavailable of
                true -> SatY ++ SatX;
                false -> unavailable
            end,
            Dissat = case DissatX =/= unavailable andalso DissatY =/= unavailable of
                true -> DissatY ++ DissatX;
                false -> unavailable
            end,
            {ok, Sat, Dissat};
        _ ->
            {ok, unavailable, unavailable}
    end;

produce_satisfaction({or_b, X, Y}, Env) ->
    case {produce_satisfaction(X, Env), produce_satisfaction(Y, Env)} of
        {{ok, SatX, DissatX}, {ok, SatY, DissatY}} ->
            %% Can satisfy with X (and dissat Y) or Y (and dissat X) or both
            Option1 = case SatX =/= unavailable andalso DissatY =/= unavailable of
                true -> DissatY ++ SatX;
                false -> unavailable
            end,
            Option2 = case DissatX =/= unavailable andalso SatY =/= unavailable of
                true -> SatY ++ DissatX;
                false -> unavailable
            end,
            Sat = choose_smaller(Option1, Option2),
            Dissat = case DissatX =/= unavailable andalso DissatY =/= unavailable of
                true -> DissatY ++ DissatX;
                false -> unavailable
            end,
            {ok, Sat, Dissat};
        _ ->
            {ok, unavailable, unavailable}
    end;

produce_satisfaction({or_c, X, Y}, Env) ->
    case {produce_satisfaction(X, Env), produce_satisfaction(Y, Env)} of
        {{ok, SatX, DissatX}, {ok, SatY, _}} ->
            Option1 = SatX,
            Option2 = case DissatX =/= unavailable andalso SatY =/= unavailable of
                true -> SatY ++ DissatX;
                false -> unavailable
            end,
            Sat = choose_smaller(Option1, Option2),
            {ok, Sat, unavailable};  %% V result can't be dissatisfied
        _ ->
            {ok, unavailable, unavailable}
    end;

produce_satisfaction({or_d, X, Y}, Env) ->
    case {produce_satisfaction(X, Env), produce_satisfaction(Y, Env)} of
        {{ok, SatX, DissatX}, {ok, SatY, DissatY}} ->
            Option1 = SatX,
            Option2 = case DissatX =/= unavailable andalso SatY =/= unavailable of
                true -> SatY ++ DissatX;
                false -> unavailable
            end,
            Sat = choose_smaller(Option1, Option2),
            Dissat = case DissatX =/= unavailable andalso DissatY =/= unavailable of
                true -> DissatY ++ DissatX;
                false -> unavailable
            end,
            {ok, Sat, Dissat};
        _ ->
            {ok, unavailable, unavailable}
    end;

produce_satisfaction({or_i, X, Y}, Env) ->
    case {produce_satisfaction(X, Env), produce_satisfaction(Y, Env)} of
        {{ok, SatX, DissatX}, {ok, SatY, DissatY}} ->
            Option1 = case SatX =/= unavailable of
                true -> SatX ++ [<<1>>];  %% Push 1 for IF
                false -> unavailable
            end,
            Option2 = case SatY =/= unavailable of
                true -> SatY ++ [<<>>];  %% Push 0 for ELSE
                false -> unavailable
            end,
            Sat = choose_smaller(Option1, Option2),
            DissatOpt1 = case DissatX =/= unavailable of
                true -> DissatX ++ [<<1>>];
                false -> unavailable
            end,
            DissatOpt2 = case DissatY =/= unavailable of
                true -> DissatY ++ [<<>>];
                false -> unavailable
            end,
            Dissat = choose_smaller(DissatOpt1, DissatOpt2),
            {ok, Sat, Dissat};
        _ ->
            {ok, unavailable, unavailable}
    end;

produce_satisfaction({andor, X, Y, Z}, Env) ->
    case {produce_satisfaction(X, Env), produce_satisfaction(Y, Env), produce_satisfaction(Z, Env)} of
        {{ok, SatX, DissatX}, {ok, SatY, _DissatY}, {ok, SatZ, DissatZ}} ->
            %% Satisfy via X+Y or via !X+Z
            Option1 = case SatX =/= unavailable andalso SatY =/= unavailable of
                true -> SatY ++ SatX;
                false -> unavailable
            end,
            Option2 = case DissatX =/= unavailable andalso SatZ =/= unavailable of
                true -> SatZ ++ DissatX;
                false -> unavailable
            end,
            Sat = choose_smaller(Option1, Option2),
            Dissat = case DissatX =/= unavailable andalso DissatZ =/= unavailable of
                true -> DissatZ ++ DissatX;
                false -> unavailable
            end,
            {ok, Sat, Dissat};
        _ ->
            {ok, unavailable, unavailable}
    end;

produce_satisfaction({thresh, K, Subs}, Env) ->
    %% DP approach: compute all possible combinations
    Results = [produce_satisfaction(S, Env) || S <- Subs],
    SatsDissats = [{Sat, Dissat} || {ok, Sat, Dissat} <- Results],
    case length(SatsDissats) =:= length(Subs) of
        true ->
            thresh_dp(SatsDissats, K);
        false ->
            {ok, unavailable, unavailable}
    end;

produce_satisfaction({multi, K, Keys}, Env) ->
    %% Need K signatures in order
    Sigs = [get_sig(Key, Env) || Key <- Keys],
    AvailableSigs = [S || S <- Sigs, S =/= unavailable],
    N = length(Keys),
    case length(AvailableSigs) >= K of
        true ->
            %% Take first K available signatures (matching order)
            {SelectedSigs, _} = select_multi_sigs(Sigs, K),
            Sat = [<<>>] ++ SelectedSigs,  %% Dummy + sigs
            Dissat = [<<>> || _ <- lists:seq(1, K + 1)],  %% K+1 empty elements
            {ok, Sat, Dissat};
        false ->
            Dissat = [<<>> || _ <- lists:seq(1, N + 1)],
            {ok, unavailable, Dissat}
    end;

produce_satisfaction({multi_a, K, Keys}, Env) ->
    %% CHECKSIGADD style: need exactly N signatures (some empty)
    Sigs = [get_sig(Key, Env) || Key <- Keys],
    AvailableCount = length([S || S <- Sigs, S =/= unavailable]),
    case AvailableCount >= K of
        true ->
            %% Replace unavailable sigs with empty
            SigStack = [case S of unavailable -> <<>>; _ -> S end || S <- Sigs],
            Dissat = [<<>> || _ <- Keys],
            {ok, lists:reverse(SigStack), Dissat};  %% Reverse for stack order
        false ->
            Dissat = [<<>> || _ <- Keys],
            {ok, unavailable, Dissat}
    end.

%% Helper to choose smaller witness
choose_smaller(unavailable, X) -> X;
choose_smaller(X, unavailable) -> X;
choose_smaller(X, Y) ->
    SizeX = witness_stack_size(X),
    SizeY = witness_stack_size(Y),
    case SizeX =< SizeY of
        true -> X;
        false -> Y
    end.

witness_stack_size(Stack) ->
    lists:sum([byte_size(E) + 1 || E <- Stack]).

%% Thresh DP: find best combination of K satisfactions
thresh_dp(SatsDissats, K) ->
    N = length(SatsDissats),
    %% DP[i][j] = best witness to have j satisfactions among first i subs
    %% Start with DP[0][0] = []
    Initial = #{0 => []},
    Final = lists:foldl(fun({Sat, Dissat}, {Idx, DP}) ->
        NewDP = maps:fold(fun(J, Witness, Acc) ->
            %% Option 1: dissatisfy this sub (stay at J)
            Acc1 = case Dissat =/= unavailable of
                true ->
                    NewWit = Dissat ++ Witness,
                    update_dp(Acc, J, NewWit);
                false ->
                    Acc
            end,
            %% Option 2: satisfy this sub (go to J+1)
            case Sat =/= unavailable andalso J < K of
                true ->
                    NewWit2 = Sat ++ Witness,
                    update_dp(Acc1, J + 1, NewWit2);
                false ->
                    Acc1
            end
        end, #{}, DP),
        {Idx + 1, NewDP}
    end, {0, Initial}, SatsDissats),

    {_, FinalDP} = Final,
    Sat = maps:get(K, FinalDP, unavailable),
    Dissat = case maps:get(0, FinalDP, unavailable) of
        unavailable -> unavailable;
        _ when K =:= N -> unavailable;  %% If K = N, can't dissatisfy
        D -> D
    end,
    {ok, Sat, Dissat}.

update_dp(DP, J, Witness) ->
    case maps:get(J, DP, unavailable) of
        unavailable -> maps:put(J, Witness, DP);
        Existing ->
            case witness_stack_size(Witness) < witness_stack_size(Existing) of
                true -> maps:put(J, Witness, DP);
                false -> DP
            end
    end.

select_multi_sigs(Sigs, K) ->
    select_multi_sigs(Sigs, K, []).

select_multi_sigs(_, 0, Acc) ->
    {lists:reverse(Acc), []};
select_multi_sigs([], _, Acc) ->
    {lists:reverse(Acc), []};
select_multi_sigs([unavailable | Rest], K, Acc) ->
    select_multi_sigs(Rest, K, Acc);
select_multi_sigs([Sig | Rest], K, Acc) ->
    select_multi_sigs(Rest, K - 1, [Sig | Acc]).

%% Environment helpers
get_sig(Key, Env) ->
    Sigs = maps:get(sigs, Env, #{}),
    maps:get(Key, Sigs, unavailable).

get_key_for_hash(Hash, Env) ->
    Keys = maps:get(keys, Env, #{}),
    maps:get(Hash, Keys, unavailable).

get_preimage(Type, Hash, Env) ->
    Preimages = maps:get(preimages, Env, #{}),
    maps:get({Type, Hash}, Preimages, unavailable).

check_sequence(Required, Available) ->
    %% Simplified check
    Available >= Required.

check_locktime(Required, Available) ->
    Available >= Required.

%%% ===================================================================
%%% Witness Size Calculation
%%% ===================================================================

%% Returns {MaxSatSize, MaxDissatSize}
witness_size({pk_k, _}) ->
    %% Sat: 72-byte sig, Dissat: 0-byte empty
    {73, 1};

witness_size({pk_h, _}) ->
    %% Sat: sig + key, Dissat: empty + key
    {73 + 34, 1 + 34};

witness_size({older, _}) ->
    %% Sat: nothing, Dissat: impossible
    {0, infinity};

witness_size({after_, _}) ->
    {0, infinity};

witness_size({sha256, _}) ->
    %% Sat: 32-byte preimage, Dissat: 32-byte zero
    {33, 33};

witness_size({hash256, _}) ->
    {33, 33};

witness_size({ripemd160, _}) ->
    %% Preimage for ripemd160 is checked to be 32 bytes (for size check)
    {33, 33};

witness_size({hash160, _}) ->
    {33, 33};

witness_size(just_1) ->
    {0, infinity};

witness_size(just_0) ->
    {infinity, 0};

witness_size({wrap_a, X}) -> witness_size(X);
witness_size({wrap_s, X}) -> witness_size(X);
witness_size({wrap_c, X}) -> witness_size(X);

witness_size({wrap_d, X}) ->
    {SatX, _} = witness_size(X),
    %% Sat: X_sat + 1, Dissat: 0
    {SatX + 1, 1};

witness_size({wrap_v, X}) ->
    {SatX, _} = witness_size(X),
    {SatX, infinity};

witness_size({wrap_j, X}) ->
    {SatX, _} = witness_size(X),
    {SatX, 1};

witness_size({wrap_n, X}) -> witness_size(X);

witness_size({and_v, X, Y}) ->
    {SatX, _} = witness_size(X),
    {SatY, _} = witness_size(Y),
    {SatX + SatY, infinity};

witness_size({and_b, X, Y}) ->
    {SatX, DissatX} = witness_size(X),
    {SatY, DissatY} = witness_size(Y),
    {SatX + SatY, min_size(DissatX + DissatY, min_size(SatX + DissatY, DissatX + SatY))};

witness_size({or_b, X, Y}) ->
    {SatX, DissatX} = witness_size(X),
    {SatY, DissatY} = witness_size(Y),
    {min_size(SatX + DissatY, DissatX + SatY), DissatX + DissatY};

witness_size({or_c, X, Y}) ->
    {SatX, DissatX} = witness_size(X),
    {SatY, _} = witness_size(Y),
    {min_size(SatX, DissatX + SatY), infinity};

witness_size({or_d, X, Y}) ->
    {SatX, DissatX} = witness_size(X),
    {SatY, DissatY} = witness_size(Y),
    {min_size(SatX, DissatX + SatY), DissatX + DissatY};

witness_size({or_i, X, Y}) ->
    {SatX, DissatX} = witness_size(X),
    {SatY, DissatY} = witness_size(Y),
    {min_size(SatX + 1, SatY + 1), min_size(DissatX + 1, DissatY + 1)};

witness_size({andor, X, Y, Z}) ->
    {SatX, DissatX} = witness_size(X),
    {SatY, _} = witness_size(Y),
    {SatZ, DissatZ} = witness_size(Z),
    {min_size(SatX + SatY, DissatX + SatZ), DissatX + DissatZ};

witness_size({thresh, K, Subs}) ->
    %% Complex: need DP to find optimal
    Sizes = [witness_size(S) || S <- Subs],
    N = length(Subs),

    %% Sat: K satisfactions + (N-K) dissatisfactions (pick smallest)
    SatSizes = [S || {S, _} <- Sizes],
    DissatSizes = [D || {_, D} <- Sizes],
    SortedSat = lists:sort(SatSizes),
    SortedDissat = lists:sort(DissatSizes),

    %% Take K smallest sats + (N-K) smallest dissats
    SatCost = lists:sum(lists:sublist(SortedSat, K)) +
              lists:sum(lists:sublist(SortedDissat, N - K)),

    %% Dissat: all dissatisfactions (only possible if K < N)
    DissatCost = case K < N of
        true -> lists:sum(DissatSizes);
        false -> infinity
    end,

    {SatCost, DissatCost};

witness_size({multi, K, _Keys}) ->
    %% Sat: dummy + K sigs, Dissat: dummy + K empty elements
    {1 + K * 73, 1 + K};

witness_size({multi_a, K, Keys}) ->
    N = length(Keys),
    %% Sat: N elements (K sigs + (N-K) empty), Dissat: N empty
    {K * 73 + (N - K), N}.

min_size(infinity, X) -> X;
min_size(X, infinity) -> X;
min_size(X, Y) -> min(X, Y).

%%% ===================================================================
%%% AST to String
%%% ===================================================================

ast_to_string({pk_k, Key}) ->
    "pk_k(" ++ binary_to_hex(Key) ++ ")";
ast_to_string({pk_h, Hash}) ->
    "pk_h(" ++ binary_to_hex(Hash) ++ ")";
ast_to_string({older, N}) ->
    "older(" ++ integer_to_list(N) ++ ")";
ast_to_string({after_, N}) ->
    "after(" ++ integer_to_list(N) ++ ")";
ast_to_string({sha256, Hash}) ->
    "sha256(" ++ binary_to_hex(Hash) ++ ")";
ast_to_string({hash256, Hash}) ->
    "hash256(" ++ binary_to_hex(Hash) ++ ")";
ast_to_string({ripemd160, Hash}) ->
    "ripemd160(" ++ binary_to_hex(Hash) ++ ")";
ast_to_string({hash160, Hash}) ->
    "hash160(" ++ binary_to_hex(Hash) ++ ")";
ast_to_string(just_1) ->
    "1";
ast_to_string(just_0) ->
    "0";
ast_to_string({wrap_a, X}) ->
    "a:" ++ ast_to_string(X);
ast_to_string({wrap_s, X}) ->
    "s:" ++ ast_to_string(X);
ast_to_string({wrap_c, X}) ->
    "c:" ++ ast_to_string(X);
ast_to_string({wrap_d, X}) ->
    "d:" ++ ast_to_string(X);
ast_to_string({wrap_v, X}) ->
    "v:" ++ ast_to_string(X);
ast_to_string({wrap_j, X}) ->
    "j:" ++ ast_to_string(X);
ast_to_string({wrap_n, X}) ->
    "n:" ++ ast_to_string(X);
ast_to_string({and_v, X, Y}) ->
    "and_v(" ++ ast_to_string(X) ++ "," ++ ast_to_string(Y) ++ ")";
ast_to_string({and_b, X, Y}) ->
    "and_b(" ++ ast_to_string(X) ++ "," ++ ast_to_string(Y) ++ ")";
ast_to_string({or_b, X, Y}) ->
    "or_b(" ++ ast_to_string(X) ++ "," ++ ast_to_string(Y) ++ ")";
ast_to_string({or_c, X, Y}) ->
    "or_c(" ++ ast_to_string(X) ++ "," ++ ast_to_string(Y) ++ ")";
ast_to_string({or_d, X, Y}) ->
    "or_d(" ++ ast_to_string(X) ++ "," ++ ast_to_string(Y) ++ ")";
ast_to_string({or_i, X, Y}) ->
    "or_i(" ++ ast_to_string(X) ++ "," ++ ast_to_string(Y) ++ ")";
ast_to_string({andor, X, Y, Z}) ->
    "andor(" ++ ast_to_string(X) ++ "," ++ ast_to_string(Y) ++ "," ++ ast_to_string(Z) ++ ")";
ast_to_string({thresh, K, Subs}) ->
    SubStrs = [ast_to_string(S) || S <- Subs],
    "thresh(" ++ integer_to_list(K) ++ "," ++ string:join(SubStrs, ",") ++ ")";
ast_to_string({multi, K, Keys}) ->
    KeyStrs = [binary_to_hex(Key) || Key <- Keys],
    "multi(" ++ integer_to_list(K) ++ "," ++ string:join(KeyStrs, ",") ++ ")";
ast_to_string({multi_a, K, Keys}) ->
    KeyStrs = [binary_to_hex(Key) || Key <- Keys],
    "multi_a(" ++ integer_to_list(K) ++ "," ++ string:join(KeyStrs, ",") ++ ")".

binary_to_hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).
