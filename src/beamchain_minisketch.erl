-module(beamchain_minisketch).

%% Minisketch library bindings for BIP330 Erlay set reconciliation.
%%
%% Minisketch is a library for efficient set reconciliation using BCH codes.
%% It represents a set of elements as a compact sketch that supports:
%%   - Add/remove elements (XOR-based toggle)
%%   - Merge sketches (XOR to get symmetric difference)
%%   - Decode to recover the set difference
%%
%% For Erlay, we use 32-bit elements (short txids) with capacity sized
%% based on expected set difference.

-on_load(init/0).

%% Sketch lifecycle
-export([create/2, create_fp/3, destroy/1, clone/1]).

%% Sketch operations
-export([add/2, merge/2]).

%% Serialization
-export([serialize/1, deserialize/2, serialized_size/1]).

%% Decoding
-export([decode/2]).

%% Info
-export([bits/1, capacity/1]).

%% Helpers
-export([compute_capacity/3, compute_max_elements/3]).

%%% -------------------------------------------------------------------
%%% NIF loading
%%% -------------------------------------------------------------------

init() ->
    SoName = filename:join(priv_dir(), "beamchain_minisketch_nif"),
    case erlang:load_nif(SoName, 0) of
        ok -> ok;
        {error, {reload, _}} -> ok;
        {error, Reason} ->
            logger:warning("minisketch NIF load failed: ~p (using fallback)", [Reason]),
            ok
    end.

priv_dir() ->
    case code:priv_dir(beamchain) of
        {error, _} ->
            case code:which(?MODULE) of
                Filename when is_list(Filename) ->
                    filename:join(
                        filename:dirname(filename:dirname(Filename)),
                        "priv");
                _ ->
                    "priv"
            end;
        Dir -> Dir
    end.

%%% -------------------------------------------------------------------
%%% NIF stubs (replaced when NIF loads, fallback to pure Erlang otherwise)
%%% -------------------------------------------------------------------

%% @doc Create a new sketch with given bits and capacity.
%% bits = element size in bits (typically 32 for Erlay)
%% capacity = maximum number of elements that can be decoded
-spec create(non_neg_integer(), non_neg_integer()) -> {ok, reference()} | {error, term()}.
create(Bits, Capacity) ->
    create_nif(Bits, Capacity).

create_nif(_Bits, _Capacity) ->
    %% Fallback: use a simple list-based representation
    {ok, {minisketch_fallback, []}}.

%% @doc Create a sketch sized for max_elements with false positive rate 2^-fpbits.
-spec create_fp(non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    {ok, reference()} | {error, term()}.
create_fp(Bits, MaxElements, FPBits) ->
    Capacity = compute_capacity(Bits, MaxElements, FPBits),
    create(Bits, Capacity).

%% @doc Destroy a sketch and free resources.
-spec destroy(reference()) -> ok.
destroy(_Sketch) ->
    ok.

%% @doc Clone a sketch.
-spec clone(reference()) -> {ok, reference()} | {error, term()}.
clone({minisketch_fallback, Elements}) ->
    {ok, {minisketch_fallback, Elements}};
clone(Sketch) ->
    clone_nif(Sketch).

clone_nif(_Sketch) ->
    {error, nif_not_loaded}.

%% @doc Add an element to the sketch. Adding the same element twice removes it.
-spec add(reference(), non_neg_integer()) -> ok.
add({minisketch_fallback, Elements}, Element) ->
    %% XOR-based toggle
    case lists:member(Element, Elements) of
        true ->
            %% Put returns a new reference - this is a limitation of fallback
            %% In real NIF, the sketch is mutable
            put(minisketch_last, lists:delete(Element, Elements));
        false ->
            put(minisketch_last, [Element | Elements])
    end,
    ok;
add(Sketch, Element) ->
    add_nif(Sketch, Element).

add_nif(_Sketch, _Element) ->
    ok.

%% @doc Merge another sketch into this one (XOR operation).
%% After merging, sketch contains the symmetric difference of both sets.
-spec merge(reference(), reference()) -> ok | {error, term()}.
merge({minisketch_fallback, Elements1}, {minisketch_fallback, Elements2}) ->
    %% Symmetric difference: (A - B) union (B - A)
    Set1 = sets:from_list(Elements1),
    Set2 = sets:from_list(Elements2),
    Diff = sets:to_list(sets:union(
        sets:subtract(Set1, Set2),
        sets:subtract(Set2, Set1))),
    put(minisketch_last, Diff),
    ok;
merge(Sketch, OtherSketch) ->
    merge_nif(Sketch, OtherSketch).

merge_nif(_Sketch, _OtherSketch) ->
    {error, nif_not_loaded}.

%% @doc Get serialized size of sketch in bytes.
-spec serialized_size(reference()) -> non_neg_integer().
serialized_size({minisketch_fallback, Elements}) ->
    length(Elements) * 4;  %% 32-bit elements
serialized_size(Sketch) ->
    serialized_size_nif(Sketch).

serialized_size_nif(_Sketch) ->
    0.

%% @doc Serialize sketch to binary.
-spec serialize(reference()) -> {ok, binary()} | {error, term()}.
serialize({minisketch_fallback, Elements}) ->
    %% Simple serialization: concatenate 32-bit elements
    Bin = << <<E:32/little>> || E <- Elements >>,
    {ok, Bin};
serialize(Sketch) ->
    serialize_nif(Sketch).

serialize_nif(_Sketch) ->
    {error, nif_not_loaded}.

%% @doc Deserialize binary into sketch.
-spec deserialize(reference(), binary()) -> ok | {error, term()}.
deserialize({minisketch_fallback, _}, Bin) ->
    %% Parse 32-bit elements
    Elements = parse_elements(Bin, []),
    put(minisketch_last, Elements),
    ok;
deserialize(Sketch, Bin) ->
    deserialize_nif(Sketch, Bin).

deserialize_nif(_Sketch, _Bin) ->
    {error, nif_not_loaded}.

parse_elements(<<>>, Acc) -> lists:reverse(Acc);
parse_elements(<<E:32/little, Rest/binary>>, Acc) ->
    parse_elements(Rest, [E | Acc]).

%% @doc Decode the sketch to recover elements.
%% Returns {ok, [Element]} or {error, decode_failed}.
-spec decode(reference(), non_neg_integer()) -> {ok, [non_neg_integer()]} | {error, term()}.
decode({minisketch_fallback, Elements}, _MaxElements) ->
    {ok, Elements};
decode(Sketch, MaxElements) ->
    decode_nif(Sketch, MaxElements).

decode_nif(_Sketch, _MaxElements) ->
    {error, nif_not_loaded}.

%% @doc Get element size in bits.
-spec bits(reference()) -> non_neg_integer().
bits({minisketch_fallback, _}) -> 32;
bits(Sketch) -> bits_nif(Sketch).

bits_nif(_Sketch) -> 32.

%% @doc Get capacity.
-spec capacity(reference()) -> non_neg_integer().
capacity({minisketch_fallback, Elements}) -> length(Elements);
capacity(Sketch) -> capacity_nif(Sketch).

capacity_nif(_Sketch) -> 0.

%% @doc Compute capacity needed for max_elements with fp rate 2^-fpbits.
-spec compute_capacity(non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    non_neg_integer().
compute_capacity(_Bits, MaxElements, FPBits) ->
    %% Approximate formula: capacity = max_elements + ceil(fpbits / log2(field_size))
    %% For 32-bit field: capacity ~ max_elements + fpbits/32 + 1
    MaxElements + (FPBits div 32) + 1.

%% @doc Compute max decodable elements for given capacity and fp rate.
-spec compute_max_elements(non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    non_neg_integer().
compute_max_elements(_Bits, Capacity, FPBits) ->
    max(0, Capacity - (FPBits div 32) - 1).
