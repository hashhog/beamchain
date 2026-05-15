-module(beamchain_bip21).

%%% -------------------------------------------------------------------
%%% BIP-21 — `bitcoin:` payment URI parser.
%%%
%%% Spec: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
%%%
%%% Grammar (BIP-21):
%%%
%%%   bitcoinurn     = "bitcoin:" bitcoinaddress [ "?" bitcoinparams ]
%%%   bitcoinaddress = *base58 | *bech32        (case-insensitive scheme)
%%%   bitcoinparams  = bitcoinparam [ "&" bitcoinparams ]
%%%   bitcoinparam   = [ "amount=" amount ] |
%%%                    [ "label=" *qchar ]     |
%%%                    [ "message=" *qchar ]   |
%%%                    [ "req-" *qchar "=" *qchar ] |
%%%                    [ otherparam ]
%%%
%%% Two BIP-21 hard requirements implemented:
%%%
%%%   1. Unknown `req-*` parameters MUST cause the wallet to reject the
%%%      URI (BIP-21 §"Forward compatibility"). We surface this as
%%%      `{error, {unsupported_required_param, BinName}}`.
%%%   2. Unknown non-`req-` parameters MUST be ignored, but we still
%%%      retain them in `extras` so a consumer (e.g. BIP-78 PayJoin
%%%      sender via W119 BUG-3) can pick up vendor extensions.
%%%
%%% Recognised first-class params:
%%%
%%%   amount         — number of bitcoin (BIP-21 is bitcoin-denominated,
%%%                    NOT satoshis). Decimal with up to 8 fractional
%%%                    digits. We return integer satoshis to avoid
%%%                    float-rounding in downstream wallet math.
%%%   label          — human-readable label, percent-decoded utf8 binary.
%%%   message        — human-readable message, percent-decoded utf8 binary.
%%%   lightning      — BOLT-11 invoice string (BIP-21 extension), raw.
%%%   pj             — BIP-78 PayJoin endpoint URL (W119 G28).
%%%   pjos           — BIP-78 disableoutputsubstitution flag, "0" | "1"
%%%                    (W119 G29). Stored as 0 | 1 integer.
%%%
%%% Parameter keys are case-insensitive (per RFC 3986 §3.1 the *scheme*
%%% is case-insensitive; BIP-21 inherits the URI grammar and most
%%% wallets normalise keys to lowercase — we do the same). Values are
%%% percent-decoded but otherwise preserved.
%%%
%%% Address syntax is delegated to `beamchain_address:address_to_script/2`
%%% to keep BIP-21 separate from the address-codec surface — we do not
%%% want this module to learn base58 / bech32. The Network argument is
%%% forwarded as-is. If the caller is happy to defer address validation
%%% they may pass `any` and the address field will be the raw decoded
%%% binary with no script-roundtrip check.
%%%
%%% -------------------------------------------------------------------

-include("beamchain_bip21.hrl").

-export([parse/2]).
-export_type([bip21_uri/0]).

-type bip21_uri() :: #bip21_uri{}.

-define(SCHEME_LOWER, <<"bitcoin:">>).

%%% -------------------------------------------------------------------
%%% Public API
%%% -------------------------------------------------------------------

-spec parse(binary(), mainnet | testnet | testnet4 | regtest | signet | any) ->
    {ok, bip21_uri()} | {error, term()}.
parse(Input, Network) when is_binary(Input) ->
    case strip_scheme(Input) of
        {error, _} = E -> E;
        {ok, AfterScheme} ->
            {AddrBin, QueryBin} = split_query(AfterScheme),
            case validate_address(AddrBin, Network) of
                {error, _} = E -> E;
                ok ->
                    case parse_query(QueryBin) of
                        {error, _} = E -> E;
                        {ok, Params} ->
                            assemble(AddrBin, Params)
                    end
            end
    end;
parse(_, _) ->
    {error, not_binary}.

%%% -------------------------------------------------------------------
%%% Scheme handling — BIP-21 scheme is "bitcoin:" case-insensitive
%%% (RFC 3986 §3.1). We accept "BITCOIN:", "Bitcoin:", etc.
%%% -------------------------------------------------------------------

strip_scheme(Input) ->
    Len = byte_size(?SCHEME_LOWER),
    case Input of
        <<Prefix:Len/binary, Rest/binary>> ->
            case to_lower(Prefix) =:= ?SCHEME_LOWER of
                true  -> {ok, Rest};
                false -> {error, not_bitcoin_uri}
            end;
        _ ->
            {error, not_bitcoin_uri}
    end.

%%% -------------------------------------------------------------------
%%% Address / query split
%%% -------------------------------------------------------------------

split_query(Bin) ->
    case binary:split(Bin, <<"?">>) of
        [Addr]            -> {Addr, <<>>};
        [Addr, Query]     -> {Addr, Query}
    end.

%% Address validation: when caller passes `any`, accept any non-empty
%% binary (lets PayJoin / W119 unit tests use synthetic addresses).
%% Otherwise we ask beamchain_address to roundtrip the decoded address
%% through script_to_address — that catches checksum / unknown HRP /
%% wrong-network errors uniformly across base58check and bech32(m).
validate_address(<<>>, _) ->
    {error, empty_address};
validate_address(_AddrBin, any) ->
    ok;
validate_address(AddrBin, Network) ->
    case beamchain_address:address_to_script(binary_to_list(AddrBin), Network) of
        {ok, _Script} -> ok;
        {error, Reason} -> {error, {bad_address, Reason}}
    end.

%%% -------------------------------------------------------------------
%%% Query string parsing.
%%%
%%% Empty query → empty list. Splits on `&`, each piece on first `=`.
%%% Missing `=` → empty value. Percent-decoded on both sides. Keys
%%% are lowercased (case-insensitive). Duplicate keys: BIP-21 does
%%% not define semantics — we follow the "first occurrence wins"
%%% rule that the rust-bitcoin / Core wallet PSBT-URI code uses.
%%% -------------------------------------------------------------------

parse_query(<<>>) ->
    {ok, []};
parse_query(QueryBin) ->
    Pairs = binary:split(QueryBin, <<"&">>, [global]),
    decode_pairs(Pairs, []).

decode_pairs([], Acc) ->
    {ok, lists:reverse(Acc)};
decode_pairs([<<>> | Rest], Acc) ->
    %% e.g. "foo=1&" — trailing empty token; ignore.
    decode_pairs(Rest, Acc);
decode_pairs([Pair | Rest], Acc) ->
    case binary:split(Pair, <<"=">>) of
        [K] ->
            case percent_decode(K) of
                {error, _} = E -> E;
                {ok, DK}       ->
                    KLower = to_lower(DK),
                    decode_pairs(Rest, [{KLower, <<>>} | Acc])
            end;
        [K, V] ->
            case {percent_decode(K), percent_decode(V)} of
                {{ok, DK}, {ok, DV}} ->
                    KLower = to_lower(DK),
                    decode_pairs(Rest, [{KLower, DV} | Acc]);
                {{error, _} = E, _} -> E;
                {_, {error, _} = E} -> E
            end
    end.

%%% -------------------------------------------------------------------
%%% Folding parsed params into a #bip21_uri.
%%%
%%% Walks pairs once, classifying each one of:
%%%   - known first-class       → set the corresponding field
%%%   - "req-XXX" name          → reject the whole URI (BIP-21 hard req)
%%%   - anything else           → push to extras
%%% -------------------------------------------------------------------

assemble(AddrBin, Pairs) ->
    Init = #bip21_uri{address = AddrBin, extras = []},
    try
        fold_pairs(Pairs, Init)
    catch
        throw:{bip21_error, Reason} -> {error, Reason}
    end.

fold_pairs([], URI) ->
    {ok, URI#bip21_uri{extras = lists:reverse(URI#bip21_uri.extras)}};
fold_pairs([{Key, Val} | Rest], URI) ->
    URI1 = apply_param(Key, Val, URI),
    fold_pairs(Rest, URI1).

apply_param(<<"amount">>, V, URI) ->
    case parse_amount(V) of
        {ok, Sats} ->
            ensure_unset(URI#bip21_uri.amount, amount),
            URI#bip21_uri{amount = Sats};
        {error, _} = E ->
            throw({bip21_error, {bad_amount, V, E}})
    end;
apply_param(<<"label">>, V, URI) ->
    ensure_unset(URI#bip21_uri.label, label),
    URI#bip21_uri{label = V};
apply_param(<<"message">>, V, URI) ->
    ensure_unset(URI#bip21_uri.message, message),
    URI#bip21_uri{message = V};
apply_param(<<"lightning">>, V, URI) ->
    ensure_unset(URI#bip21_uri.lightning, lightning),
    URI#bip21_uri{lightning = V};
apply_param(<<"pj">>, V, URI) ->
    ensure_unset(URI#bip21_uri.pj, pj),
    URI#bip21_uri{pj = V};
apply_param(<<"pjos">>, V, URI) ->
    ensure_unset(URI#bip21_uri.pjos, pjos),
    case V of
        <<"0">> -> URI#bip21_uri{pjos = 0};
        <<"1">> -> URI#bip21_uri{pjos = 1};
        _       -> throw({bip21_error, {bad_pjos, V}})
    end;
apply_param(<<"req-", _/binary>> = Key, _Val, _URI) ->
    %% Unknown required parameter → BIP-21 demands rejection of the URI.
    throw({bip21_error, {unsupported_required_param, Key}});
apply_param(Key, Val, URI) ->
    push_extra(Key, Val, URI).

push_extra(Key, Val, URI) ->
    URI#bip21_uri{extras = [{Key, Val} | URI#bip21_uri.extras]}.

%% Repeated first-class keys: BIP-21 says SHOULD be unique; we treat
%% second occurrence as `{error, duplicate_param, Name}`. This is
%% strict-by-default and protects sender wallets from receivers that
%% craft URIs hoping for late-wins races.
ensure_unset(undefined, _) -> ok;
ensure_unset(_,         Name) -> throw({bip21_error, {duplicate_param, Name}}).

%%% -------------------------------------------------------------------
%%% Amount parsing
%%%
%%% BIP-21 amounts are decimal bitcoin (e.g. "0.42"), NOT satoshis.
%%% We convert to satoshis here so callers can do integer math.
%%% Up to 8 fractional digits permitted; more digits → reject.
%%% -------------------------------------------------------------------

-define(SATS_PER_BTC, 100000000).

parse_amount(Bin) ->
    case validate_decimal(Bin) of
        false ->
            {error, not_decimal};
        true ->
            case binary:split(Bin, <<".">>) of
                [IntPart] ->
                    case int_from_bin(IntPart) of
                        {ok, I}        -> {ok, I * ?SATS_PER_BTC};
                        {error, _} = E -> E
                    end;
                [IntPart, FracPart] ->
                    case byte_size(FracPart) =< 8 of
                        false -> {error, too_many_fractional_digits};
                        true ->
                            Padded = pad_right(FracPart, 8, $0),
                            case {int_from_bin(IntPart),
                                  int_from_bin(Padded)} of
                                {{ok, I}, {ok, F}} ->
                                    {ok, I * ?SATS_PER_BTC + F};
                                {{error, _} = E, _} -> E;
                                {_, {error, _} = E} -> E
                            end
                    end
            end
    end.

%% Reject "" / "." / sign chars / scientific notation.
validate_decimal(<<>>) -> false;
validate_decimal(Bin)  ->
    case Bin of
        <<".">> -> false;
        _       -> validate_decimal_chars(Bin, false)
    end.

validate_decimal_chars(<<>>, _SawDot) ->
    true;
validate_decimal_chars(<<$., Rest/binary>>, false) ->
    validate_decimal_chars(Rest, true);
validate_decimal_chars(<<$., _/binary>>, true) ->
    false;
validate_decimal_chars(<<C, Rest/binary>>, SawDot)
        when C >= $0, C =< $9 ->
    validate_decimal_chars(Rest, SawDot);
validate_decimal_chars(_, _) ->
    false.

int_from_bin(<<>>) -> {ok, 0};
int_from_bin(B)    ->
    try
        {ok, binary_to_integer(B)}
    catch
        error:badarg -> {error, not_integer}
    end.

pad_right(Bin, Width, _Pad) when byte_size(Bin) >= Width -> Bin;
pad_right(Bin, Width, Pad) ->
    Need = Width - byte_size(Bin),
    PadBin = list_to_binary(lists:duplicate(Need, Pad)),
    <<Bin/binary, PadBin/binary>>.

%%% -------------------------------------------------------------------
%%% Percent decoding (RFC 3986 §2.1)
%%%
%%% "+" is NOT a space in standard URI parsing (that's
%%% application/x-www-form-urlencoded, a different spec). BIP-21 is
%%% a `bitcoin:` URI per RFC 3986 generic-syntax — so "+" decodes to
%%% "+", and only "%HH" gets unescaped.
%%% -------------------------------------------------------------------

percent_decode(Bin) ->
    percent_decode(Bin, <<>>).

percent_decode(<<>>, Acc) ->
    {ok, Acc};
percent_decode(<<$%, H1, H2, Rest/binary>>, Acc) ->
    case {hex_digit(H1), hex_digit(H2)} of
        {H1V, H2V} when is_integer(H1V), is_integer(H2V) ->
            Byte = (H1V bsl 4) bor H2V,
            percent_decode(Rest, <<Acc/binary, Byte:8>>);
        _ ->
            {error, {bad_percent_escape, <<$%, H1, H2>>}}
    end;
percent_decode(<<$%, _/binary>>, _Acc) ->
    {error, truncated_percent_escape};
percent_decode(<<C, Rest/binary>>, Acc) ->
    percent_decode(Rest, <<Acc/binary, C:8>>).

hex_digit(C) when C >= $0, C =< $9 -> C - $0;
hex_digit(C) when C >= $a, C =< $f -> 10 + C - $a;
hex_digit(C) when C >= $A, C =< $F -> 10 + C - $A;
hex_digit(_) -> not_hex.

%%% -------------------------------------------------------------------
%%% Lowercasing — ASCII only. Param keys are case-insensitive ASCII
%%% by BIP-21; we never lowercase the address or any value.
%%% -------------------------------------------------------------------

to_lower(Bin) ->
    << <<(lower_byte(C))>> || <<C>> <= Bin >>.

lower_byte(C) when C >= $A, C =< $Z -> C + 32;
lower_byte(C) -> C.
