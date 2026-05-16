-module(beamchain_payjoin_state).

%%% -------------------------------------------------------------------
%%% BIP-78 PayJoin receiver-side state tables (W119 FIX-67).
%%%
%%% Three ETS tables owned by this module:
%%%
%%%   1. beamchain_payjoin_tokens  (G30 — replay protection)
%%%      One row per outstanding `pj=` invoice. Key is a 32-byte random
%%%      token the receiver embeds in the published `pj=` URL as
%%%      `?token=<hex>`. When the sender POSTs the Original PSBT the
%%%      receiver atomically removes the row; absence means the invoice
%%%      has already been consumed (or never existed) and we return
%%%      `unavailable` per BIP-78.
%%%
%%%   2. beamchain_payjoin_seen    (G19 — same-PSBT no-double-process)
%%%      One row per Original PSBT we have processed in the recent
%%%      window. Key is sha256 of the canonical Original PSBT bytes.
%%%      We keep entries for `?REPLAY_TTL_MS` and prune lazily on every
%%%      check. Sender retries within the window get
%%%      `original-psbt-rejected` to surface the dedup as a deterministic
%%%      protocol error (not a generic "unavailable").
%%%
%%%   3. beamchain_payjoin_used_scripts (G20 — anti-fingerprint state)
%%%      Records which receiver-owned scriptPubKeys have already been
%%%      contributed as a payjoin input in the recent window. This lets
%%%      pick_receiver_utxo/_ deprioritise UTXOs whose scriptPubKey we
%%%      have already used to PayJoin a different invoice (UIH-1
%%%      heuristic compounds across requests when receivers reuse a
%%%      single hot UTXO).
%%%
%%% The tables are public/named so any test or sibling module can read
%%% them without going through this module. Writes go through the
%%% public functions below so the prune step always runs.
%%% -------------------------------------------------------------------

-export([ensure/0,
         %% G30
         mint_invoice_token/1,
         consume_invoice_token/1,
         token_exists/1,
         tokens_size/0,
         %% G19
         remember_seen_psbt/1,
         seen_psbt/1,
         seen_size/0,
         %% G20
         remember_used_script/1,
         script_recently_used/1,
         %% Test helpers
         clear_all/0,
         now_ms/0]).

-define(TOKEN_TABLE,        beamchain_payjoin_tokens).
-define(SEEN_TABLE,         beamchain_payjoin_seen).
-define(USED_SCRIPT_TABLE,  beamchain_payjoin_used_scripts).

%% A token (invoice nonce) is valid for 1 hour after issuance — long
%% enough for a user to scan a QR code, open their wallet, and confirm,
%% short enough that a stolen merchant URL can't be replayed days later.
-define(TOKEN_TTL_MS, 60 * 60 * 1000).

%% A processed Original PSBT is remembered for 10 minutes — long enough
%% to dedup any reasonable HTTP retry/redirect cycle. BIP-78 §"Reception
%% of the response" says the sender SHOULD give up after ~30s; we
%% generously cover 20x that to absorb any pathological retry loop
%% without growing the table unbounded.
-define(REPLAY_TTL_MS, 10 * 60 * 1000).

%% A used receiver scriptPubKey is remembered for 10 minutes for UIH
%% anti-fingerprint preference. We do not REJECT reuse — that would
%% break wallets with a single dominant UTXO; we just deprioritise.
-define(USED_SCRIPT_TTL_MS, 10 * 60 * 1000).

%%% ===================================================================
%%% Table lifecycle
%%% ===================================================================

%% Idempotent: any caller (RPC, cowboy handler, eunit) hits this on
%% first use. We do NOT register a supervised process — the ETS tables
%% are public so they belong to whoever started them. In the running
%% node the wallet gen_server gets there first via beamchain_wallet
%% boot.
ensure() ->
    ensure_table(?TOKEN_TABLE,        [named_table, set, public,
                                       {read_concurrency, true},
                                       {write_concurrency, true}]),
    ensure_table(?SEEN_TABLE,         [named_table, set, public,
                                       {read_concurrency, true},
                                       {write_concurrency, true}]),
    ensure_table(?USED_SCRIPT_TABLE,  [named_table, set, public,
                                       {read_concurrency, true},
                                       {write_concurrency, true}]),
    ok.

ensure_table(Name, Opts) ->
    case ets:whereis(Name) of
        undefined ->
            try ets:new(Name, Opts) of
                _ -> ok
            catch
                error:badarg -> ok  %% race: another caller just created it
            end;
        _ -> ok
    end.

clear_all() ->
    ensure(),
    ets:delete_all_objects(?TOKEN_TABLE),
    ets:delete_all_objects(?SEEN_TABLE),
    ets:delete_all_objects(?USED_SCRIPT_TABLE),
    ok.

%%% ===================================================================
%%% G30 — invoice token (one-shot replay protection)
%%% ===================================================================

%% Mint a fresh 16-byte token, store {Token => {ExpiresAt, BoundAddr}}.
%% Returns the hex-encoded token for use in the published pj= URL.
mint_invoice_token(BoundAddr) when is_binary(BoundAddr) ->
    ensure(),
    Token = crypto:strong_rand_bytes(16),
    Expiry = now_ms() + ?TOKEN_TTL_MS,
    ets:insert(?TOKEN_TABLE, {Token, {Expiry, BoundAddr}}),
    hex_encode(Token).

%% Atomically consume a token. The first caller wins; the second caller
%% sees `not_found`. The hex form is parsed back to binary; lower- and
%% upper-case hex both accepted. Returns:
%%   {ok, BoundAddr}     — token existed AND was not expired (consumed)
%%   {error, expired}    — token existed but was past TTL (deleted)
%%   {error, not_found}  — never existed or already consumed
consume_invoice_token(HexBin) when is_binary(HexBin) ->
    ensure(),
    case hex_decode(HexBin) of
        {error, _} = E -> E;
        {ok, Token} ->
            case ets:lookup(?TOKEN_TABLE, Token) of
                [] ->
                    {error, not_found};
                [{Token, {Expiry, BoundAddr}}] ->
                    ets:delete(?TOKEN_TABLE, Token),
                    case now_ms() =< Expiry of
                        true  -> {ok, BoundAddr};
                        false -> {error, expired}
                    end
            end
    end.

%% Soft check (does not consume). Used by tests + diagnostics. Never
%% gates the production code path — only consume_invoice_token/1 does.
token_exists(HexBin) when is_binary(HexBin) ->
    ensure(),
    case hex_decode(HexBin) of
        {error, _} -> false;
        {ok, Token} ->
            case ets:lookup(?TOKEN_TABLE, Token) of
                []             -> false;
                [{Token, _}]   -> true
            end
    end.

tokens_size() ->
    ensure(),
    ets:info(?TOKEN_TABLE, size).

%%% ===================================================================
%%% G19 — seen PSBT dedup
%%% ===================================================================

%% Record an Original PSBT hash. Returns:
%%   ok           — first time we have seen this hash (caller proceeds)
%%   {error, already_seen} — we processed this PSBT in the last
%%                            REPLAY_TTL_MS milliseconds
remember_seen_psbt(PsbtBin) when is_binary(PsbtBin) ->
    ensure(),
    Hash = psbt_hash(PsbtBin),
    Now  = now_ms(),
    Cutoff = Now - ?REPLAY_TTL_MS,
    prune_seen(Cutoff),
    case ets:lookup(?SEEN_TABLE, Hash) of
        [{Hash, _Ts}] ->
            {error, already_seen};
        [] ->
            ets:insert(?SEEN_TABLE, {Hash, Now}),
            ok
    end.

%% Soft check — returns true when the hash is in the table AND has not
%% aged out. Used by eunit + diagnostics.
seen_psbt(PsbtBin) when is_binary(PsbtBin) ->
    ensure(),
    Hash = psbt_hash(PsbtBin),
    Cutoff = now_ms() - ?REPLAY_TTL_MS,
    case ets:lookup(?SEEN_TABLE, Hash) of
        [{Hash, Ts}] when Ts >= Cutoff -> true;
        _ -> false
    end.

seen_size() ->
    ensure(),
    ets:info(?SEEN_TABLE, size).

prune_seen(Cutoff) ->
    %% Lazy prune: only when the table grows past 1024 entries do we
    %% pay the foldl cost. Bound the worst-case for high-throughput
    %% merchants behind a load balancer.
    case ets:info(?SEEN_TABLE, size) of
        N when is_integer(N), N > 1024 ->
            Stale = ets:foldl(
                      fun({K, Ts}, Acc) when Ts < Cutoff -> [K | Acc];
                         (_, Acc) -> Acc
                      end, [], ?SEEN_TABLE),
            [ets:delete(?SEEN_TABLE, K) || K <- Stale],
            ok;
        _ -> ok
    end.

psbt_hash(Bin) ->
    crypto:hash(sha256, Bin).

%%% ===================================================================
%%% G20 — recently used receiver scripts (anti-fingerprint preference)
%%% ===================================================================

%% Record that we just contributed a receiver UTXO with this
%% scriptPubKey. pick_receiver_utxo/_ uses this to deprioritise the
%% same script on the next request (UIH-1 compounds when the same hot
%% UTXO is used over and over).
remember_used_script(ScriptPubKey) when is_binary(ScriptPubKey) ->
    ensure(),
    Now = now_ms(),
    ets:insert(?USED_SCRIPT_TABLE, {ScriptPubKey, Now}),
    prune_used_scripts(Now - ?USED_SCRIPT_TTL_MS),
    ok.

script_recently_used(ScriptPubKey) when is_binary(ScriptPubKey) ->
    ensure(),
    Cutoff = now_ms() - ?USED_SCRIPT_TTL_MS,
    case ets:lookup(?USED_SCRIPT_TABLE, ScriptPubKey) of
        [{_, Ts}] when Ts >= Cutoff -> true;
        _ -> false
    end.

prune_used_scripts(Cutoff) ->
    case ets:info(?USED_SCRIPT_TABLE, size) of
        N when is_integer(N), N > 1024 ->
            Stale = ets:foldl(
                      fun({K, Ts}, Acc) when Ts < Cutoff -> [K | Acc];
                         (_, Acc) -> Acc
                      end, [], ?USED_SCRIPT_TABLE),
            [ets:delete(?USED_SCRIPT_TABLE, K) || K <- Stale],
            ok;
        _ -> ok
    end.

%%% ===================================================================
%%% Time / hex helpers
%%% ===================================================================

now_ms() ->
    erlang:system_time(millisecond).

hex_encode(Bin) when is_binary(Bin) ->
    << <<(hex_digit(N bsr 4)), (hex_digit(N band 15))>> || <<N>> <= Bin >>.

hex_digit(N) when N < 10 -> N + $0;
hex_digit(N)             -> N - 10 + $a.

hex_decode(Bin) when is_binary(Bin) ->
    %% Accept 32 hex chars → 16 bytes (and any other even-length hex
    %% string for forwards-compat with future token widths). Reject
    %% odd-length and non-hex digits (would leak through
    %% cowboy_req:parse_qs which doesn't validate).
    case byte_size(Bin) of
        Sz when Sz rem 2 =/= 0 ->
            {error, bad_hex_length};
        _ ->
            try
                Decoded = << <<(hex_pair(P1, P2))>>
                             || <<P1, P2>> <= Bin >>,
                {ok, Decoded}
            catch
                throw:{bad_hex, _} = E -> {error, E}
            end
    end.

hex_pair(A, B) ->
    (hex_val(A) bsl 4) bor hex_val(B).

hex_val(C) when C >= $0, C =< $9 -> C - $0;
hex_val(C) when C >= $a, C =< $f -> C - $a + 10;
hex_val(C) when C >= $A, C =< $F -> C - $A + 10;
hex_val(C)                       -> throw({bad_hex, C}).
