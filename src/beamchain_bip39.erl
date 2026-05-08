%%% -------------------------------------------------------------------
%%% beamchain_bip39 - BIP-39 mnemonic encoding + mnemonic-to-seed PBKDF2
%%%
%%% Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
%%%
%%% Algorithm summary:
%%%   - Entropy of 16/20/24/28/32 bytes -> 12/15/18/21/24-word mnemonic.
%%%   - Append entropy_bits/32 checksum bits (prefix of sha256(entropy)) to
%%%     the entropy bitstring, then split into 11-bit chunks; each chunk is
%%%     an index into the 2048-word English wordlist.
%%%   - Mnemonic -> seed:
%%%       PBKDF2-HMAC-SHA512(
%%%         password = NFKD(mnemonic words joined by single space),
%%%         salt     = "mnemonic" ++ NFKD(passphrase),
%%%         iters    = 2048,
%%%         dklen    = 64).
%%%
%%% NFKD: BIP-39 specifies UTF-8 NFKD on both the mnemonic string and the
%%% passphrase. We use unicode:characters_to_nfc_binary/1 ... actually
%%% Erlang OTP 24+ ships unicode:characters_to_nfkd_binary/1 which is the
%%% spec-correct primitive; we use that. For ASCII-only inputs (the English
%%% wordlist + ASCII passphrases) NFKD is the identity, but we apply it
%%% unconditionally so non-ASCII passphrases (e.g. CJK) match other impls.
%%% -------------------------------------------------------------------
-module(beamchain_bip39).

-export([entropy_to_mnemonic/1,
         mnemonic_to_entropy/1,
         mnemonic_to_seed/2,
         validate_mnemonic/1,
         generate_mnemonic/1,
         wordlist/0]).

-define(WORDLIST_FILE, "bip39/english.txt").
-define(WORDLIST_KEY, {?MODULE, english_wordlist}).
-define(PBKDF2_ITERATIONS, 2048).
-define(PBKDF2_DKLEN, 64).

-type mnemonic() :: [binary()].
-export_type([mnemonic/0]).

%%% ===================================================================
%%% Public API
%%% ===================================================================

%% @doc Encode entropy bytes into a BIP-39 mnemonic word list.
%% Entropy must be 16, 20, 24, 28, or 32 bytes.
-spec entropy_to_mnemonic(binary()) -> {ok, mnemonic()} | {error, term()}.
entropy_to_mnemonic(Entropy) when is_binary(Entropy) ->
    case byte_size(Entropy) of
        Size when Size =:= 16; Size =:= 20; Size =:= 24;
                  Size =:= 28; Size =:= 32 ->
            EntBits = Size * 8,
            ChecksumBits = EntBits div 32,
            <<Checksum:ChecksumBits, _/bitstring>> =
                crypto:hash(sha256, Entropy),
            Combined = <<Entropy/binary, Checksum:ChecksumBits>>,
            Words = bits_to_words(Combined, wordlist(), []),
            {ok, Words};
        _ ->
            {error, invalid_entropy_size}
    end;
entropy_to_mnemonic(_) ->
    {error, invalid_entropy}.

%% @doc Decode a mnemonic word list back to entropy bytes.
%% Verifies the embedded checksum; returns {error, bad_checksum} on mismatch.
-spec mnemonic_to_entropy(mnemonic()) -> {ok, binary()} | {error, term()}.
mnemonic_to_entropy(Words) when is_list(Words) ->
    NWords = length(Words),
    case lists:member(NWords, [12, 15, 18, 21, 24]) of
        false ->
            {error, invalid_word_count};
        true ->
            WL = wordlist(),
            case words_to_indices(Words, WL, []) of
                {error, _} = E -> E;
                {ok, Indices} ->
                    TotalBits = NWords * 11,
                    ChecksumBits = TotalBits div 33,
                    EntBits = TotalBits - ChecksumBits,
                    Combined = indices_to_bits(Indices),
                    <<Entropy:EntBits/bitstring,
                      Checksum:ChecksumBits>> = Combined,
                    EntropyBytes = bitstring_to_binary(Entropy),
                    <<ExpectedChecksum:ChecksumBits, _/bitstring>> =
                        crypto:hash(sha256, EntropyBytes),
                    case ExpectedChecksum =:= Checksum of
                        true ->
                            {ok, EntropyBytes};
                        false ->
                            {error, bad_checksum}
                    end
            end
    end;
mnemonic_to_entropy(_) ->
    {error, invalid_mnemonic}.

%% @doc Convert a mnemonic + passphrase into a 64-byte BIP-39 seed.
%% Uses PBKDF2-HMAC-SHA512 with 2048 iterations and salt "mnemonic"++NFKD(pass).
%%
%% NOTE: This is BIP-39 seed derivation; it is intentionally distinct
%% from the at-rest wallet-encryption PBKDF2 in beamchain_wallet (which
%% uses 25k iterations and a different salt). DO NOT MERGE.
-spec mnemonic_to_seed(mnemonic(), binary()) -> binary().
mnemonic_to_seed(Words, Passphrase)
  when is_list(Words), is_binary(Passphrase) ->
    Joined = join_words(Words),
    NormMnemonic = nfkd(Joined),
    NormPass = nfkd(Passphrase),
    Salt = <<"mnemonic", NormPass/binary>>,
    crypto:pbkdf2_hmac(sha512, NormMnemonic, Salt,
                       ?PBKDF2_ITERATIONS, ?PBKDF2_DKLEN).

%% @doc Validate a mnemonic word list (membership + checksum).
-spec validate_mnemonic(mnemonic()) -> ok | {error, term()}.
validate_mnemonic(Words) ->
    case mnemonic_to_entropy(Words) of
        {ok, _} -> ok;
        {error, _} = E -> E
    end.

%% @doc Generate a fresh mnemonic of the given word count
%% (12/15/18/21/24) using crypto:strong_rand_bytes/1.
-spec generate_mnemonic(12 | 15 | 18 | 21 | 24) ->
          {ok, mnemonic()} | {error, term()}.
generate_mnemonic(NWords) ->
    EntropyBytes =
        case NWords of
            12 -> 16;
            15 -> 20;
            18 -> 24;
            21 -> 28;
            24 -> 32;
            _  -> undefined
        end,
    case EntropyBytes of
        undefined ->
            {error, invalid_word_count};
        N ->
            entropy_to_mnemonic(crypto:strong_rand_bytes(N))
    end.

%% @doc Returns the cached English wordlist as a tuple of 2048 binaries.
%% First call loads from priv/bip39/english.txt and caches in persistent_term.
-spec wordlist() -> tuple().
wordlist() ->
    try persistent_term:get(?WORDLIST_KEY) of
        WL -> WL
    catch
        error:badarg ->
            WL = load_wordlist(),
            persistent_term:put(?WORDLIST_KEY, WL),
            WL
    end.

%%% ===================================================================
%%% Internal helpers
%%% ===================================================================

%% Load the 2048-word English wordlist from priv/bip39/english.txt.
%% Returns a tuple of binaries indexed 1..2048.
load_wordlist() ->
    Path = filename:join(priv_dir(), ?WORDLIST_FILE),
    {ok, Bin} = file:read_file(Path),
    %% Split on \n; drop trailing empty after final newline if present.
    Lines = binary:split(Bin, <<"\n">>, [global, trim_all]),
    %% Strip any trailing \r (in case of CRLF line endings).
    Words = [strip_cr(L) || L <- Lines],
    case length(Words) of
        2048 -> list_to_tuple(Words);
        N -> error({wordlist_size_mismatch, N})
    end.

strip_cr(Bin) ->
    Sz = byte_size(Bin),
    case Sz > 0 andalso binary:at(Bin, Sz - 1) of
        $\r -> binary:part(Bin, 0, Sz - 1);
        _   -> Bin
    end.

%% priv_dir() — same fallback pattern used by beamchain_minisketch:priv_dir/0
%% so this works in both rebar3-shell and release builds.
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

%% Split a bitstring (entropy ++ checksum bits) into 11-bit chunks and
%% map each to a wordlist entry.
bits_to_words(<<>>, _WL, Acc) ->
    lists:reverse(Acc);
bits_to_words(<<Idx:11, Rest/bitstring>>, WL, Acc) ->
    %% wordlist tuple is 1-indexed in Erlang; BIP-39 indices are 0-based.
    Word = element(Idx + 1, WL),
    bits_to_words(Rest, WL, [Word | Acc]).

%% Map words to their 0-based indices in the wordlist tuple.
words_to_indices([], _WL, Acc) ->
    {ok, lists:reverse(Acc)};
words_to_indices([W | Rest], WL, Acc) ->
    case word_index(W, WL) of
        not_found -> {error, {unknown_word, W}};
        Idx       -> words_to_indices(Rest, WL, [Idx | Acc])
    end.

%% Linear search over the 2048-word tuple. 12-24 lookups per validate
%% is negligible (cached after first call).
word_index(Word, WL) ->
    word_index(Word, WL, 1, tuple_size(WL)).

word_index(_Word, _WL, I, N) when I > N ->
    not_found;
word_index(Word, WL, I, N) ->
    case element(I, WL) of
        Word -> I - 1;
        _    -> word_index(Word, WL, I + 1, N)
    end.

%% Concatenate 11-bit indices into a single bitstring.
indices_to_bits(Indices) ->
    indices_to_bits(Indices, <<>>).

indices_to_bits([], Acc) ->
    Acc;
indices_to_bits([Idx | Rest], Acc) ->
    indices_to_bits(Rest, <<Acc/bitstring, Idx:11>>).

%% Convert a bitstring (whose length is a multiple of 8) to a binary.
%% For BIP-39 the entropy length in bits (128/160/192/224/256) is always
%% a multiple of 8, so no padding is required; we just re-bind the bits
%% as a binary by extracting the byte count.
bitstring_to_binary(Bits) when is_binary(Bits) ->
    Bits;
bitstring_to_binary(Bits) ->
    Sz = bit_size(Bits),
    0 = Sz rem 8,
    Bytes = Sz div 8,
    <<Out:Bytes/binary>> = Bits,
    Out.

%% Join word list with single ASCII spaces (BIP-39 mandates U+0020).
join_words([]) -> <<>>;
join_words([W | Rest]) ->
    lists:foldl(fun(Word, Acc) -> <<Acc/binary, " ", Word/binary>> end,
                W, Rest).

%% Apply Unicode NFKD normalization. OTP 24+ ships
%% unicode:characters_to_nfkd_binary/1; for ASCII inputs (English
%% wordlist + ASCII passphrases) this is identity.
nfkd(Bin) when is_binary(Bin) ->
    case unicode:characters_to_nfkd_binary(Bin) of
        Out when is_binary(Out) -> Out;
        _ -> Bin  %% defensive: fall back to raw bytes on weird input
    end.
