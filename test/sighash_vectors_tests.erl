-module(sighash_vectors_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Path relative to project root (test/data/ is committed to the repo).
-define(VECTORS_FILE, "test/data/sighash.json").

sighash_vectors_test_() ->
    {timeout, 120, fun run_all_vectors/0}.

run_all_vectors() ->
    {ok, JsonBin} = file:read_file(?VECTORS_FILE),
    Vectors = jsx:decode(JsonBin, [return_maps]),
    %% First element is a header comment, skip it
    [_Header | TestCases] = Vectors,
    Results = lists:map(fun run_one_vector/1, TestCases),
    Passed = length([ok || ok <- Results]),
    Failed = length(Results) - Passed,
    io:format(user, "~nSighash vectors: ~b passed, ~b failed out of ~b~n",
              [Passed, Failed, length(Results)]),
    ?assertEqual(0, Failed).

run_one_vector([RawTxHex, ScriptHex, InputIndex, HashType, ExpectedHashHex]) ->
    try
        %% Decode the raw transaction
        TxBin = beamchain_serialize:hex_decode(RawTxHex),
        {Tx, _Rest} = beamchain_serialize:decode_transaction(TxBin),

        %% Decode the subscript
        ScriptCode = beamchain_serialize:hex_decode(ScriptHex),

        %% HashType may be negative in the JSON (it's a signed 32-bit int).
        %% Convert to unsigned 32-bit for use in sighash computation.
        HashTypeU32 = HashType band 16#ffffffff,

        %% Compute the legacy sighash.
        %% sighash_legacy/4 returns raw double-SHA256 bytes (big-endian,
        %% natural digest order).
        Computed = beamchain_script:sighash_legacy(Tx, InputIndex, ScriptCode, HashTypeU32),

        %% Bitcoin Core's sighash.json stores the expected hash in
        %% Bitcoin display format: uint256::GetHex() reverses the byte
        %% order before hex-encoding (the internal uint256 is little-endian,
        %% so display is bytes reversed).  Reverse the computed digest
        %% before comparison so we match the same convention.
        ComputedRevBin = reverse_bytes(Computed),
        ExpectedRaw = beamchain_serialize:hex_decode(ExpectedHashHex),

        case ComputedRevBin =:= ExpectedRaw of
            true ->
                ok;
            false ->
                io:format(user,
                    "~nFAIL: input_index=~b hash_type=~b~n"
                    "  expected: ~s~n"
                    "  computed: ~s~n",
                    [InputIndex, HashTypeU32,
                     beamchain_serialize:hex_encode(ExpectedRaw),
                     beamchain_serialize:hex_encode(ComputedRevBin)]),
                fail
        end
    catch
        Class:Reason:Stack ->
            io:format(user,
                "~nERROR: input_index=~b hash_type=~b~n"
                "  ~p:~p~n  ~p~n",
                [InputIndex, HashType, Class, Reason, hd(Stack)]),
            fail
    end;
run_one_vector(_Other) ->
    %% Skip any malformed entries
    ok.

%% @doc Reverse the bytes of a binary (used to convert between internal
%% digest order and Bitcoin display order).
reverse_bytes(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).
