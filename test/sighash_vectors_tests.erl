-module(sighash_vectors_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Path to the sighash test vectors from Bitcoin Core
-define(VECTORS_FILE, "/home/max/hashhog/ouroboros/bitcoin/src/test/data/sighash.json").

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

        %% Compute the legacy sighash
        Computed = beamchain_script:sighash_legacy(Tx, InputIndex, ScriptCode, HashTypeU32),

        %% Expected hash is in hex, compare
        ExpectedHash = beamchain_serialize:hex_decode(ExpectedHashHex),

        case Computed =:= ExpectedHash of
            true ->
                ok;
            false ->
                io:format(user,
                    "~nFAIL: input_index=~b hash_type=~b~n"
                    "  expected: ~s~n"
                    "  computed: ~s~n",
                    [InputIndex, HashTypeU32,
                     beamchain_serialize:hex_encode(ExpectedHash),
                     beamchain_serialize:hex_encode(Computed)]),
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
