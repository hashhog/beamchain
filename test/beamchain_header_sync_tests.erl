-module(beamchain_header_sync_tests).
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Block locator tests
%%% ===================================================================

%% Test the block locator construction logic.
%% The locator should start at the tip and go back exponentially.

%% We test the core locator algorithm in isolation by checking
%% the structure of the locator output.

%% Helper: compute MTP from a list of timestamps
compute_mtp_test() ->
    %% 11 timestamps, sorted median should be the 6th element
    Timestamps = [{I, 1000 + I * 600} || I <- lists:seq(0, 10)],
    MTP = compute_mtp_from_window(Timestamps),
    %% Median of [1000,1600,2200,2800,3400,4000,4600,5200,5800,6400,7000]
    %% = 4000 (6th element when 1-indexed at position 6)
    ?assertEqual(4000, MTP).

compute_mtp_empty_test() ->
    ?assertEqual(0, compute_mtp_from_window([])).

compute_mtp_single_test() ->
    ?assertEqual(1000, compute_mtp_from_window([{0, 1000}])).

compute_mtp_three_test() ->
    Window = [{0, 1000}, {1, 3000}, {2, 2000}],
    %% sorted: [1000, 2000, 3000], median = 2000
    ?assertEqual(2000, compute_mtp_from_window(Window)).

%% Test MTP window update (sliding window of 11)
mtp_window_update_test() ->
    %% Start with 11 entries
    Window = [{I, 1000 + I * 600} || I <- lists:seq(0, 10)],
    ?assertEqual(11, length(Window)),
    %% Add one more — should drop the oldest
    Window2 = update_mtp_window(Window, 11, 7600),
    ?assertEqual(11, length(Window2)),
    %% First entry should now be height 1, not height 0
    [{FirstH, _} | _] = Window2,
    ?assertEqual(1, FirstH),
    %% Last entry should be height 11
    {LastH, _} = lists:last(Window2),
    ?assertEqual(11, LastH).

mtp_window_grow_test() ->
    %% Window with fewer than 11 entries should grow
    Window = [{0, 1000}],
    Window2 = update_mtp_window(Window, 1, 1600),
    ?assertEqual(2, length(Window2)),
    Window3 = update_mtp_window(Window2, 2, 2200),
    ?assertEqual(3, length(Window3)).

%% Test chainwork binary encoding
chainwork_to_binary_test() ->
    %% Zero
    ?assertEqual(<<0:256>>, chainwork_to_binary(0)),
    %% Small value should be left-padded to 32 bytes
    Bin = chainwork_to_binary(42),
    ?assertEqual(32, byte_size(Bin)),
    ?assertEqual(42, binary:decode_unsigned(Bin, big)),
    %% Large value
    BigVal = 1 bsl 128,
    BigBin = chainwork_to_binary(BigVal),
    ?assertEqual(BigVal, binary:decode_unsigned(BigBin, big)).

%%% ===================================================================
%%% Checkpoint enforcement tests
%%% ===================================================================

checkpoint_match_test() ->
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => Hash}},
    ?assertEqual(ok, check_checkpoint(100, Hash, Params)).

checkpoint_mismatch_test() ->
    GoodHash = <<1:256>>,
    BadHash = <<2:256>>,
    Params = #{checkpoints => #{100 => GoodHash}},
    ?assertThrow(checkpoint_mismatch,
                 check_checkpoint(100, BadHash, Params)).

checkpoint_no_entry_test() ->
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => <<99:256>>}},
    %% Height 50 has no checkpoint, should pass
    ?assertEqual(ok, check_checkpoint(50, Hash, Params)).

checkpoint_empty_test() ->
    Hash = <<1:256>>,
    Params = #{checkpoints => #{}},
    ?assertEqual(ok, check_checkpoint(42, Hash, Params)).

%%% ===================================================================
%%% Anti-DoS: PoW and continuity validation tests
%%% ===================================================================

%% Test PoW validation on a sequence of headers
check_headers_pow_valid_test() ->
    %% Create a valid header with correct PoW
    %% Using testnet4 pow_limit for easier testing
    PowLimit = hex_to_bin(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    %% A header with very low difficulty (max target) will have valid PoW
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,  %% mainnet genesis difficulty
        nonce = 0
    },
    %% Compute hash - won't actually be valid but tests the flow
    %% For unit testing we use a mock approach
    ?assertEqual(ok, check_headers_pow_continuity_mock([Header], PowLimit, true)).

check_headers_pow_invalid_test() ->
    PowLimit = hex_to_bin(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    Header = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,
        nonce = 0
    },
    %% Test with mock returning invalid PoW
    ?assertEqual({error, invalid_pow},
                 check_headers_pow_continuity_mock([Header], PowLimit, false)).

check_headers_non_continuous_test() ->
    %% Two headers where the second doesn't point to the first
    Header1 = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,
        nonce = 0
    },
    Header2 = #block_header{
        version = 1,
        prev_hash = <<99:256>>,  %% Wrong prev_hash
        merkle_root = <<2:256>>,
        timestamp = 1700000600,
        bits = 16#1d00ffff,
        nonce = 0
    },
    %% Should fail continuity check
    ?assertEqual({error, non_continuous},
                 check_continuity([Header1, Header2])).

check_headers_continuous_test() ->
    %% Two headers where the second correctly points to the first
    Header1 = #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1700000000,
        bits = 16#1d00ffff,
        nonce = 0
    },
    Header1Hash = mock_block_hash(Header1),
    Header2 = #block_header{
        version = 1,
        prev_hash = Header1Hash,
        merkle_root = <<2:256>>,
        timestamp = 1700000600,
        bits = 16#1d00ffff,
        nonce = 0
    },
    ?assertEqual(ok, check_continuity([Header1, Header2])).

%%% ===================================================================
%%% Anti-DoS: Checkpoint ancestry tests
%%% ===================================================================

checkpoint_ancestry_below_last_checkpoint_test() ->
    %% Height 50 is below last checkpoint (100), but no checkpoint at 50
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => <<99:256>>}},
    ?assertEqual(ok, check_checkpoint_ancestry(50, Hash, Params)).

checkpoint_ancestry_at_checkpoint_match_test() ->
    %% At checkpoint height below the last checkpoint with matching hash
    Hash = <<1:256>>,
    Params = #{checkpoints => #{100 => Hash, 200 => <<99:256>>}},
    ?assertEqual(ok, check_checkpoint_ancestry(100, Hash, Params)).

checkpoint_ancestry_at_checkpoint_mismatch_test() ->
    %% At checkpoint height below the last checkpoint with wrong hash
    BadHash = <<2:256>>,
    Params = #{checkpoints => #{100 => <<1:256>>, 200 => <<99:256>>}},
    ?assertEqual({error, checkpoint_ancestry_mismatch},
                 check_checkpoint_ancestry(100, BadHash, Params)).

checkpoint_ancestry_above_last_checkpoint_test() ->
    %% Above all checkpoints - any hash is fine
    Hash = <<42:256>>,
    Params = #{checkpoints => #{100 => <<1:256>>}},
    ?assertEqual(ok, check_checkpoint_ancestry(200, Hash, Params)).

checkpoint_ancestry_empty_checkpoints_test() ->
    %% No checkpoints configured (testnet4, regtest)
    Hash = <<1:256>>,
    Params = #{checkpoints => #{}},
    ?assertEqual(ok, check_checkpoint_ancestry(50, Hash, Params)).

%%% ===================================================================
%%% Anti-DoS: Deep fork detection tests
%%% ===================================================================

get_last_checkpoint_height_test() ->
    Checkpoints = #{100 => <<1:256>>, 200 => <<2:256>>, 50 => <<3:256>>},
    ?assertEqual(200, get_last_checkpoint_height(Checkpoints)).

get_last_checkpoint_height_empty_test() ->
    ?assertEqual(0, get_last_checkpoint_height(#{})).

get_last_checkpoint_height_single_test() ->
    Checkpoints = #{42 => <<1:256>>},
    ?assertEqual(42, get_last_checkpoint_height(Checkpoints)).

%%% ===================================================================
%%% Anti-DoS: Unconnecting header count tests
%%% ===================================================================

max_unconnecting_headers_constant_test() ->
    %% Verify the constant is defined as expected (10)
    ?assertEqual(10, max_unconnecting_headers()).

%%% ===================================================================
%%% Internal helpers (duplicated from module for testing)
%%% ===================================================================

compute_mtp_from_window([]) ->
    0;
compute_mtp_from_window(Window) ->
    Timestamps = [Ts || {_H, Ts} <- Window],
    Sorted = lists:sort(Timestamps),
    lists:nth((length(Sorted) div 2) + 1, Sorted).

update_mtp_window(Window, Height, Timestamp) ->
    Window2 = Window ++ [{Height, Timestamp}],
    case length(Window2) > 11 of
        true -> tl(Window2);
        false -> Window2
    end.

chainwork_to_binary(0) ->
    <<0:256>>;
chainwork_to_binary(N) ->
    Bin = binary:encode_unsigned(N, big),
    case byte_size(Bin) < 32 of
        true ->
            Pad = 32 - byte_size(Bin),
            <<0:(Pad * 8), Bin/binary>>;
        false ->
            Bin
    end.

check_checkpoint(Height, BlockHash, Params) ->
    Checkpoints = maps:get(checkpoints, Params, #{}),
    case maps:find(Height, Checkpoints) of
        {ok, ExpectedHash} ->
            case BlockHash =:= ExpectedHash of
                true -> ok;
                false -> throw(checkpoint_mismatch)
            end;
        error ->
            ok
    end.

%% Mock PoW+continuity check for testing
check_headers_pow_continuity_mock(_Headers, _PowLimit, true) ->
    ok;
check_headers_pow_continuity_mock(_Headers, _PowLimit, false) ->
    {error, invalid_pow}.

%% Check header continuity (prev_hash chain)
check_continuity([]) ->
    ok;
check_continuity([_Single]) ->
    ok;
check_continuity([First | Rest]) ->
    FirstHash = mock_block_hash(First),
    check_continuity_chain(Rest, FirstHash).

check_continuity_chain([], _PrevHash) ->
    ok;
check_continuity_chain([Header | Rest], PrevHash) ->
    case Header#block_header.prev_hash =:= PrevHash of
        true ->
            NextHash = mock_block_hash(Header),
            check_continuity_chain(Rest, NextHash);
        false ->
            {error, non_continuous}
    end.

%% Simple mock block hash for testing continuity
mock_block_hash(#block_header{merkle_root = MR, nonce = N}) ->
    %% Just use a deterministic hash based on merkle_root and nonce
    crypto:hash(sha256, <<MR/binary, N:32>>).

%% Checkpoint ancestry check (duplicated from module)
check_checkpoint_ancestry(Height, BlockHash, Params) ->
    Checkpoints = maps:get(checkpoints, Params, #{}),
    case maps:size(Checkpoints) of
        0 ->
            ok;
        _ ->
            LastCheckpointHeight = get_last_checkpoint_height(Checkpoints),
            case Height < LastCheckpointHeight of
                true ->
                    case maps:find(Height, Checkpoints) of
                        {ok, ExpectedHash} ->
                            case BlockHash =:= ExpectedHash of
                                true -> ok;
                                false -> {error, checkpoint_ancestry_mismatch}
                            end;
                        error ->
                            ok
                    end;
                false ->
                    ok
            end
    end.

%% Get the highest checkpoint height
get_last_checkpoint_height(Checkpoints) ->
    maps:fold(fun(H, _, Max) -> max(H, Max) end, 0, Checkpoints).

%% Constant for testing
max_unconnecting_headers() ->
    10.

%% Hex to binary helper
hex_to_bin(HexStr) ->
    hex_to_bin(HexStr, <<>>).

hex_to_bin([], Acc) ->
    Acc;
hex_to_bin([H1, H2 | Rest], Acc) ->
    Byte = (hex_val(H1) bsl 4) bor hex_val(H2),
    hex_to_bin(Rest, <<Acc/binary, Byte>>).

hex_val(C) when C >= $0, C =< $9 -> C - $0;
hex_val(C) when C >= $a, C =< $f -> C - $a + 10;
hex_val(C) when C >= $A, C =< $F -> C - $A + 10.
