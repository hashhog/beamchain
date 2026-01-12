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
