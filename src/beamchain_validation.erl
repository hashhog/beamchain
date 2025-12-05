-module(beamchain_validation).

%% Block and transaction validation — Bitcoin consensus rules.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Context-free checks
-export([check_transaction/1]).

%%% -------------------------------------------------------------------
%%% Context-free transaction validation
%%% -------------------------------------------------------------------

%% @doc Validate a transaction without any chain context.
%% Checks structural rules that can be verified in isolation.
-spec check_transaction(#transaction{}) -> ok | {error, atom()}.
check_transaction(#transaction{inputs = Inputs, outputs = Outputs} = Tx) ->
    try
        %% 1. must have at least one input and one output
        Inputs =/= [] orelse throw(no_inputs),
        Outputs =/= [] orelse throw(no_outputs),

        %% 2. check serialized size is non-empty
        %% (implicit: we have inputs and outputs)

        %% 3. each output value must be non-negative and <= MAX_MONEY
        lists:foreach(fun(#tx_out{value = V}) ->
            V >= 0 orelse throw(negative_output),
            V =< ?MAX_MONEY orelse throw(output_too_large)
        end, Outputs),

        %% 4. total output value <= MAX_MONEY (check for overflow)
        TotalOut = lists:foldl(fun(#tx_out{value = V}, Acc) ->
            Sum = Acc + V,
            Sum =< ?MAX_MONEY orelse throw(total_output_overflow),
            Sum
        end, 0, Outputs),
        TotalOut =< ?MAX_MONEY orelse throw(total_output_overflow),

        %% 5. no duplicate input outpoints
        check_duplicate_inputs(Inputs),

        %% 6. coinbase-specific checks
        IsCoinbase = is_coinbase_tx(Tx),
        case IsCoinbase of
            true ->
                %% coinbase scriptSig must be 2-100 bytes
                [#tx_in{script_sig = CbScript} | _] = Inputs,
                SigLen = byte_size(CbScript),
                (SigLen >= 2 andalso SigLen =< 100) orelse
                    throw(bad_coinbase_length);
            false ->
                %% 7. non-coinbase: no null outpoints
                lists:foreach(fun(#tx_in{prev_out = #outpoint{hash = H, index = I}}) ->
                    case H =:= <<0:256>> andalso I =:= 16#ffffffff of
                        true -> throw(null_input);
                        false -> ok
                    end
                end, Inputs)
        end,

        %% 8. transaction weight >= MIN_TRANSACTION_WEIGHT
        Weight = beamchain_serialize:tx_weight(Tx),
        Weight >= ?MIN_TRANSACTION_WEIGHT orelse throw(tx_underweight),

        ok
    catch
        throw:Reason -> {error, Reason}
    end.

%%% -------------------------------------------------------------------
%%% Internal helpers
%%% -------------------------------------------------------------------

%% @doc Check if a transaction is a coinbase transaction.
is_coinbase_tx(#transaction{inputs = [#tx_in{prev_out =
    #outpoint{hash = <<0:256>>, index = 16#ffffffff}}]}) -> true;
is_coinbase_tx(_) -> false.

%% @doc Check for duplicate input outpoints.
check_duplicate_inputs(Inputs) ->
    Outpoints = [{H, I} || #tx_in{prev_out = #outpoint{hash = H, index = I}} <- Inputs],
    case length(Outpoints) =:= length(lists:usort(Outpoints)) of
        true -> ok;
        false -> throw(duplicate_inputs)
    end.
