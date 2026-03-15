-module(beamchain_script).

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%% Public API
-export([verify_script/5, eval_script/5]).
-export([decode_script_num/2, encode_script_num/1, script_bool/1]).
-export([check_minimal_encoding/1]).
-export([flags_for_height/2]).

%% Sighash computation
-export([sighash_legacy/4, sighash_witness_v0/5, sighash_taproot/7]).
-export([find_and_delete/2]).  %% Exported for testing

%%% -------------------------------------------------------------------
%%% Script execution state
%%% -------------------------------------------------------------------

-record(script_state, {
    stack = []        :: [binary()],
    altstack = []     :: [binary()],
    exec_stack = []   :: [boolean()],   %% IF/ELSE nesting
    op_count = 0      :: non_neg_integer(),
    codesep_pos = 16#ffffffff :: non_neg_integer(),
    flags = 0         :: non_neg_integer(),
    sig_checker       :: term(),
    sig_version = base :: base | witness_v0 | tapscript,
    script = <<>>     :: binary(),      %% full script (for codesep)
    sigops_budget = 0 :: integer(),     %% tapscript sigops budget
    success = false   :: boolean()      %% tapscript OP_SUCCESS
}).

%%% -------------------------------------------------------------------
%%% Opcode constants
%%% -------------------------------------------------------------------

%% Constants / push
-define(OP_0, 16#00).
-define(OP_PUSHDATA1, 16#4c).
-define(OP_PUSHDATA2, 16#4d).
-define(OP_PUSHDATA4, 16#4e).
-define(OP_1NEGATE, 16#4f).
-define(OP_RESERVED, 16#50).
-define(OP_1, 16#51).
-define(OP_16, 16#60).

%% Flow control
-define(OP_NOP, 16#61).
-define(OP_VER, 16#62).
-define(OP_IF, 16#63).
-define(OP_NOTIF, 16#64).
-define(OP_VERIF, 16#65).
-define(OP_VERNOTIF, 16#66).
-define(OP_ELSE, 16#67).
-define(OP_ENDIF, 16#68).
-define(OP_VERIFY, 16#69).
-define(OP_RETURN, 16#6a).

%% Stack
-define(OP_TOALTSTACK, 16#6b).
-define(OP_FROMALTSTACK, 16#6c).
-define(OP_2DROP, 16#6d).
-define(OP_2DUP, 16#6e).
-define(OP_3DUP, 16#6f).
-define(OP_2OVER, 16#70).
-define(OP_2ROT, 16#71).
-define(OP_2SWAP, 16#72).
-define(OP_IFDUP, 16#73).
-define(OP_DEPTH, 16#74).
-define(OP_DROP, 16#75).
-define(OP_DUP, 16#76).
-define(OP_NIP, 16#77).
-define(OP_OVER, 16#78).
-define(OP_PICK, 16#79).
-define(OP_ROLL, 16#7a).
-define(OP_ROT, 16#7b).
-define(OP_SWAP, 16#7c).
-define(OP_TUCK, 16#7d).

%% Splice
-define(OP_CAT, 16#7e).
-define(OP_SUBSTR, 16#7f).
-define(OP_LEFT, 16#80).
-define(OP_RIGHT, 16#81).
-define(OP_SIZE, 16#82).

%% Bitwise
-define(OP_INVERT, 16#83).
-define(OP_AND, 16#84).
-define(OP_OR, 16#85).
-define(OP_XOR, 16#86).
-define(OP_EQUAL, 16#87).
-define(OP_EQUALVERIFY, 16#88).

%% Arithmetic
-define(OP_1ADD, 16#8b).
-define(OP_1SUB, 16#8c).
-define(OP_2MUL, 16#8d).
-define(OP_2DIV, 16#8e).
-define(OP_NEGATE, 16#8f).
-define(OP_ABS, 16#90).
-define(OP_NOT, 16#91).
-define(OP_0NOTEQUAL, 16#92).
-define(OP_ADD, 16#93).
-define(OP_SUB, 16#94).
-define(OP_MUL, 16#95).
-define(OP_DIV, 16#96).
-define(OP_MOD, 16#97).
-define(OP_LSHIFT, 16#98).
-define(OP_RSHIFT, 16#99).
-define(OP_BOOLAND, 16#9a).
-define(OP_BOOLOR, 16#9b).
-define(OP_NUMEQUAL, 16#9c).
-define(OP_NUMEQUALVERIFY, 16#9d).
-define(OP_NUMNOTEQUAL, 16#9e).
-define(OP_LESSTHAN, 16#9f).
-define(OP_GREATERTHAN, 16#a0).
-define(OP_LESSTHANOREQUAL, 16#a1).
-define(OP_GREATERTHANOREQUAL, 16#a2).
-define(OP_MIN, 16#a3).
-define(OP_MAX, 16#a4).
-define(OP_WITHIN, 16#a5).

%% Crypto
-define(OP_RIPEMD160, 16#a6).
-define(OP_SHA1, 16#a7).
-define(OP_SHA256, 16#a8).
-define(OP_HASH160, 16#a9).
-define(OP_HASH256, 16#aa).
-define(OP_CODESEPARATOR, 16#ab).
-define(OP_CHECKSIG, 16#ac).
-define(OP_CHECKSIGVERIFY, 16#ad).
-define(OP_CHECKMULTISIG, 16#ae).
-define(OP_CHECKMULTISIGVERIFY, 16#af).

%% Locktime
-define(OP_NOP1, 16#b0).
-define(OP_CHECKLOCKTIMEVERIFY, 16#b1).
-define(OP_CHECKSEQUENCEVERIFY, 16#b2).
-define(OP_NOP4, 16#b3).
-define(OP_NOP5, 16#b4).
-define(OP_NOP6, 16#b5).
-define(OP_NOP7, 16#b6).
-define(OP_NOP8, 16#b7).
-define(OP_NOP9, 16#b8).
-define(OP_NOP10, 16#b9).

%% Tapscript
-define(OP_CHECKSIGADD, 16#ba).

%%% -------------------------------------------------------------------
%%% Script number encoding (CScriptNum)
%%% -------------------------------------------------------------------

-spec decode_script_num(binary(), integer()) -> {ok, integer()} | {error, atom()}.
decode_script_num(<<>>, _MaxLen) ->
    {ok, 0};
decode_script_num(Bin, MaxLen) when byte_size(Bin) > MaxLen ->
    {error, script_num_overflow};
decode_script_num(Bin, _MaxLen) ->
    Bytes = binary_to_list(Bin),
    case check_minimal_num(Bytes) of
        false -> {ok, decode_num_bytes(Bytes)};
        true -> {ok, decode_num_bytes(Bytes)}
    end.

decode_num_bytes([]) ->
    0;
decode_num_bytes(Bytes) ->
    Last = lists:last(Bytes),
    Negative = (Last band 16#80) =/= 0,
    %% strip sign bit from last byte
    StrippedLast = Last band 16#7f,
    AllButLast = lists:droplast(Bytes),
    Magnitude = decode_le_magnitude(AllButLast ++ [StrippedLast]),
    case Negative of
        true -> -Magnitude;
        false -> Magnitude
    end.

decode_le_magnitude(Bytes) ->
    decode_le_magnitude(Bytes, 0, 0).
decode_le_magnitude([], Acc, _Shift) ->
    Acc;
decode_le_magnitude([B | Rest], Acc, Shift) ->
    decode_le_magnitude(Rest, Acc bor (B bsl Shift), Shift + 8).

-spec encode_script_num(integer()) -> binary().
encode_script_num(0) ->
    <<>>;
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

encode_le_positive(N) ->
    encode_le_positive(N, []).
encode_le_positive(0, Acc) ->
    lists:reverse(Acc);
encode_le_positive(N, Acc) ->
    encode_le_positive(N bsr 8, [N band 16#ff | Acc]).

%% Check for non-minimal encodings (used with MINIMALDATA flag)
check_minimal_encoding(<<>>) ->
    true;
check_minimal_encoding(Bin) ->
    Len = byte_size(Bin),
    Last = binary:at(Bin, Len - 1),
    %% If last byte is 0x00 or 0x80, check if it's needed
    case Last band 16#7f of
        0 when Len =:= 1 ->
            %% single byte 0x00 or 0x80 is non-minimal (zero should be <<>>)
            false;
        0 when Len > 1 ->
            %% trailing 0x00 or 0x80 is only needed if prev byte has high bit
            PrevByte = binary:at(Bin, Len - 2),
            (PrevByte band 16#80) =/= 0;
        _ ->
            true
    end.

check_minimal_num(_Bytes) ->
    true.

%%% -------------------------------------------------------------------
%%% Script boolean
%%% -------------------------------------------------------------------

-spec script_bool(binary()) -> boolean().
script_bool(<<>>) ->
    false;
script_bool(Bin) ->
    Len = byte_size(Bin),
    %% check if all bytes are zero (negative zero 0x80 in last byte = false)
    AllZero = lists:all(fun(I) ->
        binary:at(Bin, I) =:= 0
    end, lists:seq(0, Len - 2)),
    case AllZero of
        false -> true;
        true ->
            LastByte = binary:at(Bin, Len - 1),
            case LastByte of
                0 -> false;
                16#80 -> false;  %% negative zero
                _ -> true
            end
    end.

script_true() -> <<1>>.
script_false() -> <<>>.

%%% -------------------------------------------------------------------
%%% Disabled opcodes check
%%% -------------------------------------------------------------------

is_disabled_opcode(?OP_CAT) -> true;
is_disabled_opcode(?OP_SUBSTR) -> true;
is_disabled_opcode(?OP_LEFT) -> true;
is_disabled_opcode(?OP_RIGHT) -> true;
is_disabled_opcode(?OP_INVERT) -> true;
is_disabled_opcode(?OP_AND) -> true;
is_disabled_opcode(?OP_OR) -> true;
is_disabled_opcode(?OP_XOR) -> true;
is_disabled_opcode(?OP_2MUL) -> true;
is_disabled_opcode(?OP_2DIV) -> true;
is_disabled_opcode(?OP_MUL) -> true;
is_disabled_opcode(?OP_DIV) -> true;
is_disabled_opcode(?OP_MOD) -> true;
is_disabled_opcode(?OP_LSHIFT) -> true;
is_disabled_opcode(?OP_RSHIFT) -> true;
is_disabled_opcode(_) -> false.

%% OP_SUCCESS codes for tapscript (BIP 342)
is_op_success(16#50) -> true;
is_op_success(16#62) -> true;
is_op_success(16#7e) -> true;
is_op_success(16#7f) -> true;
is_op_success(16#80) -> true;
is_op_success(16#81) -> true;
is_op_success(Op) when Op >= 16#83, Op =< 16#86 -> true;
is_op_success(16#89) -> true;
is_op_success(16#8a) -> true;
is_op_success(16#8d) -> true;
is_op_success(16#8e) -> true;
is_op_success(Op) when Op >= 16#95, Op =< 16#99 -> true;
is_op_success(Op) when Op >= 16#bb, Op =< 16#fe -> true;
is_op_success(_) -> false.

%% @doc Check if a public key is a valid compressed key (33 bytes, 0x02 or 0x03 prefix).
%% Used for SCRIPT_VERIFY_WITNESS_PUBKEYTYPE enforcement in witness v0.
-spec is_compressed_pubkey(binary()) -> boolean().
is_compressed_pubkey(<<16#02, _:32/binary>>) -> true;
is_compressed_pubkey(<<16#03, _:32/binary>>) -> true;
is_compressed_pubkey(_) -> false.

%%% -------------------------------------------------------------------
%%% Execution state helpers
%%% -------------------------------------------------------------------

executing(#script_state{exec_stack = []}) -> true;
executing(#script_state{exec_stack = Stack}) ->
    lists:all(fun(V) -> V end, Stack).

push(Value, #script_state{stack = Stack} = State) ->
    State#script_state{stack = [Value | Stack]}.

push_num(N, State) -> push(encode_script_num(N), State).

pop(#script_state{stack = []}) ->
    {error, stack_underflow};
pop(#script_state{stack = [Top | Rest]} = State) ->
    {ok, Top, State#script_state{stack = Rest}}.

pop2(State) ->
    case pop(State) of
        {ok, A, State1} ->
            case pop(State1) of
                {ok, B, State2} -> {ok, B, A, State2};
                Error -> Error
            end;
        Error -> Error
    end.

pop3(State) ->
    case pop(State) of
        {ok, A, State1} ->
            case pop2(State1) of
                {ok, B, C, State2} -> {ok, B, C, A, State2};
                Error -> Error
            end;
        Error -> Error
    end.

pop_num(State) ->
    pop_num(State, 4).
pop_num(State, MaxLen) ->
    case pop(State) of
        {ok, Bin, State1} ->
            case decode_script_num(Bin, MaxLen) of
                {ok, N} -> {ok, N, State1};
                {error, _} = E -> E
            end;
        Error -> Error
    end.

pop_num2(State) ->
    case pop_num(State) of
        {ok, A, State1} ->
            case pop_num(State1) of
                {ok, B, State2} -> {ok, B, A, State2};
                Error -> Error
            end;
        Error -> Error
    end.

check_stack_size(#script_state{stack = S, altstack = A}) ->
    length(S) + length(A) =< ?MAX_STACK_SIZE.

count_op(#script_state{op_count = Count, sig_version = SigVer} = State) ->
    NewCount = Count + 1,
    case SigVer of
        tapscript ->
            %% tapscript has no opcode limit
            {ok, State#script_state{op_count = NewCount}};
        _ when NewCount > ?MAX_OPS_PER_SCRIPT ->
            {error, op_count_exceeded};
        _ ->
            {ok, State#script_state{op_count = NewCount}}
    end.

%%% -------------------------------------------------------------------
%%% Main evaluation entry point
%%% -------------------------------------------------------------------

-spec eval_script(binary(), [binary()], non_neg_integer(),
                  term(), base | witness_v0 | tapscript) ->
    {ok, [binary()]} | {error, atom()}.
eval_script(Script, Stack, Flags, SigChecker, SigVersion) ->
    %% Check for OP_SUCCESS in tapscript before execution
    case SigVersion of
        tapscript ->
            case check_op_success(Script, Flags) of
                {success, true} ->
                    {ok, [script_true()]};
                {error, _} = E ->
                    E;
                ok ->
                    do_eval_script(Script, Stack, Flags, SigChecker, SigVersion)
            end;
        _ ->
            do_eval_script(Script, Stack, Flags, SigChecker, SigVersion)
    end.

do_eval_script(Script, Stack, Flags, SigChecker, SigVersion) ->
    case byte_size(Script) > ?MAX_SCRIPT_SIZE andalso SigVersion =/= tapscript of
        true -> {error, script_too_large};
        false ->
            State0 = #script_state{
                stack = Stack,
                flags = Flags,
                sig_checker = SigChecker,
                sig_version = SigVersion,
                script = Script,
                sigops_budget = 0  %% set by caller for tapscript
            },
            execute(Script, 0, State0)
    end.

%%% -------------------------------------------------------------------
%%% Check for OP_SUCCESS in tapscript (BIP 342)
%%% -------------------------------------------------------------------

check_op_success(Script, Flags) ->
    case scan_for_op_success(Script) of
        true ->
            case Flags band ?SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS of
                0 -> {success, true};
                _ -> {error, discourage_op_success}
            end;
        false ->
            ok
    end.

scan_for_op_success(<<>>) ->
    false;
scan_for_op_success(<<Op, _Rest/binary>>) when Op >= 1, Op =< 16#4b ->
    %% data push, skip bytes
    skip_push(Op, _Rest);
scan_for_op_success(<<?OP_PUSHDATA1, Len:8, Rest/binary>>) ->
    skip_data(Len, Rest);
scan_for_op_success(<<?OP_PUSHDATA2, Len:16/little, Rest/binary>>) ->
    skip_data(Len, Rest);
scan_for_op_success(<<?OP_PUSHDATA4, Len:32/little, Rest/binary>>) ->
    skip_data(Len, Rest);
scan_for_op_success(<<Op, _Rest/binary>>) ->
    case is_op_success(Op) of
        true -> true;
        false -> scan_for_op_success(_Rest)
    end.

skip_push(N, Bin) ->
    case Bin of
        <<_:N/binary, Rest/binary>> -> scan_for_op_success(Rest);
        _ -> false
    end.

skip_data(Len, Bin) ->
    case Bin of
        <<_:Len/binary, Rest/binary>> -> scan_for_op_success(Rest);
        _ -> false
    end.

%%% -------------------------------------------------------------------
%%% Script execution loop
%%% -------------------------------------------------------------------

execute(<<>>, _Pos, #script_state{exec_stack = ExecStack} = State) ->
    case ExecStack of
        [] -> {ok, State#script_state.stack};
        _ -> {error, unbalanced_conditional}
    end;

%% --- Data push: 1-75 bytes ---
execute(<<PushLen, Rest/binary>>, Pos, State)
  when PushLen >= 1, PushLen =< 16#4b ->
    case Rest of
        <<Data:PushLen/binary, Rest2/binary>> ->
            case executing(State) of
                true ->
                    case check_push_size(Data, State) of
                        ok ->
                            State1 = push(Data, State),
                            case check_stack_size(State1) of
                                true -> execute(Rest2, Pos + 1 + PushLen, State1);
                                false -> {error, stack_overflow}
                            end;
                        Error -> Error
                    end;
                false ->
                    execute(Rest2, Pos + 1 + PushLen, State)
            end;
        _ ->
            {error, script_truncated}
    end;

%% --- OP_0 (push empty) ---
execute(<<?OP_0, Rest/binary>>, Pos, State) ->
    case executing(State) of
        true ->
            State1 = push(<<>>, State),
            execute(Rest, Pos + 1, State1);
        false ->
            execute(Rest, Pos + 1, State)
    end;

%% --- OP_PUSHDATA1 ---
execute(<<?OP_PUSHDATA1, Len:8, Rest/binary>>, Pos, State) ->
    execute_pushdata(Len, Rest, Pos + 2, State);

%% --- OP_PUSHDATA2 ---
execute(<<?OP_PUSHDATA2, Len:16/little, Rest/binary>>, Pos, State) ->
    execute_pushdata(Len, Rest, Pos + 3, State);

%% --- OP_PUSHDATA4 ---
execute(<<?OP_PUSHDATA4, Len:32/little, Rest/binary>>, Pos, State) ->
    execute_pushdata(Len, Rest, Pos + 5, State);

%% --- OP_1NEGATE ---
execute(<<?OP_1NEGATE, Rest/binary>>, Pos, State) ->
    case executing(State) of
        true ->
            State1 = push(encode_script_num(-1), State),
            execute(Rest, Pos + 1, State1);
        false ->
            execute(Rest, Pos + 1, State)
    end;

%% --- OP_RESERVED (0x50) - causes failure if executed ---
execute(<<?OP_RESERVED, Rest/binary>>, Pos, State) ->
    case executing(State) of
        true -> {error, op_reserved};
        false -> execute(Rest, Pos + 1, State)
    end;

%% --- OP_1 through OP_16 ---
execute(<<Op, Rest/binary>>, Pos, State)
  when Op >= ?OP_1, Op =< ?OP_16 ->
    case executing(State) of
        true ->
            N = Op - ?OP_1 + 1,
            State1 = push(encode_script_num(N), State),
            execute(Rest, Pos + 1, State1);
        false ->
            execute(Rest, Pos + 1, State)
    end;

%% --- OP_NOP ---
execute(<<?OP_NOP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute(Rest, Pos + 1, State1);
        Error -> Error
    end;

%% --- OP_VER (causes failure if executed) ---
execute(<<?OP_VER, Rest/binary>>, Pos, State) ->
    case executing(State) of
        true -> {error, op_ver};
        false -> execute(Rest, Pos + 1, State)
    end;

%% --- OP_VERIF / OP_VERNOTIF (always fail) ---
execute(<<?OP_VERIF, _/binary>>, _Pos, _State) ->
    {error, op_verif};
execute(<<?OP_VERNOTIF, _/binary>>, _Pos, _State) ->
    {error, op_vernotif};

%% --- OP_IF ---
execute(<<?OP_IF, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_if(true, Rest, Pos + 1, State1);
        Error -> Error
    end;

%% --- OP_NOTIF ---
execute(<<?OP_NOTIF, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_if(false, Rest, Pos + 1, State1);
        Error -> Error
    end;

%% --- OP_ELSE ---
execute(<<?OP_ELSE, _Rest/binary>>, _Pos,
        #script_state{exec_stack = []} = _State) ->
    {error, unexpected_else};
execute(<<?OP_ELSE, Rest/binary>>, Pos,
        #script_state{exec_stack = [Top | ExRest]} = State) ->
    case count_op(State) of
        {ok, State1} ->
            State2 = State1#script_state{
                exec_stack = [not Top | ExRest]
            },
            execute(Rest, Pos + 1, State2);
        Error -> Error
    end;

%% --- OP_ENDIF ---
execute(<<?OP_ENDIF, _Rest/binary>>, _Pos,
        #script_state{exec_stack = []} = _State) ->
    {error, unexpected_endif};
execute(<<?OP_ENDIF, Rest/binary>>, Pos,
        #script_state{exec_stack = [_ | ExRest]} = State) ->
    case count_op(State) of
        {ok, State1} ->
            State2 = State1#script_state{exec_stack = ExRest},
            execute(Rest, Pos + 1, State2);
        Error -> Error
    end;

%% --- OP_VERIFY ---
execute(<<?OP_VERIFY, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                true ->
                    case pop(State1) of
                        {ok, Top, State2} ->
                            case script_bool(Top) of
                                true -> execute(Rest, Pos + 1, State2);
                                false -> {error, verify_failed}
                            end;
                        Error -> Error
                    end;
                false ->
                    execute(Rest, Pos + 1, State1)
            end;
        Error -> Error
    end;

%% --- OP_RETURN ---
execute(<<?OP_RETURN, Rest/binary>>, Pos, State) ->
    case executing(State) of
        true -> {error, op_return};
        false -> execute(Rest, Pos + 1, State)
    end;

%% --- Stack operations ---
execute(<<?OP_TOALTSTACK, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(toaltstack, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_FROMALTSTACK, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(fromaltstack, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_2DROP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op('2drop', Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_2DUP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op('2dup', Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_3DUP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op('3dup', Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_2OVER, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op('2over', Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_2ROT, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op('2rot', Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_2SWAP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op('2swap', Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_IFDUP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(ifdup, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_DEPTH, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(depth, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_DROP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(drop, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_DUP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(dup, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_NIP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(nip, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_OVER, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(over, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_PICK, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(pick, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_ROLL, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(roll, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_ROT, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(rot, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_SWAP, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(swap, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_TUCK, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(tuck, Rest, Pos + 1, State1);
        Error -> Error
    end;
execute(<<?OP_SIZE, Rest/binary>>, Pos, State) ->
    case count_op(State) of
        {ok, State1} -> execute_stack_op(size, Rest, Pos + 1, State1);
        Error -> Error
    end;

%% --- Disabled opcodes ---
execute(<<Op, _Rest/binary>>, _Pos, #script_state{sig_version = SigVer} = _State)
  when is_integer(Op) ->
    case is_disabled_opcode(Op) of
        true when SigVer =/= tapscript ->
            {error, disabled_opcode};
        _ ->
            execute_remaining(Op, _Rest, _Pos, _State)
    end;

execute(_, _Pos, _State) ->
    {error, invalid_script}.

%%% -------------------------------------------------------------------
%%% Remaining opcodes dispatch
%%% -------------------------------------------------------------------

execute_remaining(Op, Rest, Pos, State) ->
    case Op of
        ?OP_EQUAL -> execute_equal(Rest, Pos + 1, State);
        ?OP_EQUALVERIFY -> execute_equalverify(Rest, Pos + 1, State);
        _ when Op >= ?OP_1ADD, Op =< ?OP_WITHIN ->
            execute_arith(Op, Rest, Pos + 1, State);
        ?OP_RIPEMD160 -> execute_hash(ripemd160, Rest, Pos + 1, State);
        ?OP_SHA1 -> execute_hash(sha1, Rest, Pos + 1, State);
        ?OP_SHA256 -> execute_hash(sha256, Rest, Pos + 1, State);
        ?OP_HASH160 -> execute_hash(hash160, Rest, Pos + 1, State);
        ?OP_HASH256 -> execute_hash(hash256, Rest, Pos + 1, State);
        ?OP_CODESEPARATOR -> execute_codesep(Rest, Pos + 1, State);
        ?OP_CHECKSIG -> execute_checksig(Rest, Pos + 1, State);
        ?OP_CHECKSIGVERIFY -> execute_checksigverify(Rest, Pos + 1, State);
        ?OP_CHECKMULTISIG -> execute_checkmultisig(Rest, Pos + 1, State);
        ?OP_CHECKMULTISIGVERIFY -> execute_checkmultisigverify(Rest, Pos + 1, State);
        ?OP_CHECKLOCKTIMEVERIFY -> execute_cltv(Rest, Pos + 1, State);
        ?OP_CHECKSEQUENCEVERIFY -> execute_csv(Rest, Pos + 1, State);
        ?OP_CHECKSIGADD -> execute_checksigadd(Rest, Pos + 1, State);
        Nop when Nop =:= ?OP_NOP1;
                 Nop >= ?OP_NOP4, Nop =< ?OP_NOP10 ->
            execute_nop(Rest, Pos + 1, State);
        _ ->
            {error, {unknown_opcode, Op}}
    end.

%%% -------------------------------------------------------------------
%%% Pushdata helper
%%% -------------------------------------------------------------------

execute_pushdata(Len, Bin, Pos, State) ->
    case Bin of
        <<Data:Len/binary, Rest/binary>> ->
            case executing(State) of
                true ->
                    case check_push_size(Data, State) of
                        ok ->
                            State1 = push(Data, State),
                            case check_stack_size(State1) of
                                true -> execute(Rest, Pos + Len, State1);
                                false -> {error, stack_overflow}
                            end;
                        Error -> Error
                    end;
                false ->
                    execute(Rest, Pos + Len, State)
            end;
        _ ->
            {error, script_truncated}
    end.

check_push_size(Data, #script_state{sig_version = tapscript}) ->
    %% tapscript: max push size is 520 bytes
    case byte_size(Data) > ?MAX_SCRIPT_ELEMENT_SIZE of
        true -> {error, push_size_exceeded};
        false -> ok
    end;
check_push_size(Data, _State) ->
    case byte_size(Data) > ?MAX_SCRIPT_ELEMENT_SIZE of
        true -> {error, push_size_exceeded};
        false -> ok
    end.

%%% -------------------------------------------------------------------
%%% IF/NOTIF execution
%%% -------------------------------------------------------------------

execute_if(ExpectTrue, Rest, Pos, State) ->
    case executing(State) of
        true ->
            case pop(State) of
                {ok, Cond, State1} ->
                    Bool = case State1#script_state.sig_version of
                        tapscript ->
                            %% MINIMALIF is always on in tapscript
                            case Cond of
                                <<>> -> false;
                                <<1>> -> true;
                                _ -> error
                            end;
                        _ ->
                            case (State1#script_state.flags band
                                  ?SCRIPT_VERIFY_MINIMALIF) =/= 0 of
                                true ->
                                    case Cond of
                                        <<>> -> false;
                                        <<1>> -> true;
                                        _ -> error
                                    end;
                                false ->
                                    script_bool(Cond)
                            end
                    end,
                    case Bool of
                        error ->
                            {error, minimalif_failed};
                        _ ->
                            Exec = case ExpectTrue of
                                true -> Bool;
                                false -> not Bool
                            end,
                            ExecStack = [Exec | State1#script_state.exec_stack],
                            execute(Rest, Pos,
                                    State1#script_state{exec_stack = ExecStack})
                    end;
                Error -> Error
            end;
        false ->
            %% not executing, just push false onto exec stack
            ExecStack = [false | State#script_state.exec_stack],
            execute(Rest, Pos, State#script_state{exec_stack = ExecStack})
    end.

%%% -------------------------------------------------------------------
%%% Stack operations implementation
%%% -------------------------------------------------------------------

execute_stack_op(Op, Rest, Pos, State) ->
    case executing(State) of
        false -> execute(Rest, Pos, State);
        true -> do_stack_op(Op, Rest, Pos, State)
    end.

do_stack_op(toaltstack, Rest, Pos, State) ->
    case pop(State) of
        {ok, Top, State1} ->
            State2 = State1#script_state{
                altstack = [Top | State1#script_state.altstack]
            },
            execute(Rest, Pos, State2);
        Error -> Error
    end;
do_stack_op(fromaltstack, _Rest, _Pos, #script_state{altstack = []} = _State) ->
    {error, altstack_underflow};
do_stack_op(fromaltstack, Rest, Pos,
            #script_state{altstack = [Top | AltRest]} = State) ->
    State1 = push(Top, State#script_state{altstack = AltRest}),
    execute(Rest, Pos, State1);
do_stack_op('2drop', Rest, Pos, State) ->
    case pop(State) of
        {ok, _, State1} ->
            case pop(State1) of
                {ok, _, State2} -> execute(Rest, Pos, State2);
                Error -> Error
            end;
        Error -> Error
    end;
do_stack_op('2dup', Rest, Pos, #script_state{stack = [A, B | _]} = State) ->
    State1 = State#script_state{stack = [A, B | State#script_state.stack]},
    case check_stack_size(State1) of
        true -> execute(Rest, Pos, State1);
        false -> {error, stack_overflow}
    end;
do_stack_op('2dup', _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op('3dup', Rest, Pos, #script_state{stack = [A, B, C | _]} = State) ->
    State1 = State#script_state{stack = [A, B, C | State#script_state.stack]},
    case check_stack_size(State1) of
        true -> execute(Rest, Pos, State1);
        false -> {error, stack_overflow}
    end;
do_stack_op('3dup', _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op('2over', Rest, Pos, #script_state{stack = [_, _, C, D | _]} = State) ->
    State1 = State#script_state{stack = [C, D | State#script_state.stack]},
    case check_stack_size(State1) of
        true -> execute(Rest, Pos, State1);
        false -> {error, stack_overflow}
    end;
do_stack_op('2over', _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op('2rot', Rest, Pos,
            #script_state{stack = [A, B, C, D, E, F | Tail]} = State) ->
    State1 = State#script_state{stack = [E, F, A, B, C, D | Tail]},
    execute(Rest, Pos, State1);
do_stack_op('2rot', _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op('2swap', Rest, Pos,
            #script_state{stack = [A, B, C, D | Tail]} = State) ->
    State1 = State#script_state{stack = [C, D, A, B | Tail]},
    execute(Rest, Pos, State1);
do_stack_op('2swap', _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op(ifdup, Rest, Pos, State) ->
    case State#script_state.stack of
        [Top | _] ->
            case script_bool(Top) of
                true ->
                    State1 = push(Top, State),
                    case check_stack_size(State1) of
                        true -> execute(Rest, Pos, State1);
                        false -> {error, stack_overflow}
                    end;
                false ->
                    execute(Rest, Pos, State)
            end;
        [] -> {error, stack_underflow}
    end;
do_stack_op(depth, Rest, Pos, State) ->
    Depth = length(State#script_state.stack),
    State1 = push_num(Depth, State),
    execute(Rest, Pos, State1);
do_stack_op(drop, Rest, Pos, State) ->
    case pop(State) of
        {ok, _, State1} -> execute(Rest, Pos, State1);
        Error -> Error
    end;
do_stack_op(dup, Rest, Pos, #script_state{stack = [Top | _]} = State) ->
    State1 = push(Top, State),
    case check_stack_size(State1) of
        true -> execute(Rest, Pos, State1);
        false -> {error, stack_overflow}
    end;
do_stack_op(dup, _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op(nip, Rest, Pos, #script_state{stack = [A, _ | Tail]} = State) ->
    State1 = State#script_state{stack = [A | Tail]},
    execute(Rest, Pos, State1);
do_stack_op(nip, _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op(over, Rest, Pos, #script_state{stack = [_, B | _]} = State) ->
    State1 = push(B, State),
    case check_stack_size(State1) of
        true -> execute(Rest, Pos, State1);
        false -> {error, stack_overflow}
    end;
do_stack_op(over, _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op(pick, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, N, State1} when N >= 0 ->
            Stack = State1#script_state.stack,
            case N < length(Stack) of
                true ->
                    Item = lists:nth(N + 1, Stack),
                    State2 = push(Item, State1),
                    case check_stack_size(State2) of
                        true -> execute(Rest, Pos, State2);
                        false -> {error, stack_overflow}
                    end;
                false -> {error, stack_underflow}
            end;
        {ok, _, _} -> {error, invalid_stack_index};
        Error -> Error
    end;
do_stack_op(roll, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, N, State1} when N >= 0 ->
            Stack = State1#script_state.stack,
            case N < length(Stack) of
                true ->
                    Item = lists:nth(N + 1, Stack),
                    {Before, [_ | After]} = lists:split(N, Stack),
                    State2 = State1#script_state{stack = [Item | Before ++ After]},
                    execute(Rest, Pos, State2);
                false -> {error, stack_underflow}
            end;
        {ok, _, _} -> {error, invalid_stack_index};
        Error -> Error
    end;
do_stack_op(rot, Rest, Pos, #script_state{stack = [A, B, C | Tail]} = State) ->
    State1 = State#script_state{stack = [C, A, B | Tail]},
    execute(Rest, Pos, State1);
do_stack_op(rot, _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op(swap, Rest, Pos, #script_state{stack = [A, B | Tail]} = State) ->
    State1 = State#script_state{stack = [B, A | Tail]},
    execute(Rest, Pos, State1);
do_stack_op(swap, _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op(tuck, Rest, Pos, #script_state{stack = [A, B | Tail]} = State) ->
    State1 = State#script_state{stack = [A, B, A | Tail]},
    case check_stack_size(State1) of
        true -> execute(Rest, Pos, State1);
        false -> {error, stack_overflow}
    end;
do_stack_op(tuck, _Rest, _Pos, _State) ->
    {error, stack_underflow};
do_stack_op(size, Rest, Pos, #script_state{stack = [Top | _]} = State) ->
    Size = byte_size(Top),
    State1 = push_num(Size, State),
    case check_stack_size(State1) of
        true -> execute(Rest, Pos, State1);
        false -> {error, stack_overflow}
    end;
do_stack_op(size, _Rest, _Pos, _State) ->
    {error, stack_underflow}.

%%% -------------------------------------------------------------------
%%% OP_EQUAL / OP_EQUALVERIFY
%%% -------------------------------------------------------------------

execute_equal(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    case pop2(State1) of
                        {ok, A, B, State2} ->
                            Result = case A =:= B of
                                true -> script_true();
                                false -> script_false()
                            end,
                            State3 = push(Result, State2),
                            execute(Rest, Pos, State3);
                        Error -> Error
                    end
            end;
        Error -> Error
    end.

execute_equalverify(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    case pop2(State1) of
                        {ok, A, B, State2} ->
                            case A =:= B of
                                true -> execute(Rest, Pos, State2);
                                false -> {error, equalverify_failed}
                            end;
                        Error -> Error
                    end
            end;
        Error -> Error
    end.

%%% -------------------------------------------------------------------
%%% Arithmetic opcodes
%%% -------------------------------------------------------------------

execute_arith(Op, Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true -> do_arith(Op, Rest, Pos, State1)
            end;
        Error -> Error
    end.

%% Unary arithmetic
do_arith(?OP_1ADD, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, A, State1} -> execute(Rest, Pos, push_num(A + 1, State1));
        Error -> Error
    end;
do_arith(?OP_1SUB, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, A, State1} -> execute(Rest, Pos, push_num(A - 1, State1));
        Error -> Error
    end;
do_arith(?OP_NEGATE, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, A, State1} -> execute(Rest, Pos, push_num(-A, State1));
        Error -> Error
    end;
do_arith(?OP_ABS, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, A, State1} -> execute(Rest, Pos, push_num(abs(A), State1));
        Error -> Error
    end;
do_arith(?OP_NOT, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, 0, State1} -> execute(Rest, Pos, push_num(1, State1));
        {ok, _, State1} -> execute(Rest, Pos, push_num(0, State1));
        Error -> Error
    end;
do_arith(?OP_0NOTEQUAL, Rest, Pos, State) ->
    case pop_num(State) of
        {ok, 0, State1} -> execute(Rest, Pos, push_num(0, State1));
        {ok, _, State1} -> execute(Rest, Pos, push_num(1, State1));
        Error -> Error
    end;

%% Binary arithmetic
do_arith(?OP_ADD, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} -> execute(Rest, Pos, push_num(A + B, State1));
        Error -> Error
    end;
do_arith(?OP_SUB, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} -> execute(Rest, Pos, push_num(A - B, State1));
        Error -> Error
    end;
do_arith(?OP_BOOLAND, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            R = case A =/= 0 andalso B =/= 0 of
                true -> 1; false -> 0
            end,
            execute(Rest, Pos, push_num(R, State1));
        Error -> Error
    end;
do_arith(?OP_BOOLOR, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            R = case A =/= 0 orelse B =/= 0 of
                true -> 1; false -> 0
            end,
            execute(Rest, Pos, push_num(R, State1));
        Error -> Error
    end;
do_arith(?OP_NUMEQUAL, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            execute(Rest, Pos, push_num(case A =:= B of true -> 1; false -> 0 end, State1));
        Error -> Error
    end;
do_arith(?OP_NUMEQUALVERIFY, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            case A =:= B of
                true -> execute(Rest, Pos, State1);
                false -> {error, numequalverify_failed}
            end;
        Error -> Error
    end;
do_arith(?OP_NUMNOTEQUAL, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            execute(Rest, Pos, push_num(case A =/= B of true -> 1; false -> 0 end, State1));
        Error -> Error
    end;
do_arith(?OP_LESSTHAN, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            execute(Rest, Pos, push_num(case A < B of true -> 1; false -> 0 end, State1));
        Error -> Error
    end;
do_arith(?OP_GREATERTHAN, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            execute(Rest, Pos, push_num(case A > B of true -> 1; false -> 0 end, State1));
        Error -> Error
    end;
do_arith(?OP_LESSTHANOREQUAL, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            execute(Rest, Pos, push_num(case A =< B of true -> 1; false -> 0 end, State1));
        Error -> Error
    end;
do_arith(?OP_GREATERTHANOREQUAL, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} ->
            execute(Rest, Pos, push_num(case A >= B of true -> 1; false -> 0 end, State1));
        Error -> Error
    end;
do_arith(?OP_MIN, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} -> execute(Rest, Pos, push_num(min(A, B), State1));
        Error -> Error
    end;
do_arith(?OP_MAX, Rest, Pos, State) ->
    case pop_num2(State) of
        {ok, A, B, State1} -> execute(Rest, Pos, push_num(max(A, B), State1));
        Error -> Error
    end;
do_arith(?OP_WITHIN, Rest, Pos, State) ->
    case pop3(State) of
        {ok, X, Min, Max, State1} ->
            case decode_script_num(X, 4) of
                {ok, XN} ->
                    case decode_script_num(Min, 4) of
                        {ok, MinN} ->
                            case decode_script_num(Max, 4) of
                                {ok, MaxN} ->
                                    R = case MinN =< XN andalso XN < MaxN of
                                        true -> 1; false -> 0
                                    end,
                                    execute(Rest, Pos, push_num(R, State1));
                                Error -> Error
                            end;
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end;
do_arith(Op, _Rest, _Pos, _State) ->
    {error, {disabled_opcode, Op}}.

%%% -------------------------------------------------------------------
%%% Hash opcodes
%%% -------------------------------------------------------------------

execute_hash(HashType, Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    case pop(State1) of
                        {ok, Data, State2} ->
                            Hash = do_hash(HashType, Data),
                            State3 = push(Hash, State2),
                            execute(Rest, Pos, State3);
                        Error -> Error
                    end
            end;
        Error -> Error
    end.

do_hash(ripemd160, Data) -> crypto:hash(ripemd160, Data);
do_hash(sha1, Data) -> crypto:hash(sha, Data);
do_hash(sha256, Data) -> crypto:hash(sha256, Data);
do_hash(hash160, Data) -> beamchain_crypto:hash160(Data);
do_hash(hash256, Data) -> beamchain_crypto:hash256(Data).

%%% -------------------------------------------------------------------
%%% OP_CODESEPARATOR
%%% -------------------------------------------------------------------

execute_codesep(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    %% In tapscript, CONST_SCRIPTCODE flag makes this
                    %% fail when CONST_SCRIPTCODE is set... but actually
                    %% OP_CODESEPARATOR is valid in tapscript.
                    %% It fails in witness_v0 if CONST_SCRIPTCODE is set.
                    case State1#script_state.sig_version of
                        witness_v0 when
                            (State1#script_state.flags band
                             ?SCRIPT_VERIFY_CONST_SCRIPTCODE) =/= 0 ->
                            {error, op_codeseparator_in_witness};
                        _ ->
                            State2 = State1#script_state{codesep_pos = Pos},
                            execute(Rest, Pos, State2)
                    end
            end;
        Error -> Error
    end.

%%% -------------------------------------------------------------------
%%% OP_CHECKSIG (ECDSA for base/witness_v0, Schnorr for tapscript)
%%% -------------------------------------------------------------------

execute_checksig(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true -> do_checksig(Rest, Pos, State1)
            end;
        Error -> Error
    end.

do_checksig(Rest, Pos, #script_state{sig_version = tapscript} = State) ->
    do_checksig_tapscript(Rest, Pos, State);
do_checksig(Rest, Pos, State) ->
    do_checksig_ecdsa(Rest, Pos, State).

do_checksig_ecdsa(Rest, Pos, State) ->
    %% pop2 returns {ok, deeper, top, State} — deeper=Sig, top=PubKey
    case pop2(State) of
        {ok, Sig, PubKey, State1} ->
            case Sig of
                <<>> ->
                    %% empty sig = push false (no NULLFAIL issue with empty)
                    execute(Rest, Pos, push(script_false(), State1));
                _ ->
                    %% extract hash type (last byte)
                    SigLen = byte_size(Sig),
                    HashTypeByte = binary:at(Sig, SigLen - 1),
                    SigBody = binary:part(Sig, 0, SigLen - 1),
                    Flags = State1#script_state.flags,
                    %% check DER encoding
                    DerOk = case Flags band ?SCRIPT_VERIFY_DERSIG of
                        0 -> true;
                        _ -> beamchain_crypto:check_strict_der(SigBody)
                    end,
                    LowSOk = case Flags band ?SCRIPT_VERIFY_LOW_S of
                        0 -> true;
                        _ ->
                            case beamchain_crypto:decode_der_signature(SigBody) of
                                {ok, {_R, S}} -> beamchain_crypto:is_low_s(S);
                                _ -> false
                            end
                    end,
                    StrictEncOk = case Flags band ?SCRIPT_VERIFY_STRICTENC of
                        0 -> true;
                        _ -> check_hash_type(HashTypeByte) andalso
                             beamchain_crypto:validate_pubkey(PubKey)
                    end,
                    %% BIP 141: WITNESS_PUBKEYTYPE requires compressed pubkeys in witness v0
                    WitnessPubKeyTypeOk = case State1#script_state.sig_version of
                        witness_v0 ->
                            (Flags band ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) =:= 0 orelse
                            is_compressed_pubkey(PubKey);
                        _ -> true
                    end,
                    case DerOk andalso LowSOk andalso StrictEncOk andalso WitnessPubKeyTypeOk of
                        false when not WitnessPubKeyTypeOk ->
                            %% WITNESS_PUBKEYTYPE failure is always an error
                            {error, witness_pubkeytype};
                        false ->
                            case Flags band ?SCRIPT_VERIFY_NULLFAIL of
                                0 -> execute(Rest, Pos, push(script_false(), State1));
                                _ -> {error, sig_encoding}
                            end;
                        true ->
                            %% FindAndDelete: for legacy scripts, remove the
                            %% signature from the scriptCode before computing sighash
                            State2 = case State1#script_state.sig_version of
                                base ->
                                    S2 = find_and_delete(State1#script_state.script, Sig),
                                    State1#script_state{script = S2};
                                _ ->
                                    State1
                            end,
                            SigChecker = State2#script_state.sig_checker,
                            SigHash = compute_sig_hash(State2, HashTypeByte, Pos),
                            Valid = check_ecdsa_sig(SigChecker, SigBody, PubKey, SigHash),
                            case Valid of
                                true ->
                                    execute(Rest, Pos, push(script_true(), State1));
                                false ->
                                    case Flags band ?SCRIPT_VERIFY_NULLFAIL of
                                        0 ->
                                            execute(Rest, Pos,
                                                    push(script_false(), State1));
                                        _ ->
                                            {error, nullfail}
                                    end
                            end
                    end
            end;
        Error -> Error
    end.

do_checksig_tapscript(Rest, Pos, State) ->
    %% pop2 returns {ok, deeper, top, State} — deeper=Sig, top=PubKey
    case pop2(State) of
        {ok, Sig, PubKey, State1} ->
            case PubKey of
                <<>> ->
                    {error, tapscript_empty_pubkey};
                _ when byte_size(PubKey) =:= 32 ->
                    %% x-only pubkey: Schnorr verify
                    do_schnorr_checksig(Rest, Pos, PubKey, Sig, State1);
                _ ->
                    %% unknown pubkey type
                    Flags = State1#script_state.flags,
                    case Flags band ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE of
                        0 ->
                            %% unknown pubkey type succeeds
                            execute(Rest, Pos, push(script_true(), State1));
                        _ ->
                            {error, discourage_upgradable_pubkeytype}
                    end
            end;
        Error -> Error
    end.

do_schnorr_checksig(Rest, Pos, _PubKey, <<>>, State) ->
    %% empty sig = push false, don't consume sigops budget
    execute(Rest, Pos, push(script_false(), State));
do_schnorr_checksig(Rest, Pos, PubKey, Sig, State) ->
    {HashType, SigBytes} = case Sig of
        <<S:64/binary>> ->
            {?SIGHASH_DEFAULT, S};
        <<S:64/binary, HT:8>> when HT =/= 0 ->
            {HT, S};
        _ ->
            {invalid, <<>>}
    end,
    case HashType of
        invalid ->
            {error, invalid_schnorr_sig_size};
        _ ->
            %% consume sigops budget
            Budget = State#script_state.sigops_budget - 50,
            case Budget < 0 of
                true -> {error, tapscript_sigops_exceeded};
                false ->
                    State1 = State#script_state{sigops_budget = Budget},
                    SigChecker = State1#script_state.sig_checker,
                    SigHash = compute_taproot_sig_hash(State1, HashType, Pos),
                    Valid = check_schnorr_sig(SigChecker, SigBytes, PubKey, SigHash),
                    case Valid of
                        true ->
                            execute(Rest, Pos, push(script_true(), State1));
                        false ->
                            {error, schnorr_sig_failed}
                    end
            end
    end.

%%% -------------------------------------------------------------------
%%% OP_CHECKSIGVERIFY
%%% -------------------------------------------------------------------

execute_checksigverify(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    case do_checksig_result(State1, Pos) of
                        {ok, true, State2} ->
                            execute(Rest, Pos, State2);
                        {ok, false, _State2} ->
                            {error, checksigverify_failed};
                        {error, _} = E -> E
                    end
            end;
        Error -> Error
    end.

do_checksig_result(#script_state{sig_version = tapscript} = State, Pos) ->
    %% pop2 returns {ok, deeper, top, State} — deeper=Sig, top=PubKey
    case pop2(State) of
        {ok, Sig, PubKey, State1} ->
            case PubKey of
                <<>> ->
                    {error, tapscript_empty_pubkey};
                _ when byte_size(PubKey) =:= 32 ->
                    case Sig of
                        <<>> -> {ok, false, State1};
                        _ ->
                            {HashType, SigBytes} = parse_schnorr_sig(Sig),
                            case HashType of
                                invalid -> {error, invalid_schnorr_sig_size};
                                _ ->
                                    Budget = State1#script_state.sigops_budget - 50,
                                    case Budget < 0 of
                                        true -> {error, tapscript_sigops_exceeded};
                                        false ->
                                            State2 = State1#script_state{sigops_budget = Budget},
                                            SigHash = compute_taproot_sig_hash(State2, HashType, Pos),
                                            Valid = check_schnorr_sig(
                                                State2#script_state.sig_checker,
                                                SigBytes, PubKey, SigHash),
                                            {ok, Valid, State2}
                                    end
                            end
                    end;
                _ ->
                    Flags = State1#script_state.flags,
                    case Flags band ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE of
                        0 -> {ok, true, State1};
                        _ -> {error, discourage_upgradable_pubkeytype}
                    end
            end;
        Error -> Error
    end;
do_checksig_result(State, Pos) ->
    %% pop2 returns {ok, deeper, top, State} — deeper=Sig, top=PubKey
    case pop2(State) of
        {ok, Sig, PubKey, State1} ->
            Flags = State1#script_state.flags,
            %% BIP 141: WITNESS_PUBKEYTYPE requires compressed pubkeys in witness v0
            WitnessPubKeyTypeOk = case State1#script_state.sig_version of
                witness_v0 ->
                    (Flags band ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) =:= 0 orelse
                    is_compressed_pubkey(PubKey);
                _ -> true
            end,
            case WitnessPubKeyTypeOk of
                false ->
                    {error, witness_pubkeytype};
                true ->
                    case Sig of
                        <<>> -> {ok, false, State1};
                        _ ->
                            SigLen = byte_size(Sig),
                            HashTypeByte = binary:at(Sig, SigLen - 1),
                            SigBody = binary:part(Sig, 0, SigLen - 1),
                            %% FindAndDelete for legacy scripts
                            State2 = case State1#script_state.sig_version of
                                base ->
                                    S2 = find_and_delete(State1#script_state.script, Sig),
                                    State1#script_state{script = S2};
                                _ ->
                                    State1
                            end,
                            SigHash = compute_sig_hash(State2, HashTypeByte, Pos),
                            Valid = check_ecdsa_sig(
                                State2#script_state.sig_checker, SigBody, PubKey, SigHash),
                            case Valid of
                                false when (Flags band ?SCRIPT_VERIFY_NULLFAIL) =/= 0 ->
                                    {error, nullfail};
                                _ ->
                                    {ok, Valid, State1}
                            end
                    end
            end;
        Error -> Error
    end.

parse_schnorr_sig(<<S:64/binary>>) -> {?SIGHASH_DEFAULT, S};
parse_schnorr_sig(<<S:64/binary, HT:8>>) when HT =/= 0 -> {HT, S};
parse_schnorr_sig(_) -> {invalid, <<>>}.

%%% -------------------------------------------------------------------
%%% OP_CHECKMULTISIG
%%% -------------------------------------------------------------------

execute_checkmultisig(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    case State1#script_state.sig_version of
                        tapscript ->
                            %% OP_CHECKMULTISIG disabled in tapscript
                            {error, checkmultisig_in_tapscript};
                        _ ->
                            case do_checkmultisig_eval(State1, Pos) of
                                {ok, true, State2} ->
                                    execute(Rest, Pos, push(script_true(), State2));
                                {ok, false, State2} ->
                                    execute(Rest, Pos, push(script_false(), State2));
                                {error, _} = E -> E
                            end
                    end
            end;
        Error -> Error
    end.


verify_multisig_sigs(_PubKeys, [], _State, _Pos) ->
    true;
verify_multisig_sigs([], [_ | _], _State, _Pos) ->
    false;  %% more sigs than pubkeys remaining
verify_multisig_sigs([PK | PKRest], [Sig | SigRest] = Sigs, State, Pos) ->
    case Sig of
        <<>> ->
            %% empty sig always fails, try next pubkey
            verify_multisig_sigs(PKRest, Sigs, State, Pos);
        _ ->
            SigLen = byte_size(Sig),
            HashTypeByte = binary:at(Sig, SigLen - 1),
            SigBody = binary:part(Sig, 0, SigLen - 1),
            SigHash = compute_sig_hash(State, HashTypeByte, Pos),
            case check_ecdsa_sig(State#script_state.sig_checker, SigBody, PK, SigHash) of
                true ->
                    verify_multisig_sigs(PKRest, SigRest, State, Pos);
                false ->
                    case length(PKRest) >= length(Sigs) of
                        true ->
                            verify_multisig_sigs(PKRest, Sigs, State, Pos);
                        false ->
                            false
                    end
            end
    end.

execute_checkmultisigverify(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    case State1#script_state.sig_version of
                        tapscript ->
                            {error, checkmultisig_in_tapscript};
                        _ ->
                            case do_checkmultisig_eval(State1, Pos) of
                                {ok, true, State2} ->
                                    execute(Rest, Pos, State2);
                                {ok, false, _State2} ->
                                    {error, checkmultisigverify_failed};
                                {error, _} = E -> E
                            end
                    end
            end;
        Error -> Error
    end.

do_checkmultisig_eval(State, Pos) ->
    %% Evaluate multisig and return {ok, true/false, State} without calling execute.
    %% pop nkeys
    case pop_num(State) of
        {ok, NKeys, State1} when NKeys >= 0, NKeys =< ?MAX_PUBKEYS_PER_MULTISIG ->
            NewOpCount = State1#script_state.op_count + NKeys,
            case NewOpCount > ?MAX_OPS_PER_SCRIPT andalso
                 State1#script_state.sig_version =/= tapscript of
                true -> {error, op_count_exceeded};
                false ->
                    State2 = State1#script_state{op_count = NewOpCount},
                    case pop_n(NKeys, State2) of
                        {ok, PubKeys, State3} ->
                            Flags = State3#script_state.flags,
                            %% BIP 141: WITNESS_PUBKEYTYPE requires compressed pubkeys in witness v0
                            WitnessPubKeyTypeOk = case State3#script_state.sig_version of
                                witness_v0 when (Flags band ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) =/= 0 ->
                                    lists:all(fun is_compressed_pubkey/1, PubKeys);
                                _ -> true
                            end,
                            case WitnessPubKeyTypeOk of
                                false ->
                                    {error, witness_pubkeytype};
                                true ->
                            case pop_num(State3) of
                                {ok, NSigs, State4} when NSigs >= 0, NSigs =< NKeys ->
                                    case pop_n(NSigs, State4) of
                                        {ok, Sigs, State5} ->
                                            case pop(State5) of
                                                {ok, Dummy, State6} ->
                                                    case (Flags band ?SCRIPT_VERIFY_NULLDUMMY) =/= 0 andalso
                                                         Dummy =/= <<>> of
                                                        true -> {error, nulldummy_failed};
                                                        false ->
                                                            %% FindAndDelete: for legacy scripts, remove
                                                            %% all sigs from the scriptCode before verifying
                                                            State7 = case State6#script_state.sig_version of
                                                                base ->
                                                                    CleanedScript = lists:foldl(
                                                                        fun(S, Sc) -> find_and_delete(Sc, S) end,
                                                                        State6#script_state.script,
                                                                        Sigs),
                                                                    State6#script_state{script = CleanedScript};
                                                                _ ->
                                                                    State6
                                                            end,
                                                            Result = verify_multisig_sigs(
                                                                PubKeys, Sigs, State7, Pos),
                                                            case Result of
                                                                true ->
                                                                    {ok, true, State6};
                                                                false ->
                                                                    case (Flags band ?SCRIPT_VERIFY_NULLFAIL) =/= 0 andalso
                                                                         lists:any(fun(S) -> S =/= <<>> end, Sigs) of
                                                                        true -> {error, nullfail};
                                                                        false -> {ok, false, State6}
                                                                    end
                                                            end
                                                    end;
                                                Error -> Error
                                            end;
                                        Error -> Error
                                    end;
                                {ok, _, _} -> {error, invalid_multisig};
                                Error -> Error
                            end
                            end;
                        Error -> Error
                    end
            end;
        {ok, _, _} -> {error, invalid_multisig_key_count};
        Error -> Error
    end.

%%% -------------------------------------------------------------------
%%% OP_CHECKSIGADD (tapscript only, BIP 342)
%%% -------------------------------------------------------------------

execute_checksigadd(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    case State1#script_state.sig_version of
                        tapscript ->
                            do_checksigadd(Rest, Pos, State1);
                        _ ->
                            {error, {unknown_opcode, ?OP_CHECKSIGADD}}
                    end
            end;
        Error -> Error
    end.

do_checksigadd(Rest, Pos, State) ->
    %% stack: ... <sig> <n> <pubkey>  (pubkey is on top)
    case pop(State) of
        {ok, PubKey, State1} ->
            case pop_num(State1) of
                {ok, N, State2} ->
                    case pop(State2) of
                        {ok, Sig, State3} ->
                            case PubKey of
                                <<>> ->
                                    {error, tapscript_empty_pubkey};
                                _ when byte_size(PubKey) =:= 32 ->
                                    case Sig of
                                        <<>> ->
                                            %% empty sig = no contribution
                                            execute(Rest, Pos, push_num(N, State3));
                                        _ ->
                                            {HashType, SigBytes} = parse_schnorr_sig(Sig),
                                            case HashType of
                                                invalid ->
                                                    {error, invalid_schnorr_sig_size};
                                                _ ->
                                                    Budget = State3#script_state.sigops_budget - 50,
                                                    case Budget < 0 of
                                                        true -> {error, tapscript_sigops_exceeded};
                                                        false ->
                                                            State4 = State3#script_state{sigops_budget = Budget},
                                                            SigHash = compute_taproot_sig_hash(State4, HashType, Pos),
                                                            Valid = check_schnorr_sig(
                                                                State4#script_state.sig_checker,
                                                                SigBytes, PubKey, SigHash),
                                                            case Valid of
                                                                true ->
                                                                    execute(Rest, Pos, push_num(N + 1, State4));
                                                                false ->
                                                                    {error, schnorr_sig_failed}
                                                            end
                                                    end
                                            end
                                    end;
                                _ ->
                                    Flags = State3#script_state.flags,
                                    case Flags band ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE of
                                        0 ->
                                            case Sig of
                                                <<>> -> execute(Rest, Pos, push_num(N, State3));
                                                _ -> execute(Rest, Pos, push_num(N + 1, State3))
                                            end;
                                        _ ->
                                            {error, discourage_upgradable_pubkeytype}
                                    end
                            end;
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

%%% -------------------------------------------------------------------
%%% OP_CHECKLOCKTIMEVERIFY (BIP 65) / OP_CHECKSEQUENCEVERIFY (BIP 112)
%%% -------------------------------------------------------------------

execute_cltv(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    Flags = State1#script_state.flags,
                    case Flags band ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY of
                        0 ->
                            %% treat as NOP
                            execute(Rest, Pos, State1);
                        _ ->
                            %% peek at top (don't pop)
                            case State1#script_state.stack of
                                [Top | _] ->
                                    case decode_script_num(Top, 5) of
                                        {ok, N} when N < 0 ->
                                            {error, negative_locktime};
                                        {ok, N} ->
                                            SigChecker = State1#script_state.sig_checker,
                                            case check_locktime(SigChecker, N) of
                                                true -> execute(Rest, Pos, State1);
                                                false -> {error, locktime_failed}
                                            end;
                                        Error -> Error
                                    end;
                                [] -> {error, stack_underflow}
                            end
                    end
            end;
        Error -> Error
    end.

execute_csv(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            case executing(State1) of
                false -> execute(Rest, Pos, State1);
                true ->
                    Flags = State1#script_state.flags,
                    case Flags band ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY of
                        0 ->
                            %% treat as NOP
                            execute(Rest, Pos, State1);
                        _ ->
                            case State1#script_state.stack of
                                [Top | _] ->
                                    case decode_script_num(Top, 5) of
                                        {ok, N} when N < 0 ->
                                            {error, negative_sequence};
                                        {ok, N} ->
                                            %% If disable flag is set, treat as NOP
                                            case N band ?SEQUENCE_LOCKTIME_DISABLE_FLAG of
                                                0 ->
                                                    SigChecker = State1#script_state.sig_checker,
                                                    case check_sequence(SigChecker, N) of
                                                        true -> execute(Rest, Pos, State1);
                                                        false -> {error, sequence_failed}
                                                    end;
                                                _ ->
                                                    %% disable flag set, treat as NOP
                                                    execute(Rest, Pos, State1)
                                            end;
                                        Error -> Error
                                    end;
                                [] -> {error, stack_underflow}
                            end
                    end
            end;
        Error -> Error
    end.

%%% -------------------------------------------------------------------
%%% NOP opcodes
%%% -------------------------------------------------------------------

execute_nop(Rest, Pos, State) ->
    case count_op(State) of
        {ok, State1} ->
            Flags = State1#script_state.flags,
            case Flags band ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS of
                0 -> execute(Rest, Pos, State1);
                _ -> {error, discourage_upgradable_nops}
            end;
        Error -> Error
    end.

%%% -------------------------------------------------------------------
%%% Pop N items from stack
%%% -------------------------------------------------------------------

pop_n(0, State) ->
    {ok, [], State};
pop_n(N, State) when N > 0 ->
    case pop(State) of
        {ok, Item, State1} ->
            case pop_n(N - 1, State1) of
                {ok, Items, State2} -> {ok, [Item | Items], State2};
                Error -> Error
            end;
        Error -> Error
    end.

%%% -------------------------------------------------------------------
%%% Signature checking delegation to sig_checker
%%% -------------------------------------------------------------------

%% The sig_checker is either a fun or a map with callback functions.
%% We'll define it as a map: #{check_sig => Fun, check_locktime => Fun, ...}
%% Or for simplicity, a tuple {Module, State} where Module exports callbacks.
%%
%% For now, support map-based checker:
%%   #{check_ecdsa_sig => fun(Sig, PubKey, SigHash) -> boolean(),
%%     check_schnorr_sig => fun(Sig, PubKey, SigHash) -> boolean(),
%%     check_locktime => fun(LockTime) -> boolean(),
%%     check_sequence => fun(Sequence) -> boolean(),
%%     compute_sighash => fun(HashType, SigVersion, CodeSepPos) -> binary(),
%%     compute_taproot_sighash => fun(HashType, CodeSepPos) -> binary()}

check_ecdsa_sig(#{check_ecdsa_sig := Fun}, Sig, PubKey, SigHash) ->
    Fun(Sig, PubKey, SigHash);
check_ecdsa_sig({_Tx, _Idx, _Amt, _PrevOuts}, Sig, PubKey, SigHash) ->
    beamchain_crypto:ecdsa_verify_cached(SigHash, Sig, PubKey);
check_ecdsa_sig({_Tx, _Idx, _Amt}, Sig, PubKey, SigHash) ->
    beamchain_crypto:ecdsa_verify_cached(SigHash, Sig, PubKey);
check_ecdsa_sig(_, _Sig, _PubKey, _SigHash) ->
    false.

check_schnorr_sig(#{check_schnorr_sig := Fun}, Sig, PubKey, SigHash) ->
    Fun(Sig, PubKey, SigHash);
check_schnorr_sig({_Tx, _Idx, _Amt, _PrevOuts}, Sig, PubKey, SigHash) ->
    beamchain_crypto:schnorr_verify_cached(SigHash, Sig, PubKey);
check_schnorr_sig({_Tx, _Idx, _Amt}, Sig, PubKey, SigHash) ->
    beamchain_crypto:schnorr_verify_cached(SigHash, Sig, PubKey);
check_schnorr_sig(_, _Sig, _PubKey, _SigHash) ->
    false.

check_locktime(#{check_locktime := Fun}, LockTime) ->
    Fun(LockTime);
check_locktime({Tx, InputIndex, _Amt, _PrevOuts}, LockTime) ->
    check_locktime_impl(Tx, InputIndex, LockTime);
check_locktime({Tx, InputIndex, _Amt}, LockTime) ->
    check_locktime_impl(Tx, InputIndex, LockTime);
check_locktime(_, _LockTime) ->
    false.

check_locktime_impl(Tx, InputIndex, LockTime) ->
    TxLockTime = Tx#transaction.locktime,
    %% Locktime type must match (both height or both time)
    SameType = (LockTime < ?LOCKTIME_THRESHOLD andalso TxLockTime < ?LOCKTIME_THRESHOLD) orelse
               (LockTime >= ?LOCKTIME_THRESHOLD andalso TxLockTime >= ?LOCKTIME_THRESHOLD),
    case SameType of
        false -> false;
        true ->
            case LockTime > TxLockTime of
                true -> false;
                false ->
                    %% nSequence must not be 0xffffffff (which disables locktime)
                    Input = lists:nth(InputIndex + 1, Tx#transaction.inputs),
                    Input#tx_in.sequence =/= 16#ffffffff
            end
    end.

check_sequence(#{check_sequence := Fun}, Sequence) ->
    Fun(Sequence);
check_sequence({Tx, InputIndex, _Amt, _PrevOuts}, Sequence) ->
    check_sequence_impl(Tx, InputIndex, Sequence);
check_sequence({Tx, InputIndex, _Amt}, Sequence) ->
    check_sequence_impl(Tx, InputIndex, Sequence);
check_sequence(_, _Sequence) ->
    false.

check_sequence_impl(Tx, InputIndex, Sequence) ->
    %% BIP 112: tx version must be >= 2
    case Tx#transaction.version < 2 of
        true -> false;
        false ->
            Input = lists:nth(InputIndex + 1, Tx#transaction.inputs),
            TxSeq = Input#tx_in.sequence,
            %% Input sequence disable flag must NOT be set
            case (TxSeq band ?SEQUENCE_LOCKTIME_DISABLE_FLAG) =/= 0 of
                true -> false;
                false ->
                    %% Type flags must match
                    SeqType = Sequence band ?SEQUENCE_LOCKTIME_TYPE_FLAG,
                    TxType = TxSeq band ?SEQUENCE_LOCKTIME_TYPE_FLAG,
                    case SeqType =:= TxType of
                        false -> false;
                        true ->
                            %% Compare masked values
                            SeqVal = Sequence band ?SEQUENCE_LOCKTIME_MASK,
                            TxVal = TxSeq band ?SEQUENCE_LOCKTIME_MASK,
                            SeqVal =< TxVal
                    end
            end
    end.

compute_sig_hash(#script_state{sig_checker = #{compute_sighash := Fun}},
                 HashType, CodeSepPos) ->
    Fun(HashType, CodeSepPos);
compute_sig_hash(#script_state{sig_checker = {Tx, InputIndex, Amount, _PrevOuts},
                               sig_version = SigVersion,
                               script = Script,
                               codesep_pos = CodesepPos},
                 HashType, _Pos) ->
    ScriptCode = subscript_from_codesep(Script, CodesepPos),
    case SigVersion of
        witness_v0 ->
            sighash_witness_v0(Tx, InputIndex, ScriptCode, Amount, HashType);
        _ ->
            sighash_legacy(Tx, InputIndex, ScriptCode, HashType)
    end;
compute_sig_hash(#script_state{sig_checker = {Tx, InputIndex, Amount},
                               sig_version = SigVersion,
                               script = Script,
                               codesep_pos = CodesepPos},
                 HashType, _Pos) ->
    ScriptCode = subscript_from_codesep(Script, CodesepPos),
    case SigVersion of
        witness_v0 ->
            sighash_witness_v0(Tx, InputIndex, ScriptCode, Amount, HashType);
        _ ->
            sighash_legacy(Tx, InputIndex, ScriptCode, HashType)
    end;
compute_sig_hash(_, _, _) ->
    <<0:256>>.

compute_taproot_sig_hash(#script_state{sig_checker = #{compute_taproot_sighash := Fun}},
                         HashType, CodeSepPos) ->
    Fun(HashType, CodeSepPos);
compute_taproot_sig_hash(#script_state{sig_checker = {Tx, InputIndex, _Amount, PrevOuts},
                                       script = Script,
                                       codesep_pos = CodesepPos},
                         HashType, _Pos) ->
    %% For tapscript, compute leaf hash from the executing script
    LeafHash = beamchain_crypto:tagged_hash(
        <<"TapLeaf">>,
        <<16#c0, (encode_compact_size(byte_size(Script)))/binary, Script/binary>>),
    sighash_taproot(Tx, InputIndex, PrevOuts, HashType, undefined, LeafHash, CodesepPos);
compute_taproot_sig_hash(_, _, _) ->
    <<0:256>>.

check_hash_type(HT) ->
    Base = HT band (bnot ?SIGHASH_ANYONECANPAY),
    Base >= ?SIGHASH_ALL andalso Base =< ?SIGHASH_SINGLE.

%%% -------------------------------------------------------------------
%%% Top-level script verification
%%% -------------------------------------------------------------------

-spec verify_script(binary(), binary(), [binary()],
                    non_neg_integer(), term()) -> boolean().
verify_script(ScriptSig, ScriptPubKey, Witness, Flags, SigChecker) ->
    try
        Result = do_verify_script(ScriptSig, ScriptPubKey, Witness, Flags, SigChecker),
        case Result of
            false ->
                logger:error("verify_script returned false for ~s",
                             [binary:encode_hex(ScriptPubKey)]);
            _ -> ok
        end,
        Result
    catch
        Class:Reason:Stack ->
            logger:error("verify_script exception: ~p:~p stack=~p "
                         "scriptPubKey=~s",
                         [Class, Reason, lists:sublist(Stack, 3),
                          binary:encode_hex(ScriptPubKey)]),
            false
    end.

do_verify_script(ScriptSig, ScriptPubKey, Witness, Flags, SigChecker) ->
    %% SIGPUSHONLY: scriptSig must contain only push ops
    case (Flags band ?SCRIPT_VERIFY_SIGPUSHONLY) =/= 0 of
        true ->
            case is_push_only(ScriptSig) of
                true -> ok;
                false -> throw(sig_pushonly)
            end;
        false -> ok
    end,
    %% Step 1: Execute ScriptSig
    case eval_script(ScriptSig, [], Flags, SigChecker, base) of
        {ok, Stack1} ->
            StackCopy = Stack1,
            %% Step 2: Execute ScriptPubKey with resulting stack
            case eval_script(ScriptPubKey, Stack1, Flags, SigChecker, base) of
                {ok, []} ->
                    logger:debug("verify: scriptPubKey left empty stack"),
                    false;
                {ok, Stack2} ->
                    [Top | _] = Stack2,
                    case script_bool(Top) of
                        false -> false;
                        true ->
                            %% Step 3: P2SH evaluation
                            IsP2SH = (Flags band ?SCRIPT_VERIFY_P2SH) =/= 0 andalso
                                     is_p2sh(ScriptPubKey),
                            Stack3 = case IsP2SH of
                                true ->
                                    %% BIP 16: P2SH scriptSig must be push-only (unconditional)
                                    case is_push_only(ScriptSig) of
                                        false -> throw(sig_pushonly);
                                        true -> ok
                                    end,
                                    %% The serialized script is top of StackCopy
                                    case StackCopy of
                                        [] -> throw(p2sh_no_script);
                                        [RedeemScript | StackRest] ->
                                            case eval_script(RedeemScript, StackRest,
                                                           Flags, SigChecker, base) of
                                                {ok, []} -> throw(p2sh_empty_stack);
                                                {ok, S} ->
                                                    case script_bool(hd(S)) of
                                                        true -> S;
                                                        false -> throw(p2sh_failed)
                                                    end;
                                                {error, E} -> throw(E)
                                            end
                                    end;
                                false ->
                                    Stack2
                            end,
                            %% Step 4: Witness program check
                            WitnessProg = extract_witness_program(ScriptPubKey),
                            WitnessResult = case WitnessProg of
                                {ok, WitVer, WitProg} when
                                    (Flags band ?SCRIPT_VERIFY_WITNESS) =/= 0 ->
                                    verify_witness_program(
                                        WitVer, WitProg, Witness,
                                        Flags, SigChecker);
                                _ ->
                                    %% Check if P2SH redeem script is witness program
                                    check_p2sh_witness(IsP2SH, StackCopy,
                                        Witness, Flags, SigChecker, Stack3)
                            end,
                            case WitnessResult of
                                {ok, FinalStack} ->
                                    %% CLEANSTACK check
                                    case (Flags band ?SCRIPT_VERIFY_CLEANSTACK) =/= 0 of
                                        true ->
                                            length(FinalStack) =:= 1;
                                        false ->
                                            true
                                    end;
                                {error, WE} ->
                                    logger:error("verify: witness error=~p "
                                                 "scriptPubKey=~s",
                                                 [WE, binary:encode_hex(ScriptPubKey)]),
                                    false
                            end
                    end;
                {error, SPKErr} ->
                    logger:error("verify: scriptPubKey eval error=~p",
                                 [SPKErr]),
                    false
            end;
        {error, _} ->
            false
    end.

%%% -------------------------------------------------------------------
%%% Witness program verification
%%% -------------------------------------------------------------------

verify_witness_program(0, Program, Witness, Flags, SigChecker)
  when byte_size(Program) =:= 20 ->
    %% P2WPKH
    case Witness of
        [Sig, PubKey] ->
            %% BIP 141: WITNESS_PUBKEYTYPE requires compressed pubkeys in witness v0
            case (Flags band ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) =/= 0 andalso
                 not is_compressed_pubkey(PubKey) of
                true ->
                    {error, witness_pubkeytype};
                false ->
                    %% construct P2PKH script from the 20-byte program
                    Script = <<?OP_DUP, ?OP_HASH160,
                               20, Program/binary,
                               ?OP_EQUALVERIFY, ?OP_CHECKSIG>>,
                    %% Add MINIMALIF for witness execution (prevents third-party malleability)
                    WitnessFlags = Flags bor ?SCRIPT_VERIFY_MINIMALIF,
                    %% Stack: PubKey on top (HEAD), Sig below — matches P2PKH expectations
                    P2WPKHResult = eval_script(Script, [PubKey, Sig], WitnessFlags, SigChecker, witness_v0),
                    case P2WPKHResult of
                        {ok, [Top]} ->
                            case script_bool(Top) of
                                true -> {ok, [Top]};
                                false -> {error, witness_program_failed}
                            end;
                        {ok, S} ->
                            logger:error("P2WPKH: unexpected stack len=~B", [length(S)]),
                            {error, witness_cleanstack};
                        {error, E} ->
                            logger:error("P2WPKH eval failed: ~p pubkey=~s",
                                         [E, binary:encode_hex(PubKey)]),
                            {error, E}
                    end
            end;
        _ ->
            {error, witness_program_mismatch}
    end;

verify_witness_program(0, Program, Witness, Flags, SigChecker)
  when byte_size(Program) =:= 32 ->
    %% P2WSH
    case Witness of
        [] -> {error, witness_program_empty};
        _ ->
            WitnessScript = lists:last(Witness),
            StackItems = lists:droplast(Witness),
            %% SHA256(witness_script) must equal program
            case crypto:hash(sha256, WitnessScript) =:= Program of
                true ->
                    case byte_size(WitnessScript) > ?MAX_SCRIPT_SIZE of
                        true -> {error, witness_script_too_large};
                        false ->
                            %% Add MINIMALIF for witness execution (prevents third-party malleability)
                            WitnessFlags = Flags bor ?SCRIPT_VERIFY_MINIMALIF,
                            %% Reverse stack items: wire order is bottom-to-top,
                            %% but our list HEAD = top of stack
                            case eval_script(WitnessScript, lists:reverse(StackItems),
                                           WitnessFlags, SigChecker, witness_v0) of
                                {ok, [Top]} ->
                                    case script_bool(Top) of
                                        true -> {ok, [Top]};
                                        false -> {error, witness_program_failed}
                                    end;
                                {ok, _} -> {error, witness_cleanstack};
                                {error, _} = E -> E
                            end
                    end;
                false ->
                    {error, witness_program_mismatch}
            end
    end;

verify_witness_program(1, Program, Witness, Flags, SigChecker)
  when byte_size(Program) =:= 32,
       (Flags band ?SCRIPT_VERIFY_TAPROOT) =/= 0 ->
    %% P2TR (Taproot)
    verify_taproot(Program, Witness, Flags, SigChecker);

verify_witness_program(Version, _Program, Witness, Flags, _SigChecker)
  when Version >= 2, Version =< 16 ->
    %% future witness versions
    case (Flags band ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) =/= 0 of
        true -> {error, discourage_upgradable_witness_program};
        false ->
            %% unknown witness version succeeds
            case Witness of
                [] -> {error, witness_program_empty};
                _ -> {ok, [script_true()]}
            end
    end;

verify_witness_program(1, Program, _Witness, Flags, _SigChecker)
  when byte_size(Program) =:= 32,
       (Flags band ?SCRIPT_VERIFY_TAPROOT) =:= 0 ->
    %% taproot not active yet, succeed
    {ok, [script_true()]};

verify_witness_program(1, Program, _Witness, Flags, _SigChecker)
  when byte_size(Program) =/= 32,
       (Flags band ?SCRIPT_VERIFY_TAPROOT) =/= 0 ->
    %% BIP 341: v1 witness programs that are NOT 32 bytes are reserved
    %% for future extensions and succeed unconditionally (unencumbered).
    case (Flags band ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) =/= 0 of
        true -> {error, discourage_upgradable_witness_program};
        false -> {ok, [script_true()]}
    end;

verify_witness_program(_, _, _, _, _) ->
    {error, witness_program_wrong_length}.

%%% -------------------------------------------------------------------
%%% Taproot verification
%%% -------------------------------------------------------------------

verify_taproot(OutputKey, Witness, Flags, SigChecker) ->
    %% Check for annex (last witness item starting with 0x50)
    {CleanWitness, _Annex} = strip_annex(Witness),
    case CleanWitness of
        [] ->
            {error, witness_program_empty};
        [Sig] ->
            %% Key path spend
            verify_taproot_key_path(OutputKey, Sig, Flags, SigChecker);
        _ ->
            %% Script path spend
            %% Last two items: script and control block
            Script = lists:nth(length(CleanWitness) - 1, CleanWitness),
            ControlBlock = lists:last(CleanWitness),
            ScriptArgs = lists:sublist(CleanWitness, length(CleanWitness) - 2),
            verify_taproot_script_path(
                OutputKey, Script, ControlBlock, ScriptArgs, Flags, SigChecker)
    end.

strip_annex(Witness) when length(Witness) >= 2 ->
    Last = lists:last(Witness),
    case Last of
        <<16#50, _/binary>> ->
            {lists:droplast(Witness), Last};
        _ ->
            {Witness, undefined}
    end;
strip_annex(Witness) ->
    {Witness, undefined}.

verify_taproot_key_path(OutputKey, Sig, _Flags, SigChecker) ->
    {HashType, SigBytes} = parse_schnorr_sig(Sig),
    case HashType of
        invalid ->
            {error, invalid_schnorr_sig_size};
        _ ->
            SigHash = case SigChecker of
                #{compute_taproot_sighash := Fun} ->
                    Fun(HashType, 16#ffffffff);
                {Tx, InputIndex, _Amt, PrevOuts} ->
                    %% Key path: no leaf hash, no annex
                    sighash_taproot(Tx, InputIndex, PrevOuts, HashType,
                                    undefined, undefined, 16#ffffffff);
                _ ->
                    <<0:256>>
            end,
            case check_schnorr_sig(SigChecker, SigBytes, OutputKey, SigHash) of
                true -> {ok, [script_true()]};
                false -> {error, taproot_sig_failed}
            end
    end.

verify_taproot_script_path(OutputKey, Script, ControlBlock,
                           ScriptArgs, Flags, SigChecker) ->
    %% Validate control block
    CBLen = byte_size(ControlBlock),
    case CBLen >= 33 andalso (CBLen - 33) rem 32 =:= 0 of
        false ->
            {error, invalid_control_block};
        true ->
            <<LeafVersionByte:8, InternalKey:32/binary, MerklePath/binary>> = ControlBlock,
            %% BIP 341: leaf version = c[0] & 0xFE (strip output key parity bit)
            LeafVersion = LeafVersionByte band 16#fe,
            %% Compute leaf hash
            ScriptLen = byte_size(Script),
            LeafData = <<LeafVersion, (encode_compact_size(ScriptLen))/binary, Script/binary>>,
            LeafHash = beamchain_crypto:tagged_hash(<<"TapLeaf">>, LeafData),
            %% Walk merkle path
            MerkleRoot = compute_taproot_merkle(LeafHash, MerklePath),
            %% Compute tweak
            TweakHash = beamchain_crypto:tagged_hash(
                <<"TapTweak">>,
                <<InternalKey/binary, MerkleRoot/binary>>),
            %% Verify tweaked key matches output key
            case beamchain_crypto:xonly_pubkey_tweak_add(InternalKey, TweakHash) of
                {ok, TweakedKey, _Parity} ->
                    case TweakedKey =:= OutputKey of
                        true ->
                            %% Execute script in tapscript mode
                            TapLeafVer = LeafVersion,
                            case TapLeafVer of
                                16#c0 ->
                                    %% Known leaf version (tapscript)
                                    WitnessSize = lists:foldl(
                                        fun(W, Acc) -> Acc + byte_size(W) end,
                                        0, ScriptArgs),
                                    Budget = WitnessSize,
                                    %% Reverse: wire order is bottom-to-top,
                                    %% our list HEAD = top of stack
                                    eval_tapscript(Script, lists:reverse(ScriptArgs),
                                                  Budget, Flags, SigChecker);
                                _ ->
                                    case (Flags band ?SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) =/= 0 of
                                        true ->
                                            {error, discourage_upgradable_taproot_version};
                                        false ->
                                            {ok, [script_true()]}
                                    end
                            end;
                        false ->
                            {error, taproot_commitment_mismatch}
                    end;
                {error, _} ->
                    {error, taproot_tweak_failed}
            end
    end.

eval_tapscript(Script, Stack, SigopsBudget, Flags, SigChecker) ->
    State0 = #script_state{
        stack = Stack,
        flags = Flags,
        sig_checker = SigChecker,
        sig_version = tapscript,
        script = Script,
        sigops_budget = SigopsBudget
    },
    %% check for OP_SUCCESS first
    case check_op_success(Script, Flags) of
        {success, true} ->
            {ok, [script_true()]};
        {error, _} = E ->
            E;
        ok ->
            case execute(Script, 0, State0) of
                {ok, [Top]} ->
                    case script_bool(Top) of
                        true -> {ok, [Top]};
                        false -> {error, tapscript_failed}
                    end;
                {ok, []} ->
                    {error, tapscript_empty_stack};
                {ok, _} ->
                    {error, tapscript_cleanstack};
                {error, _} = E ->
                    E
            end
    end.

compute_taproot_merkle(Current, <<>>) ->
    Current;
compute_taproot_merkle(Current, <<Node:32/binary, Rest/binary>>) ->
    %% lexicographic ordering for the pair
    Combined = case Current =< Node of
        true -> <<Current/binary, Node/binary>>;
        false -> <<Node/binary, Current/binary>>
    end,
    Next = beamchain_crypto:tagged_hash(<<"TapBranch">>, Combined),
    compute_taproot_merkle(Next, Rest).

encode_compact_size(N) ->
    beamchain_serialize:encode_varint(N).

encode_outpoint(#outpoint{hash = Hash, index = Index}) ->
    <<Hash/binary, Index:32/little>>.

%%% -------------------------------------------------------------------
%%% Witness program extraction
%%% -------------------------------------------------------------------

extract_witness_program(<<Version, PushLen, Program/binary>>)
  when Version =:= ?OP_0 orelse (Version >= ?OP_1 andalso Version =< ?OP_16),
       PushLen >= 2, PushLen =< 40,
       byte_size(Program) =:= PushLen ->
    WitVer = case Version of
        ?OP_0 -> 0;
        _ -> Version - ?OP_1 + 1
    end,
    {ok, WitVer, Program};
extract_witness_program(_) ->
    none.

%%% -------------------------------------------------------------------
%%% P2SH detection
%%% -------------------------------------------------------------------

is_p2sh(<<16#a9, 16#14, _:20/binary, 16#87>>) -> true;
is_p2sh(_) -> false.

check_p2sh_witness(true, [RS | _], Witness, Flags, SigChecker, _Stack3) ->
    case extract_witness_program(RS) of
        {ok, WV, WP} when (Flags band ?SCRIPT_VERIFY_WITNESS) =/= 0 ->
            verify_witness_program(WV, WP, Witness, Flags, SigChecker);
        _ ->
            {ok, _Stack3}
    end;
check_p2sh_witness(_, _, _, _, _, Stack3) ->
    {ok, Stack3}.

%%% -------------------------------------------------------------------
%%% Push-only check (for scriptSig with SIGPUSHONLY flag)
%%% -------------------------------------------------------------------

is_push_only(<<>>) ->
    true;
is_push_only(<<Op, Rest/binary>>) when Op >= 1, Op =< 16#4b ->
    case Rest of
        <<_:Op/binary, Rest2/binary>> -> is_push_only(Rest2);
        _ -> false
    end;
is_push_only(<<?OP_0, Rest/binary>>) ->
    is_push_only(Rest);
is_push_only(<<?OP_PUSHDATA1, Len:8, Rest/binary>>) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> -> is_push_only(Rest2);
        _ -> false
    end;
is_push_only(<<?OP_PUSHDATA2, Len:16/little, Rest/binary>>) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> -> is_push_only(Rest2);
        _ -> false
    end;
is_push_only(<<?OP_PUSHDATA4, Len:32/little, Rest/binary>>) ->
    case Rest of
        <<_:Len/binary, Rest2/binary>> -> is_push_only(Rest2);
        _ -> false
    end;
is_push_only(<<?OP_1NEGATE, Rest/binary>>) ->
    is_push_only(Rest);
is_push_only(<<Op, Rest/binary>>) when Op >= ?OP_1, Op =< ?OP_16 ->
    is_push_only(Rest);
is_push_only(_) ->
    false.

%%% -------------------------------------------------------------------
%%% Script code extraction for sighash
%%% -------------------------------------------------------------------

%% @doc Extract the subscript starting from after the last OP_CODESEPARATOR.
%% CodesepPos 0 means no codeseparator was hit, use full script.
subscript_from_codesep(Script, 0) ->
    Script;
subscript_from_codesep(Script, CodesepPos) ->
    case CodesepPos =< byte_size(Script) of
        true -> binary:part(Script, CodesepPos, byte_size(Script) - CodesepPos);
        false -> Script
    end.

%%% -------------------------------------------------------------------
%%% Sighash computation
%%% -------------------------------------------------------------------

-spec sighash_legacy(#transaction{}, non_neg_integer(),
                     binary(), non_neg_integer()) -> binary().
sighash_legacy(Tx, InputIndex, ScriptCode, HashType) ->
    BaseType = HashType band 16#1f,
    AnyoneCanPay = (HashType band ?SIGHASH_ANYONECANPAY) =/= 0,
    %% SIGHASH_SINGLE with input index >= outputs: return magic hash
    case BaseType =:= ?SIGHASH_SINGLE andalso
         InputIndex >= length(Tx#transaction.outputs) of
        true ->
            <<1, 0:248>>;
        false ->
            %% Remove OP_CODESEPARATOR from scriptCode
            CleanScript = remove_codeseparator(ScriptCode),
            %% Build modified transaction
            Inputs = Tx#transaction.inputs,
            ModInputs = case AnyoneCanPay of
                true ->
                    [modify_input(lists:nth(InputIndex + 1, Inputs),
                                  CleanScript, BaseType, true)];
                false ->
                    lists:map(fun({I, Idx}) ->
                        IsSelf = Idx =:= InputIndex,
                        modify_input(I, case IsSelf of
                            true -> CleanScript;
                            false -> <<>>
                        end, BaseType, IsSelf)
                    end, lists:zip(Inputs, lists:seq(0, length(Inputs) - 1)))
            end,
            ModOutputs = case BaseType of
                ?SIGHASH_NONE ->
                    [];
                ?SIGHASH_SINGLE ->
                    %% Keep only outputs up to InputIndex
                    Outs = Tx#transaction.outputs,
                    Padded = [#tx_out{value = 16#ffffffffffffffff,
                                     script_pubkey = <<>>}
                              || _ <- lists:seq(0, InputIndex - 1)],
                    Padded ++ [lists:nth(InputIndex + 1, Outs)];
                _ ->
                    Tx#transaction.outputs
            end,
            ModTx = Tx#transaction{
                inputs = ModInputs,
                outputs = ModOutputs
            },
            %% Serialize without witness + hash type as LE uint32
            TxBin = beamchain_serialize:encode_transaction(ModTx, no_witness),
            beamchain_crypto:hash256(<<TxBin/binary, HashType:32/little>>)
    end.

modify_input(#tx_in{} = Input, ScriptCode, BaseType, IsSelf) ->
    Seq = case IsSelf of
        true -> Input#tx_in.sequence;
        false ->
            case BaseType of
                ?SIGHASH_NONE -> 0;
                ?SIGHASH_SINGLE -> 0;
                _ -> Input#tx_in.sequence
            end
    end,
    Input#tx_in{script_sig = ScriptCode, sequence = Seq, witness = []}.

remove_codeseparator(Script) ->
    remove_codesep(Script, <<>>).

remove_codesep(<<>>, Acc) ->
    Acc;
remove_codesep(<<?OP_CODESEPARATOR, Rest/binary>>, Acc) ->
    remove_codesep(Rest, Acc);
remove_codesep(<<Op, Rest/binary>>, Acc) when Op >= 1, Op =< 16#4b ->
    case Rest of
        <<Data:Op/binary, Rest2/binary>> ->
            remove_codesep(Rest2, <<Acc/binary, Op, Data/binary>>);
        _ ->
            <<Acc/binary, Op, Rest/binary>>
    end;
remove_codesep(<<?OP_PUSHDATA1, Len:8, Rest/binary>>, Acc) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            remove_codesep(Rest2, <<Acc/binary, ?OP_PUSHDATA1, Len:8, Data/binary>>);
        _ ->
            <<Acc/binary, ?OP_PUSHDATA1, Len:8, Rest/binary>>
    end;
remove_codesep(<<?OP_PUSHDATA2, Len:16/little, Rest/binary>>, Acc) ->
    case Rest of
        <<Data:Len/binary, Rest2/binary>> ->
            remove_codesep(Rest2, <<Acc/binary, ?OP_PUSHDATA2, Len:16/little, Data/binary>>);
        _ ->
            <<Acc/binary, ?OP_PUSHDATA2, Len:16/little, Rest/binary>>
    end;
remove_codesep(<<B, Rest/binary>>, Acc) ->
    remove_codesep(Rest, <<Acc/binary, B>>).

%% @doc FindAndDelete: remove all occurrences of a push-encoded signature
%% from the scriptCode. Used for legacy (SigVersion::BASE) CHECKSIG and
%% CHECKMULTISIG. The pattern is the signature bytes push-encoded as a
%% script data push (e.g., <push_len><sig_bytes>).
-spec find_and_delete(binary(), binary()) -> binary().
find_and_delete(Script, Sig) ->
    Pattern = push_encode(Sig),
    find_and_delete_pattern(Script, Pattern).

%% Push-encode a data item as a minimal script push operation.
push_encode(Data) ->
    Len = byte_size(Data),
    if
        Len =< 16#4b ->
            <<Len, Data/binary>>;
        Len =< 16#ff ->
            <<?OP_PUSHDATA1, Len:8, Data/binary>>;
        Len =< 16#ffff ->
            <<?OP_PUSHDATA2, Len:16/little, Data/binary>>;
        true ->
            <<?OP_PUSHDATA4, Len:32/little, Data/binary>>
    end.

%% Remove all occurrences of Pattern from Script.
find_and_delete_pattern(Script, Pattern) ->
    case binary:match(Script, Pattern) of
        nomatch -> Script;
        {Pos, Len} ->
            Before = binary:part(Script, 0, Pos),
            After = binary:part(Script, Pos + Len, byte_size(Script) - Pos - Len),
            find_and_delete_pattern(<<Before/binary, After/binary>>, Pattern)
    end.

-spec sighash_witness_v0(#transaction{}, non_neg_integer(),
                         binary(), non_neg_integer(),
                         non_neg_integer()) -> binary().
sighash_witness_v0(Tx, InputIndex, ScriptCode, Amount, HashType) ->
    BaseType = HashType band 16#1f,
    AnyoneCanPay = (HashType band ?SIGHASH_ANYONECANPAY) =/= 0,
    Inputs = Tx#transaction.inputs,
    Input = lists:nth(InputIndex + 1, Inputs),

    %% hashPrevouts
    HashPrevouts = case AnyoneCanPay of
        true -> <<0:256>>;
        false ->
            PrevoutsData = list_to_binary([
                encode_outpoint(I#tx_in.prev_out) || I <- Inputs
            ]),
            beamchain_crypto:hash256(PrevoutsData)
    end,

    %% hashSequence
    HashSequence = case AnyoneCanPay orelse BaseType =:= ?SIGHASH_SINGLE orelse
                        BaseType =:= ?SIGHASH_NONE of
        true -> <<0:256>>;
        false ->
            SeqData = list_to_binary([
                begin Seq = I#tx_in.sequence, <<Seq:32/little>> end || I <- Inputs
            ]),
            beamchain_crypto:hash256(SeqData)
    end,

    %% outpoint
    Outpoint = encode_outpoint(Input#tx_in.prev_out),

    %% scriptCode (serialized with varint length prefix)
    ScriptCodeSer = beamchain_serialize:encode_varstr(ScriptCode),

    %% hashOutputs
    HashOutputs = case BaseType of
        ?SIGHASH_SINGLE when InputIndex < length(Tx#transaction.outputs) ->
            Output = lists:nth(InputIndex + 1, Tx#transaction.outputs),
            beamchain_crypto:hash256(beamchain_serialize:encode_tx_out(Output));
        ?SIGHASH_SINGLE ->
            <<0:256>>;
        ?SIGHASH_NONE ->
            <<0:256>>;
        _ ->
            OutsData = list_to_binary([
                beamchain_serialize:encode_tx_out(O)
                || O <- Tx#transaction.outputs
            ]),
            beamchain_crypto:hash256(OutsData)
    end,

    %% Compose preimage
    Preimage = <<(Tx#transaction.version):32/little,
                 HashPrevouts/binary,
                 HashSequence/binary,
                 Outpoint/binary,
                 ScriptCodeSer/binary,
                 Amount:64/little,
                 (Input#tx_in.sequence):32/little,
                 HashOutputs/binary,
                 (Tx#transaction.locktime):32/little,
                 HashType:32/little>>,
    beamchain_crypto:hash256(Preimage).

-spec sighash_taproot(#transaction{}, non_neg_integer(),
                      [{non_neg_integer(), binary()}],
                      non_neg_integer(),
                      binary() | undefined,
                      binary() | undefined,
                      non_neg_integer()) -> binary().
sighash_taproot(Tx, InputIndex, PrevOuts, HashType, AnnexHash,
                LeafHash, CodeSepPos) ->
    BaseType = HashType band 16#1f,
    AnyoneCanPay = (HashType band ?SIGHASH_ANYONECANPAY) =/= 0,
    Inputs = Tx#transaction.inputs,
    Input = lists:nth(InputIndex + 1, Inputs),

    %% epoch
    Epoch = <<0>>,

    %% OutputType controls which data sections are included (outputs, etc.)
    %% SIGHASH_DEFAULT behaves like SIGHASH_ALL for data inclusion.
    OutputType = case BaseType of
        ?SIGHASH_DEFAULT -> ?SIGHASH_ALL;
        _ -> BaseType
    end,

    %% Common data
    Version = <<(Tx#transaction.version):32/little>>,
    LockTime = <<(Tx#transaction.locktime):32/little>>,

    {CommonPrevouts, CommonAmounts, CommonScriptPubkeys, CommonSequences} =
        case AnyoneCanPay of
            false ->
                PrevoutsData = list_to_binary([
                    encode_outpoint(I#tx_in.prev_out) || I <- Inputs
                ]),
                AmountsData = list_to_binary([
                    <<Amt:64/little>> || {Amt, _} <- PrevOuts
                ]),
                ScriptPKData = list_to_binary([
                    beamchain_serialize:encode_varstr(SPK) || {_, SPK} <- PrevOuts
                ]),
                SeqData = list_to_binary([
                    begin Seq = I#tx_in.sequence, <<Seq:32/little>> end || I <- Inputs
                ]),
                {beamchain_crypto:sha256(PrevoutsData),
                 beamchain_crypto:sha256(AmountsData),
                 beamchain_crypto:sha256(ScriptPKData),
                 beamchain_crypto:sha256(SeqData)};
            true ->
                {<<>>, <<>>, <<>>, <<>>}
        end,

    CommonOutputs = case OutputType of
        T when T =:= ?SIGHASH_ALL; T =:= ?SIGHASH_DEFAULT ->
            OutsData = list_to_binary([
                beamchain_serialize:encode_tx_out(O)
                || O <- Tx#transaction.outputs
            ]),
            beamchain_crypto:sha256(OutsData);
        _ ->
            <<>>
    end,

    %% spend_type
    SpendType0 = case AnnexHash of
        undefined -> 0;
        _ -> 1
    end,
    ExtFlag = case LeafHash of
        undefined -> 0;
        _ -> 1
    end,
    SpendTypeByte = (ExtFlag bsl 1) bor SpendType0,

    %% input-specific data
    InputSpecific = case AnyoneCanPay of
        true ->
            {Amt, SPK} = lists:nth(InputIndex + 1, PrevOuts),
            OutpointBin = encode_outpoint(Input#tx_in.prev_out),
            SPKBin = beamchain_serialize:encode_varstr(SPK),
            <<OutpointBin/binary,
              Amt:64/little,
              SPKBin/binary,
              (Input#tx_in.sequence):32/little>>;
        false ->
            <<InputIndex:32/little>>
    end,

    %% Annex
    AnnexPart = case AnnexHash of
        undefined -> <<>>;
        _ -> AnnexHash
    end,

    %% Single output
    SingleOutput = case OutputType of
        ?SIGHASH_SINGLE when InputIndex < length(Tx#transaction.outputs) ->
            Output = lists:nth(InputIndex + 1, Tx#transaction.outputs),
            beamchain_crypto:sha256(beamchain_serialize:encode_tx_out(Output));
        _ ->
            <<>>
    end,

    %% Leaf hash extension
    LeafPart = case LeafHash of
        undefined -> <<>>;
        _ -> <<LeafHash/binary, 0, CodeSepPos:32/little>>
    end,

    %% Compose the tagged hash preimage
    %% BIP 341: write the ORIGINAL hash_type (0x00 for DEFAULT), not the
    %% remapped value.  OutputType is only used to decide which data to
    %% include (outputs, sequences, etc.).
    Preimage = <<Epoch/binary,
                 HashType:8,
                 Version/binary,
                 LockTime/binary,
                 CommonPrevouts/binary,
                 CommonAmounts/binary,
                 CommonScriptPubkeys/binary,
                 CommonSequences/binary,
                 CommonOutputs/binary,
                 SpendTypeByte:8,
                 InputSpecific/binary,
                 AnnexPart/binary,
                 SingleOutput/binary,
                 LeafPart/binary>>,
    beamchain_crypto:tagged_hash(<<"TapSighash">>, Preimage).

%%% -------------------------------------------------------------------
%%% Script flags for a given height
%%% -------------------------------------------------------------------

-spec flags_for_height(non_neg_integer(), atom()) -> non_neg_integer().
flags_for_height(Height, mainnet) ->
    F0 = ?SCRIPT_VERIFY_NONE,
    F1 = case Height >= 173805 of
        true -> F0 bor ?SCRIPT_VERIFY_P2SH;
        false -> F0
    end,
    F2 = case Height >= 363725 of
        true -> F1 bor ?SCRIPT_VERIFY_DERSIG;
        false -> F1
    end,
    F3 = case Height >= 388381 of
        true -> F2 bor ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        false -> F2
    end,
    F4 = case Height >= 419328 of
        true -> F3 bor ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        false -> F3
    end,
    F5 = case Height >= 481824 of
        true -> F4 bor ?SCRIPT_VERIFY_WITNESS;
        false -> F4
    end,
    F6 = case Height >= 709632 of
        true -> F5 bor ?SCRIPT_VERIFY_TAPROOT;
        false -> F5
    end,
    %% NULLDUMMY, NULLFAIL, and WITNESS_PUBKEYTYPE are consensus since segwit activation (BIP 141/143/146)
    case Height >= 481824 of
        true -> F6 bor ?SCRIPT_VERIFY_NULLDUMMY bor ?SCRIPT_VERIFY_NULLFAIL
                   bor ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;
        false -> F6
    end;

flags_for_height(_Height, _Network) ->
    %% testnet/regtest: all consensus flags active from genesis
    %% Only consensus flags here — policy flags (CLEANSTACK, SIGPUSHONLY,
    %% LOW_S, STRICTENC, MINIMALDATA, etc.) are NOT consensus.
    ?SCRIPT_VERIFY_P2SH
    bor ?SCRIPT_VERIFY_DERSIG
    bor ?SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    bor ?SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    bor ?SCRIPT_VERIFY_WITNESS
    bor ?SCRIPT_VERIFY_NULLDUMMY
    bor ?SCRIPT_VERIFY_NULLFAIL
    bor ?SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    bor ?SCRIPT_VERIFY_TAPROOT.
