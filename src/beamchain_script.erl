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

%%% -------------------------------------------------------------------
%%% Script execution state
%%% -------------------------------------------------------------------

-record(script_state, {
    stack = []        :: [binary()],
    altstack = []     :: [binary()],
    exec_stack = []   :: [boolean()],   %% IF/ELSE nesting
    op_count = 0      :: non_neg_integer(),
    codesep_pos = 0   :: non_neg_integer(),
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

%% --- OP_RETURN ---
execute(<<?OP_RETURN, _Rest/binary>>, _Pos, State) ->
    case executing(State) of
        true -> {error, op_return};
        false ->
            %% still need to parse the rest for IF nesting
            {error, op_return}
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
%%% Remaining opcodes dispatch (stubs for now)
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
        Nop when Nop =:= ?OP_NOP1;
                 Nop >= ?OP_NOP4, Nop =< ?OP_NOP10 ->
            execute_nop(Rest, Pos + 1, State);
        _ ->
            {error, {unknown_opcode, Op}}
    end.

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
%%% OP_CHECKSIG (ECDSA for base/witness_v0)
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
    case pop2(State) of
        {ok, PubKey, Sig, State1} ->
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
                    case DerOk andalso LowSOk andalso StrictEncOk of
                        false ->
                            case Flags band ?SCRIPT_VERIFY_NULLFAIL of
                                0 -> execute(Rest, Pos, push(script_false(), State1));
                                _ -> {error, sig_encoding}
                            end;
                        true ->
                            SigChecker = State1#script_state.sig_checker,
                            SigHash = compute_sig_hash(State1, HashTypeByte, Pos),
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

%% tapscript checksig stub (to be implemented with schnorr)
do_checksig_tapscript(_Rest, _Pos, _State) ->
    {error, not_implemented}.

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

do_checksig_result(#script_state{sig_version = tapscript} = _State, _Pos) ->
    {error, not_implemented};
do_checksig_result(State, Pos) ->
    case pop2(State) of
        {ok, PubKey, Sig, State1} ->
            case Sig of
                <<>> -> {ok, false, State1};
                _ ->
                    SigLen = byte_size(Sig),
                    HashTypeByte = binary:at(Sig, SigLen - 1),
                    SigBody = binary:part(Sig, 0, SigLen - 1),
                    SigHash = compute_sig_hash(State1, HashTypeByte, Pos),
                    Valid = check_ecdsa_sig(
                        State1#script_state.sig_checker, SigBody, PubKey, SigHash),
                    Flags = State1#script_state.flags,
                    case Valid of
                        false when (Flags band ?SCRIPT_VERIFY_NULLFAIL) =/= 0 ->
                            {error, nullfail};
                        _ ->
                            {ok, Valid, State1}
                    end
            end;
        Error -> Error
    end.

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
                            do_checkmultisig(Rest, Pos, State1)
                    end
            end;
        Error -> Error
    end.

do_checkmultisig(Rest, Pos, State) ->
    %% pop nkeys
    case pop_num(State) of
        {ok, NKeys, State1} when NKeys >= 0, NKeys =< ?MAX_PUBKEYS_PER_MULTISIG ->
            %% add nkeys to op_count
            NewOpCount = State1#script_state.op_count + NKeys,
            case NewOpCount > ?MAX_OPS_PER_SCRIPT andalso
                 State1#script_state.sig_version =/= tapscript of
                true -> {error, op_count_exceeded};
                false ->
                    State2 = State1#script_state{op_count = NewOpCount},
                    %% pop public keys
                    case pop_n(NKeys, State2) of
                        {ok, PubKeys, State3} ->
                            %% pop nsigs
                            case pop_num(State3) of
                                {ok, NSigs, State4} when NSigs >= 0, NSigs =< NKeys ->
                                    %% pop signatures
                                    case pop_n(NSigs, State4) of
                                        {ok, Sigs, State5} ->
                                            %% pop the off-by-one dummy element
                                            case pop(State5) of
                                                {ok, Dummy, State6} ->
                                                    Flags = State6#script_state.flags,
                                                    %% NULLDUMMY check
                                                    case (Flags band ?SCRIPT_VERIFY_NULLDUMMY) =/= 0 andalso
                                                         Dummy =/= <<>> of
                                                        true -> {error, nulldummy_failed};
                                                        false ->
                                                            do_multisig_verify(
                                                                PubKeys, Sigs,
                                                                Rest, Pos, State6)
                                                    end;
                                                Error -> Error
                                            end;
                                        Error -> Error
                                    end;
                                {ok, _, _} -> {error, invalid_multisig};
                                Error -> Error
                            end;
                        Error -> Error
                    end
            end;
        {ok, _, _} -> {error, invalid_multisig_key_count};
        Error -> Error
    end.

do_multisig_verify(PubKeys, Sigs, Rest, Pos, State) ->
    %% sequential matching: each sig must match a pubkey in order
    Result = verify_multisig_sigs(PubKeys, Sigs, State, Pos),
    Flags = State#script_state.flags,
    case Result of
        true ->
            execute(Rest, Pos, push(script_true(), State));
        false ->
            %% NULLFAIL: if any sig is non-empty and verification failed, error
            case (Flags band ?SCRIPT_VERIFY_NULLFAIL) =/= 0 andalso
                 lists:any(fun(S) -> S =/= <<>> end, Sigs) of
                true -> {error, nullfail};
                false -> execute(Rest, Pos, push(script_false(), State))
            end
    end.

verify_multisig_sigs(_PubKeys, [], _State, _Pos) ->
    true;
verify_multisig_sigs([], [_ | _], _State, _Pos) ->
    false;  %% more sigs than pubkeys remaining
verify_multisig_sigs([PK | PKRest], [Sig | SigRest] = Sigs, State, Pos) ->
    case Sig of
        <<>> ->
            %% empty sig - try next pubkey? No, empty sig always fails
            verify_multisig_sigs(PKRest, Sigs, State, Pos);
        _ ->
            SigLen = byte_size(Sig),
            HashTypeByte = binary:at(Sig, SigLen - 1),
            SigBody = binary:part(Sig, 0, SigLen - 1),
            SigHash = compute_sig_hash(State, HashTypeByte, Pos),
            case check_ecdsa_sig(State#script_state.sig_checker, SigBody, PK, SigHash) of
                true ->
                    %% matched, advance both
                    verify_multisig_sigs(PKRest, SigRest, State, Pos);
                false ->
                    %% sig didn't match this key, try next key
                    %% but only if remaining keys >= remaining sigs
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
                            %% Run multisig, then verify
                            case do_checkmultisig_result(Rest, Pos, State1) of
                                {ok, State2} ->
                                    case pop(State2) of
                                        {ok, Top, State3} ->
                                            case script_bool(Top) of
                                                true -> execute(Rest, Pos, State3);
                                                false -> {error, checkmultisigverify_failed}
                                            end;
                                        Error -> Error
                                    end;
                                Error -> Error
                            end
                    end
            end;
        Error -> Error
    end.

do_checkmultisig_result(Rest, Pos, State) ->
    %% This duplicates do_checkmultisig but returns state
    do_checkmultisig(Rest, Pos, State).

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
check_ecdsa_sig(_, _Sig, _PubKey, _SigHash) ->
    false.

check_schnorr_sig(#{check_schnorr_sig := Fun}, Sig, PubKey, SigHash) ->
    Fun(Sig, PubKey, SigHash);
check_schnorr_sig(_, _Sig, _PubKey, _SigHash) ->
    false.

check_locktime(#{check_locktime := Fun}, LockTime) ->
    Fun(LockTime);
check_locktime(_, _LockTime) ->
    false.

check_sequence(#{check_sequence := Fun}, Sequence) ->
    Fun(Sequence);
check_sequence(_, _Sequence) ->
    false.

compute_sig_hash(#script_state{sig_checker = Checker}, HashType, CodeSepPos) ->
    case Checker of
        #{compute_sighash := Fun} -> Fun(HashType, CodeSepPos);
        _ -> <<0:256>>
    end.

compute_taproot_sig_hash(#script_state{sig_checker = Checker}, HashType, CodeSepPos) ->
    case Checker of
        #{compute_taproot_sighash := Fun} -> Fun(HashType, CodeSepPos);
        _ -> <<0:256>>
    end.

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
        do_verify_script(ScriptSig, ScriptPubKey, Witness, Flags, SigChecker)
    catch
        _:_ -> false
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
                                {error, _} ->
                                    false
                            end
                    end;
                {error, _} ->
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
            %% construct P2PKH script from the 20-byte program
            Script = <<?OP_DUP, ?OP_HASH160,
                       20, Program/binary,
                       ?OP_EQUALVERIFY, ?OP_CHECKSIG>>,
            case eval_script(Script, [Sig, PubKey], Flags, SigChecker, witness_v0) of
                {ok, [Top]} ->
                    case script_bool(Top) of
                        true -> {ok, [Top]};
                        false -> {error, witness_program_failed}
                    end;
                {ok, _} -> {error, witness_cleanstack};
                {error, _} = E -> E
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
                            case eval_script(WitnessScript, StackItems,
                                           Flags, SigChecker, witness_v0) of
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

verify_witness_program(1, Program, Witness, Flags, SigChecker)
  when byte_size(Program) =:= 32,
       (Flags band ?SCRIPT_VERIFY_TAPROOT) =/= 0 ->
    %% P2TR (Taproot) - stub for now
    verify_taproot(Program, Witness, Flags, SigChecker);

verify_witness_program(_, _, _, _, _) ->
    {error, witness_program_wrong_length}.

%% taproot stub (to be implemented)
verify_taproot(_OutputKey, _Witness, _Flags, _SigChecker) ->
    {ok, [script_true()]}.

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

encode_outpoint(#outpoint{hash = Hash, index = Index}) ->
    <<Hash/binary, Index:32/little>>.

%%% -------------------------------------------------------------------
%%% Stubs (to be implemented)
%%% -------------------------------------------------------------------

-spec sighash_taproot(#transaction{}, non_neg_integer(),
                      [{non_neg_integer(), binary()}],
                      non_neg_integer(),
                      binary() | undefined,
                      binary() | undefined,
                      non_neg_integer()) -> binary().
sighash_taproot(_Tx, _InputIndex, _PrevOuts, _HashType,
                _AnnexHash, _LeafHash, _CodeSepPos) ->
    <<0:256>>.

flags_for_height(_Height, _Network) ->
    ?SCRIPT_VERIFY_NONE.
