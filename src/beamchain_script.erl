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

execute_remaining(Op, _Rest, _Pos, _State) ->
    {error, {unknown_opcode, Op}}.

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
%%% Stubs (to be implemented)
%%% -------------------------------------------------------------------

verify_script(_ScriptSig, _ScriptPubKey, _Witness, _Flags, _SigChecker) ->
    {error, not_implemented}.

flags_for_height(_Height, _Network) ->
    ?SCRIPT_VERIFY_NONE.

sighash_legacy(_Tx, _InputIndex, _ScriptCode, _HashType) ->
    <<0:256>>.

sighash_witness_v0(_Tx, _InputIndex, _ScriptCode, _Amount, _HashType) ->
    <<0:256>>.

sighash_taproot(_Tx, _InputIndex, _PrevOuts, _HashType,
                _AnnexHash, _LeafHash, _CodeSepPos) ->
    <<0:256>>.
