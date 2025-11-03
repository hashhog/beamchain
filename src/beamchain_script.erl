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
%%% Stubs (to be implemented)
%%% -------------------------------------------------------------------

verify_script(_ScriptSig, _ScriptPubKey, _Witness, _Flags, _SigChecker) ->
    {error, not_implemented}.

eval_script(_Script, _Stack, _Flags, _SigChecker, _SigVersion) ->
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
