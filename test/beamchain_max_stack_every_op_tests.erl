-module(beamchain_max_stack_every_op_tests).
%% MAX_STACK_SIZE (1000) must hold after EVERY opcode, exactly as Core's
%% EvalScript checks `stack.size() + altstack.size() > MAX_STACK_SIZE` at the
%% bottom of its opcode loop (interpreter.cpp, SCRIPT_ERR_STACK_SIZE). beamchain
%% only checked on the data-push, OP_1NEGATE and OP_1..OP_16 paths, so OP_0,
%% OP_DEPTH and any opcode run on an oversized initial (witness) stack slipped
%% past the limit: scripts Core rejects were valid to beamchain (consensus split).
%%
%% Every "rejects" case below is invalid in Core; every "control" case is valid
%% in Core and must stay valid here.
-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-define(OP_0, 16#00).
-define(OP_1, 16#51).
-define(OP_NOP, 16#61).
-define(OP_IF, 16#63).
-define(OP_ENDIF, 16#68).
-define(OP_TOALTSTACK, 16#6b).
-define(OP_2DROP, 16#6d).
-define(OP_DEPTH, 16#74).
-define(OP_DROP, 16#75).

eval(Script) ->
    eval(Script, [], base).
eval(Script, Stack, SigVersion) ->
    beamchain_script:eval_script(Script, Stack, 0, #{}, SigVersion).

ops(Op, N) -> binary:copy(<<Op>>, N).

%%% --- OP_0 -----------------------------------------------------------

op0_1001_items_rejects_test() ->
    ?assertEqual({error, stack_overflow}, eval(ops(?OP_0, 1001))).

%% The audit's split: 1001 x OP_0 OP_2DROP OP_1 ends with 1000 items, so only a
%% per-opcode check catches it.
op0_1001_then_2drop_rejects_test() ->
    Script = <<(ops(?OP_0, 1001))/binary, ?OP_2DROP, ?OP_1>>,
    ?assertEqual({error, stack_overflow}, eval(Script)).

op0_1000_items_control_test() ->
    {ok, Stack} = eval(ops(?OP_0, 1000)),
    ?assertEqual(1000, length(Stack)).

%% Altstack items count towards the limit (Core: stack + altstack). 200 moves
%% keep the script under the 201 non-push opcode limit.
op0_with_altstack_rejects_test() ->
    Script = <<(ops(?OP_1, 200))/binary, (ops(?OP_TOALTSTACK, 200))/binary,
               (ops(?OP_0, 801))/binary>>,
    ?assertEqual({error, stack_overflow}, eval(Script)).

op0_with_altstack_control_test() ->
    Script = <<(ops(?OP_1, 200))/binary, (ops(?OP_TOALTSTACK, 200))/binary,
               (ops(?OP_0, 800))/binary>>,
    ?assertMatch({ok, _}, eval(Script)).

%%% --- OP_DEPTH -------------------------------------------------------

op_depth_to_1001_rejects_test() ->
    Script = <<(ops(?OP_1, 1000))/binary, ?OP_DEPTH, ?OP_DROP>>,
    ?assertEqual({error, stack_overflow}, eval(Script)).

op_depth_to_1000_control_test() ->
    {ok, Stack} = eval(<<(ops(?OP_1, 999))/binary, ?OP_DEPTH>>),
    ?assertEqual(1000, length(Stack)).

%%% --- Full spend through verify_script (legacy, as in a block) -------

%% scriptSig 1001 x OP_0 already breaks the limit in Core (SCRIPT_ERR_STACK_SIZE
%% during scriptSig evaluation). Before the fix beamchain carried all 1001 items
%% into the scriptPubKey, where OP_2DROP OP_1 left a true top: a valid spend.
legacy_spend_scriptsig_1001_op0_rejects_test() ->
    ?assertEqual(false,
                 beamchain_script:verify_script(ops(?OP_0, 1001),
                                                <<?OP_2DROP, ?OP_1>>, [],
                                                ?SCRIPT_VERIFY_P2SH, #{})).

legacy_spend_scriptsig_1000_op0_control_test() ->
    ?assertEqual(true,
                 beamchain_script:verify_script(ops(?OP_0, 1000),
                                                <<?OP_2DROP, ?OP_1>>, [],
                                                ?SCRIPT_VERIFY_P2SH, #{})).

%%% --- Oversized initial stack (eval level) ----------------------------

%% Core checks after an opcode, so one that shrinks an oversized initial
%% stack to <= 1000 is fine.
oversized_initial_stack_shrinking_op_control_test() ->
    Stack = lists:duplicate(1001, <<>>),
    {ok, Out} = eval(<<?OP_2DROP>>, Stack, witness_v0),
    ?assertEqual(999, length(Out)).

oversized_initial_stack_nop_rejects_test() ->
    Stack = lists:duplicate(1001, <<>>),
    ?assertEqual({error, stack_overflow}, eval(<<?OP_NOP>>, Stack, witness_v0)).

%% An opcode that does not bring an oversized stack back to 1000 fails, even
%% one that pops: 1002 items, OP_IF pops the false top -> 1001. Core fails
%% after OP_IF; without the per-opcode check the false branch is skipped and
%% the script ends with 1001 items.
op_if_on_oversized_stack_rejects_test() ->
    Stack = lists:duplicate(1002, <<>>),
    Script = <<?OP_IF, ?OP_NOP, ?OP_ENDIF>>,
    ?assertEqual({error, stack_overflow}, eval(Script, Stack, witness_v0)).

%% Core does not run the check when no opcode executes (empty script).
empty_script_oversized_stack_control_test() ->
    Stack = lists:duplicate(1001, <<>>),
    ?assertMatch({ok, _}, eval(<<>>, Stack, witness_v0)).

%%% --- Tapscript ------------------------------------------------------

%% Initial tapscript stack of 1000 passes the entry gate; OP_0 makes it 1001.
tapscript_op0_rejects_test() ->
    Stack = lists:duplicate(1000, <<>>),
    ?assertEqual({error, stack_overflow},
                 eval(<<?OP_0, ?OP_DROP>>, Stack, tapscript)).

tapscript_1000_control_test() ->
    Stack = lists:duplicate(999, <<>>),
    ?assertMatch({ok, _}, eval(<<?OP_0>>, Stack, tapscript)).
