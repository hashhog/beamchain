%%% Tapscript OP_IF nesting must cost O(1) per opcode (Core's ConditionStack).
%%%
%%% Item secscan2-beamchain, finding F1 of the Claude Security plugin scan
%%% (CWE-407, "Tapscript IF nesting makes every opcode walk the whole condition
%%% stack").
%%%
%%% Core v31.1, src/script/interpreter.cpp keeps the IF/ELSE state as a
%%% ConditionStack: a size plus the position of the first false value, so
%%% `bool fExec = vfExec.all_true();` is O(1) on every opcode. Core switched to
%%% it before taproot activated because BIP-342 drops the 201-opcode limit, so
%%% nothing else bounds the nesting depth inside a tapscript leaf.
%%%
%%% beamchain_script:executing/1 is `lists:all(fun(V) -> V end, Stack)` over
%%% the exec_stack list and runs before every push, OP_IF/NOTIF and stack,
%%% arithmetic and hash opcode. With N nested true OP_IFs each later opcode
%%% walks N atoms, so the script's cost is O(N^2): a 400 kWU standard
%%% transaction reaches ~87k levels.
%%%
%%% The test times two leaves through eval_tapscript/5 (the tapscript entry
%%% point the block and mempool script checks reach), best of 3 each:
%%%
%%%   nested(N) = (OP_1 OP_IF) x N, OP_1, OP_ENDIF x N   (depth reaches N)
%%%   flat(N)   = (OP_1 OP_IF OP_ENDIF) x N, OP_1        (depth stays <= 1)
%%%
%%% Both execute the same 3N+1 opcodes. The flat leaf is the control: with an
%%% O(1) condition stack the two cost the same up to a small factor, and the
%%% assertion allows 20x. On master nested(16000) costs ~2 s against a few
%%% ms for flat(16000), several hundred times more. A same-size comparison
%%% is used because scaling ratios (N vs 4N) are skewed by GC and heap growth
%%% even for linear work on this VM (flat measured 3.2x-7.7x for a 4x step).
-module(beamchain_secscan2_tapscript_condstack_tests).

-include_lib("eunit/include/eunit.hrl").

-define(OP_0, 16#00).
-define(OP_1, 16#51).
-define(OP_IF, 16#63).
-define(OP_NOTIF, 16#64).
-define(OP_ELSE, 16#67).
-define(OP_ENDIF, 16#68).
-define(N, 16000).
-define(MAX_FACTOR, 20).

nested(N) ->
    <<(binary:copy(<<?OP_1, ?OP_IF>>, N))/binary, ?OP_1,
      (binary:copy(<<?OP_ENDIF>>, N))/binary>>.

flat(N) ->
    <<(binary:copy(<<?OP_1, ?OP_IF, ?OP_ENDIF>>, N))/binary, ?OP_1>>.

flags() ->
    beamchain_script:flags_for_height(900000, mainnet).

run(Script) ->
    beamchain_script:eval_tapscript(Script, [], 1000000, flags(), #{}).

best_us(Script) ->
    _ = run(Script),                             %% warm up
    lists:min([element(1, timer:tc(fun() -> run(Script) end))
               || _ <- lists:seq(1, 3)]).

condstack_test_() ->
    [
     %% Both leaves are valid and run to the end, so the comparison below
     %% measures full executions, not an early failure.
     {"fixtures are valid scripts with the same opcode count",
      {timeout, 60,
       fun() ->
               ?assertEqual(byte_size(nested(?N)), byte_size(flat(?N))),
               ?assertMatch({ok, [<<1>> | _]}, run(nested(?N))),
               ?assertMatch({ok, [<<1>> | _]}, run(flat(?N)))
       end}},
     {"nested IFs cost about the same as flat IFs (O(1) condition stack)",
      {timeout, 120,
       fun() ->
               Flat = max(best_us(flat(?N)), 1),
               Nested = best_us(nested(?N)),
               Factor = Nested / Flat,
               ?debugFmt("condstack N=~b: flat ~p us, nested ~p us, factor ~.1f",
                         [?N, Flat, Nested, Factor]),
               ?assert(Factor < ?MAX_FACTOR)
       end}}
    ].

%%% -------------------------------------------------------------------
%%% Branch semantics. A first-false position tracked wrongly would make a
%%% branch run that Core skips (or skip one Core runs), which is a
%%% consensus split, so the bookkeeping is pinned case by case and then
%%% against a list-based reference model over random IF/NOTIF/ELSE/ENDIF
%%% programs. Markers OP_2..OP_16 push <<2>>..<<16>>, so the final stack
%%% shows which branches ran (top first). These cases pass on master too: they guard
%%% the replacement, the timing test above is the one master fails.
%%% -------------------------------------------------------------------

m(N) when N >= 2, N =< 16 -> 16#50 + N.     %% OP_N
s(Ops) -> list_to_binary(Ops).

%% eval_tapscript/5 applies the leaf's clean-stack rule (exactly one true
%% element), which would hide multi-marker results, so the branch checks
%% run the same tapscript interpreter through eval_script/5 and compare the
%% whole final stack. Both reach execute/3 with sig_version = tapscript.
runx(Script) ->
    beamchain_script:eval_script(Script, [], flags(), #{}, tapscript).

branch_cases() ->
    [
     %% {name, script, expected runx/1 result}
     {"true IF runs",           [?OP_1, ?OP_IF, m(2), ?OP_ENDIF],         {ok, [<<2>>]}},
     {"false IF skips",         [?OP_0, ?OP_IF, m(2), ?OP_ENDIF, m(3)],   {ok, [<<3>>]}},
     {"true IF ELSE",           [?OP_1, ?OP_IF, m(2), ?OP_ELSE, m(3), ?OP_ENDIF], {ok, [<<2>>]}},
     {"false IF ELSE",          [?OP_0, ?OP_IF, m(2), ?OP_ELSE, m(3), ?OP_ENDIF], {ok, [<<3>>]}},
     {"true NOTIF ELSE",        [?OP_1, ?OP_NOTIF, m(2), ?OP_ELSE, m(3), ?OP_ENDIF], {ok, [<<3>>]}},
     {"false NOTIF ELSE",       [?OP_0, ?OP_NOTIF, m(2), ?OP_ELSE, m(3), ?OP_ENDIF], {ok, [<<2>>]}},
     {"double ELSE toggles back",
      [?OP_1, ?OP_IF, m(2), ?OP_ELSE, m(3), ?OP_ELSE, m(4), ?OP_ENDIF], {ok, [<<4>>, <<2>>]}},
     %% Popping the first false makes execution resume.
     {"pop first false resumes",
      [?OP_1, ?OP_IF, ?OP_0, ?OP_IF, m(2), ?OP_ENDIF, m(3), ?OP_ENDIF], {ok, [<<3>>]}},
     %% Nested IF inside a false branch pushes false without popping a
     %% condition; its ELSE must not run (toggle above the first false is
     %% unobservable), and the outer ELSE must run.
     {"nested in false branch, inner ELSE stays off",
      [?OP_0, ?OP_IF, ?OP_1, ?OP_IF, m(2), ?OP_ELSE, m(3), ?OP_ENDIF, m(4),
       ?OP_ELSE, m(5), ?OP_ENDIF], {ok, [<<5>>]}},
     {"false below, toggle top twice",
      [?OP_1, ?OP_IF, ?OP_0, ?OP_IF, ?OP_1, ?OP_IF, m(2), ?OP_ELSE, m(3),
       ?OP_ELSE, m(4), ?OP_ENDIF, m(5), ?OP_ELSE, m(6), ?OP_ENDIF, m(7), ?OP_ENDIF],
      {ok, [<<7>>, <<6>>]}},
     %% The first false is not at the top: ELSE of the top entry is a no-op,
     %% ENDIF of the top does not clear the first false below it.
     {"first false below top survives inner ENDIF",
      [?OP_0, ?OP_IF, ?OP_0, ?OP_IF, ?OP_ENDIF, m(2), ?OP_ELSE, m(3), ?OP_ENDIF],
      {ok, [<<3>>]}},
     %% First false at depth 2 of 3: the top's ELSE stays off, the middle
     %% ELSE turns execution back on.
     {"first false in the middle",
      [?OP_1, ?OP_IF, ?OP_0, ?OP_IF, ?OP_1, ?OP_IF, m(2), ?OP_ELSE, m(3),
       ?OP_ENDIF, ?OP_ELSE, m(4), ?OP_ENDIF, m(5), ?OP_ENDIF],
      {ok, [<<5>>, <<4>>]}},
     {"unbalanced IF",          [?OP_1, ?OP_IF, m(2)],          {error, unbalanced_conditional}},
     {"ELSE with no IF",        [?OP_1, ?OP_ELSE],              {error, unexpected_else}},
     {"ENDIF with no IF",       [?OP_1, ?OP_ENDIF],             {error, unexpected_endif}},
     {"ENDIF after the IF closed",
      [?OP_1, ?OP_IF, ?OP_ENDIF, ?OP_ENDIF],                    {error, unexpected_endif}},
     {"ELSE after the IF closed",
      [?OP_0, ?OP_IF, ?OP_ENDIF, ?OP_ELSE],                     {error, unexpected_else}}
    ].

branch_cases_test_() ->
    [{Name, fun() -> ?assertEqual(Want, runx(s(Ops))) end}
     || {Name, Ops, Want} <- branch_cases()]
    ++
    %% The leaf entry point itself, on single-result programs.
    [{"eval_tapscript: false IF ELSE",
      ?_assertEqual({ok, [<<3>>]},
                    run(s([?OP_0, ?OP_IF, m(2), ?OP_ELSE, m(3), ?OP_ENDIF])))},
     {"eval_tapscript: nested in false branch",
      ?_assertEqual({ok, [<<5>>]},
                    run(s([?OP_0, ?OP_IF, ?OP_1, ?OP_IF, m(2), ?OP_ELSE, m(3),
                           ?OP_ENDIF, m(4), ?OP_ELSE, m(5), ?OP_ENDIF])))}].

%% Reference model: the condition stack as a plain list of booleans, top
%% first, executing iff every entry is true (the pre-ConditionStack form).
%% Only the opcodes the generator emits are modelled.
ref(Ops) -> ref(Ops, [], []).

ref([], Stack, []) -> {ok, Stack};
ref([], _Stack, _Exec) -> {error, unbalanced_conditional};
ref([Op | Rest], Stack, Exec) ->
    On = lists:all(fun(B) -> B end, Exec),
    if
        Op =:= ?OP_IF; Op =:= ?OP_NOTIF ->
            case {On, Stack} of
                {false, _} -> ref(Rest, Stack, [false | Exec]);
                {true, []} -> error;
                {true, [<<>> | S]} -> ref(Rest, S, [Op =:= ?OP_NOTIF | Exec]);
                {true, [<<1>> | S]} -> ref(Rest, S, [Op =:= ?OP_IF | Exec]);
                {true, _} -> error
            end;
        Op =:= ?OP_ELSE ->
            case Exec of
                [] -> {error, unexpected_else};
                [T | E] -> ref(Rest, Stack, [not T | E])
            end;
        Op =:= ?OP_ENDIF ->
            case Exec of
                [] -> {error, unexpected_endif};
                [_ | E] -> ref(Rest, Stack, E)
            end;
        not On -> ref(Rest, Stack, Exec);
        Op =:= ?OP_0 -> ref(Rest, [<<>> | Stack], Exec);
        Op =:= ?OP_1 -> ref(Rest, [<<1>> | Stack], Exec);
        true -> ref(Rest, [<<(Op - 16#50)>> | Stack], Exec)
    end.

%% Random programs: each IF/NOTIF is preceded by OP_0 or OP_1 so the
%% condition is minimal, ELSE/ENDIF appear only while an IF is open (plus a
%% few stray ones), and markers record what ran.
gen(0, Depth, Acc) ->
    lists:reverse(Acc) ++ lists:duplicate(Depth, ?OP_ENDIF);
gen(K, Depth, Acc) ->
    R = rand:uniform(100),
    if
        R =< 30 ->
            Cond = case rand:uniform(2) of 1 -> ?OP_0; 2 -> ?OP_1 end,
            If = case rand:uniform(2) of 1 -> ?OP_IF; 2 -> ?OP_NOTIF end,
            gen(K - 1, Depth + 1, [If, Cond | Acc]);
        R =< 45, Depth > 0 -> gen(K - 1, Depth, [?OP_ELSE | Acc]);
        R =< 65, Depth > 0 -> gen(K - 1, Depth - 1, [?OP_ENDIF | Acc]);
        R =:= 66 -> gen(K - 1, Depth, [?OP_ELSE | Acc]);              %% stray
        R =:= 67 -> gen(K - 1, max(Depth - 1, 0), [?OP_ENDIF | Acc]); %% stray
        true -> gen(K - 1, Depth, [m(1 + rand:uniform(15)) | Acc])
    end.

differential_test_() ->
    {timeout, 120,
     fun() ->
             rand:seed(exsss, {20261125, 1621, 42}),
             Checked = lists:foldl(
                 fun(_, N) ->
                         Ops = gen(rand:uniform(40), 0, []),
                         case ref(Ops) of
                             error ->
                                 ?assertMatch({error, _}, runx(s(Ops)));
                             Want ->
                                 ?assertEqual({Ops, Want}, {Ops, runx(s(Ops))})
                         end,
                         N + 1
                 end, 0, lists:seq(1, 20000)),
             ?assertEqual(20000, Checked)
     end}.
