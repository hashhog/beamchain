-module(beamchain_escript_repro_tests).

%%% Escript zip reproducibility.
%%%
%%% OTP 27 zip:create writes filesystem atime into each local-header
%%% 0x5455 extra. rebar3 pins mtime but not atime, so three escriptize
%%% builds produce three sha256s. scripts/normalize_escript.escript
%%% rebuilds the archive with {extra, []} and a pinned DOS-epoch mtime.
%%%
%%% CONTROL (full):  bash scripts/reproducible-escript.sh
%%% CONTROL (fast):  rebar3 eunit --module=beamchain_escript_repro_tests
%%% The unnormalized pair MUST diverge (negative control); after
%%% normalize they MUST match.

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

-define(PK, <<80, 75, 3, 4>>).
-define(HEADER, <<"#!/usr/bin/env escript\n%% \n%%! -escript main beamchain_cli\n">>).

normalize_script() ->
    filename:absname("scripts/normalize_escript.escript").

sha256(Bin) ->
    crypto:hash(sha256, Bin).

%% Build a tiny escript whose zip extra carries the given atime.
make_escript(Atime) ->
    Mtime = {{1970, 1, 1}, {0, 0, 1}},
    Info = #file_info{
        size = 4,
        type = regular,
        access = read_write,
        atime = Atime,
        mtime = Mtime,
        ctime = Atime,
        mode = 8#100644,
        links = 1,
        major_device = 0,
        minor_device = 0,
        inode = 0,
        uid = 1000,
        gid = 1000
    },
    {ok, {_, Zip}} = zip:create(
        "dummy.zip",
        [{"foo.beam", <<"abcd">>, Info}],
        [memory]
    ),
    <<?HEADER/binary, Zip/binary>>.

run_normalize(Path) ->
    Escript = os:find_executable("escript"),
    ?assertNotEqual(false, Escript),
    Port = open_port(
        {spawn_executable, Escript},
        [exit_status, binary, stderr_to_stdout, hide,
         {args, [normalize_script(), Path]}]
    ),
    collect_port(Port, []).

collect_port(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            collect_port(Port, [Acc, Data]);
        {Port, {exit_status, 0}} ->
            ok;
        {Port, {exit_status, N}} ->
            {error, {N, iolist_to_binary(Acc)}}
    after 15000 ->
        {error, timeout}
    end.

tmpdir() ->
    Dir = filename:join("/tmp", "beamchain-escript-repro-" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

%%% ===================================================================
%%% Negative control: unnormalized zips with different atimes diverge
%%% ===================================================================

unnormalized_atime_extras_diverge_test() ->
    A = make_escript({{2026, 9, 11}, {18, 0, 0}}),
    B = make_escript({{2026, 9, 11}, {18, 0, 1}}),
    ?assertNotEqual(sha256(A), sha256(B)).

%%% ===================================================================
%%% Normalize collapses atime divergence
%%% ===================================================================

normalize_collapses_atime_divergence_test() ->
    Dir = tmpdir(),
    try
        PA = filename:join(Dir, "a"),
        PB = filename:join(Dir, "b"),
        ok = file:write_file(PA, make_escript({{2026, 9, 11}, {18, 0, 0}})),
        ok = file:write_file(PB, make_escript({{2026, 9, 11}, {18, 0, 1}})),
        ?assertEqual(ok, run_normalize(PA)),
        ?assertEqual(ok, run_normalize(PB)),
        {ok, NA} = file:read_file(PA),
        {ok, NB} = file:read_file(PB),
        ?assertEqual(sha256(NA), sha256(NB)),
        ?assertEqual(?HEADER, header_of(NA)),
        ?assertEqual(false, local_extra_has_atime(NA))
    after
        file:del_dir_r(Dir)
    end.

normalize_is_idempotent_test() ->
    Dir = tmpdir(),
    try
        P = filename:join(Dir, "e"),
        ok = file:write_file(P, make_escript({{2026, 9, 11}, {18, 0, 2}})),
        ?assertEqual(ok, run_normalize(P)),
        {ok, Once} = file:read_file(P),
        ?assertEqual(ok, run_normalize(P)),
        {ok, Twice} = file:read_file(P),
        ?assertEqual(Once, Twice)
    after
        file:del_dir_r(Dir)
    end.

header_of(Bin) ->
    {Pos, _} = binary:match(Bin, ?PK),
    <<H:Pos/binary, _/binary>> = Bin,
    H.

%% True when the first local-file extra encodes atime (UT flag bit 1).
local_extra_has_atime(Bin) ->
    {Pos, _} = binary:match(Bin, ?PK),
    <<_:Pos/binary, Zip/binary>> = Bin,
    %% local file header: PK\x03\x04, then 22 bytes of fixed fields
    %% before file name + extra. See APPNOTE.TXT 4.3.7.
    <<80, 75, 3, 4, _:22/binary, NameLen:16/little, ExtraLen:16/little, Rest/binary>> = Zip,
    <<_Name:NameLen/binary, Extra:ExtraLen/binary, _/binary>> = Rest,
    ut_extra_has_atime(Extra).

ut_extra_has_atime(<<>>) ->
    false;
ut_extra_has_atime(<<16#5455:16/little, Len:16/little, Data:Len/binary, Rest/binary>>) ->
    case Data of
        <<Flags, _/binary>> when (Flags band 2) =/= 0 -> true;
        _ -> ut_extra_has_atime(Rest)
    end;
ut_extra_has_atime(<<_Id:16/little, Len:16/little, _:Len/binary, Rest/binary>>) ->
    ut_extra_has_atime(Rest);
ut_extra_has_atime(_) ->
    false.
