#!/usr/bin/env escript
%% -*- erlang -*-
%%! -noshell
%%
%% Rewrite a rebar3 escript so the zip archive is byte-reproducible.
%%
%% rebar3 already pins each member's mtime to 1970-01-01 00:00:01, but
%% OTP 27's zip:create still writes the filesystem atime into the local
%% header's 0x5455 extra field. Three `rebar3 escriptize` runs therefore
%% produce three sha256s of an otherwise identical archive.
%%
%% This script unpacks the zip, rebuilds it with `{extra, []}` and a
%% pinned DOS-epoch mtime, and splices the original shebang/emu_args
%% back on. Invoked as a rebar3 post-escriptize hook.
-mode(compile).

-include_lib("kernel/include/file.hrl").

-define(PK, <<80, 75, 3, 4>>).
-define(EPOCH, {{1980, 1, 1}, {0, 0, 0}}).
-define(MODE, 8#100644).
-define(DEFAULT_PATH, "_build/default/bin/beamchain").

main([]) ->
    main([?DEFAULT_PATH]);
main([Path]) ->
    case normalize(Path) of
        ok ->
            halt(0);
        {error, Reason} ->
            io:format(standard_error, "normalize_escript: ~s: ~p~n", [Path, Reason]),
            halt(1)
    end;
main(_) ->
    io:format(standard_error, "usage: normalize_escript.escript [escript-path]~n", []),
    halt(1).

normalize(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            case split_escript(Bin) of
                {ok, Header, Zip} ->
                    case zip:unzip(Zip, [memory]) of
                        {ok, Files} ->
                            ZipFiles = [zip_member(Name, Data) || {Name, Data} <- lists:sort(Files)],
                            case zip:create("dummy.zip", ZipFiles, [memory, {extra, []}]) of
                                {ok, {_, NewZip}} ->
                                    case file:write_file(Path, <<Header/binary, NewZip/binary>>) of
                                        ok ->
                                            _ = file:change_mode(Path, 8#755),
                                            ok;
                                        Error ->
                                            Error
                                    end;
                                Error ->
                                    Error
                            end;
                        Error ->
                            Error
                    end;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

split_escript(Bin) ->
    case binary:match(Bin, ?PK) of
        {Pos, _} ->
            <<Header:Pos/binary, Zip/binary>> = Bin,
            {ok, Header, Zip};
        nomatch ->
            {error, no_zip_payload}
    end.

zip_member(Name0, Data) ->
    Name = unicode:characters_to_list(Name0),
    Info = #file_info{
        size = byte_size(Data),
        type = regular,
        access = read_write,
        atime = undefined,
        mtime = ?EPOCH,
        ctime = undefined,
        mode = ?MODE,
        links = 1,
        major_device = 0,
        minor_device = 0,
        inode = 0,
        uid = undefined,
        gid = undefined
    },
    {Name, Data, Info}.
