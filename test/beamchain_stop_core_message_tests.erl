-module(beamchain_stop_core_message_tests).
-include_lib("eunit/include/eunit.hrl").

%% Core rpc/server.cpp `stop` returns "Bitcoin Core stopping".  The RPC
%% cannot be dispatched in eunit (it schedules init:stop() and would end the
%% test VM), so check the literal inside the rpc_stop/1 clause.
stop_result_is_core_string_test() ->
    Src = proplists:get_value(source, beamchain_rpc:module_info(compile)),
    {ok, Bin} = file:read_file(Src),
    Text = binary_to_list(Bin),
    Start = string:str(Text, "rpc_stop([]) ->"),
    ?assert(Start > 0),
    Tail = string:substr(Text, Start),
    End = string:str(Tail, "rpc_stop([Wait])"),
    ?assert(End > 0),
    Body = string:substr(Tail, 1, End),
    ?assert(string:str(Body, "{ok, <<\"Bitcoin Core stopping\">>}") > 0),
    ?assertEqual(0, string:str(Body, "Beamchain server stopping")).
