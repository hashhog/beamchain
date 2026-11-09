-module(beamchain_log_redact).

%% Strip secrets from terms before they reach the logger.
%%
%% Core never logs wallet passphrases, seeds or private keys. beamchain logs
%% raw exception terms (`~p' of Class:Reason:Stack) in several catch-alls, and
%% those terms carry secrets in three ways:
%%
%%   1. A failed gen_server:call exits with {Why, {gen_server, call, [Pid,
%%      Request | _]}}, and Request is e.g. {walletpassphrase, Passphrase, T}.
%%   2. Stack frames for function_clause and BIF errors carry the call's
%%      arguments, which can be a passphrase or the whole #wallet_state{}.
%%   3. Any part of the reason may embed a value the caller supplied, e.g.
%%      {badmatch, Passphrase}.
%%
%% reason/1 and stack/1 handle (1) and (2) for every term. scrub/2 handles
%% (3) when the caller knows which values are secret (the RPC dispatcher does:
%% it is every string parameter of a secret-bearing method).

-export([reason/1, stack/1, scrub/2, secrets_in/1,
         secret_rpc_method/1]).

-define(REDACTED, <<"<redacted>">>).

%% @doc Redact call requests and wallet state anywhere inside a term.
%% A call request is reduced to its tag, so the log still says which call
%% failed ({timeout, {gen_server, call, [Pid, {walletpassphrase, redacted}]}}).
-spec reason(term()) -> term().
reason({Behaviour, call, [Dest, Request | Rest]})
  when Behaviour =:= gen_server; Behaviour =:= gen_statem; Behaviour =:= gen ->
    {Behaviour, call, [Dest, request_tag(Request) | [reason(R) || R <- Rest]]};
reason({M, F, Args, Loc}) when is_atom(M), is_atom(F), is_list(Args),
                               is_list(Loc) ->
    %% A stack frame nested in a reason ({function_clause, Stack}, a crash
    %% report's {Error, Stack}): keep the arity, drop the arguments.
    {M, F, arity(Args), Loc};
reason({Fun, Args, Loc}) when is_function(Fun), is_list(Args), is_list(Loc) ->
    {Fun, arity(Args), Loc};
reason(T) when is_tuple(T), tuple_size(T) > 0, element(1, T) =:= wallet_state ->
    '#wallet_state{redacted}';
reason(T) when is_tuple(T), tuple_size(T) > 0, element(1, T) =:= hd_key ->
    '#hd_key{redacted}';
reason(T) when is_tuple(T) ->
    list_to_tuple([reason(E) || E <- tuple_to_list(T)]);
reason(L) when is_list(L) ->
    map_list(fun reason/1, L);
reason(M) when is_map(M) ->
    maps:from_list([{reason(K), reason(V)} || {K, V} <- maps:to_list(M)]);
reason(Other) ->
    Other.

%% @doc Replace the argument list of every stack frame with its arity.
%% Frames that already hold an arity are kept; anything else is passed
%% through reason/1.
-spec stack(term()) -> term().
stack(Stack) when is_list(Stack) ->
    map_list(fun frame/1, Stack);
stack(Other) ->
    reason(Other).

frame({M, F, Args, Loc}) when is_list(Args) ->
    {M, F, arity(Args), Loc};
frame({Fun, Args, Loc}) when is_list(Args) ->
    {Fun, arity(Args), Loc};
frame(Frame) ->
    reason(Frame).

%% @doc Replace every occurrence of a secret inside Term with <<"<redacted>">>.
%% A binary or printable string that equals or contains a secret is replaced
%% whole, so a secret formatted into a larger message is caught too.
-spec scrub(term(), [binary()]) -> term().
scrub(Term, []) ->
    Term;
scrub(Term, Secrets) ->
    do_scrub(Term, Secrets).

do_scrub(B, Secrets) when is_binary(B) ->
    case contains_secret(B, Secrets) of
        true  -> ?REDACTED;
        false -> B
    end;
do_scrub(L, Secrets) when is_list(L) ->
    case io_lib:printable_unicode_list(L) of
        true ->
            case contains_secret(unicode:characters_to_binary(L), Secrets) of
                true  -> ?REDACTED;
                false -> L
            end;
        false ->
            map_list(fun(E) -> do_scrub(E, Secrets) end, L)
    end;
do_scrub(T, Secrets) when is_tuple(T) ->
    list_to_tuple([do_scrub(E, Secrets) || E <- tuple_to_list(T)]);
do_scrub(M, Secrets) when is_map(M) ->
    maps:from_list([{do_scrub(K, Secrets), do_scrub(V, Secrets)}
                    || {K, V} <- maps:to_list(M)]);
do_scrub(Other, _Secrets) ->
    Other.

contains_secret(_B, []) ->
    false;
contains_secret(B, [S | Rest]) ->
    (binary:match(B, S) =/= nomatch) orelse contains_secret(B, Rest).

%% @doc Every non-empty string value inside a JSON-RPC params term.
-spec secrets_in(term()) -> [binary()].
secrets_in(Params) ->
    lists:usort(collect(Params, [])).

collect(B, Acc) when is_binary(B), byte_size(B) > 0 -> [B | Acc];
collect(L, Acc) when is_list(L) -> lists:foldl(fun collect/2, Acc, L);
collect(M, Acc) when is_map(M) -> collect(maps:values(M), Acc);
collect(_, Acc) -> Acc.

%% @doc RPC methods whose parameters can carry a passphrase, seed, mnemonic,
%% private key or private descriptor.
-spec secret_rpc_method(term()) -> boolean().
secret_rpc_method(Method) ->
    lists:member(Method,
                 [<<"walletpassphrase">>, <<"walletpassphrasechange">>,
                  <<"encryptwallet">>, <<"createwallet">>,
                  <<"restorewallet">>, <<"importprivkey">>,
                  <<"importdescriptors">>, <<"importmulti">>,
                  <<"sethdseed">>, <<"signmessagewithprivkey">>,
                  <<"signrawtransactionwithkey">>]).

%%% Internal

request_tag(Request) when is_tuple(Request), tuple_size(Request) > 0,
                          is_atom(element(1, Request)) ->
    {element(1, Request), redacted};
request_tag(Request) when is_atom(Request) ->
    Request;
request_tag(_Request) ->
    redacted.

%% erlang:raise/3 only accepts frames whose third element is a list or an
%% integer, so an improper argument list maps to 0 rather than an atom.
arity(Args) ->
    try length(Args) catch error:badarg -> 0 end.

%% lists:map/2 that tolerates improper lists.
map_list(F, [H | T]) -> [F(H) | map_list(F, T)];
map_list(_F, []) -> [];
map_list(F, Tail) -> F(Tail).
