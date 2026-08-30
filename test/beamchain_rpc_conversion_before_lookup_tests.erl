%%% @doc The integer CONVERSION runs before the lookup, and disconnectnode
%%% accepts Core's by-nodeid call.  REGRESSION PINS.
%%%
%%% #81 fixed the arguments beamchain ACCEPTED out of range.  This is the
%%% other half: arguments beamchain REJECTED, but with the wrong error,
%%% because the width check ran after -- or instead of -- the conversion.
%%% Measured against a regtest Core oracle (tools/rpc-arg-differential.py):
%%% 24 findings, all four hostile widths on each of
%%%
%%%   getblockhash <h>              -8 "Block height out of range"   (Core -1)
%%%   getblock <hash> <verbosity>   -5 "Block not found"             (Core -1)
%%%   getrawtransaction <t> <verb>  -5 "No such mempool or ..."      (Core -1)
%%%   getchaintxstats <nblocks>     -8 "Invalid block count..."      (Core -1)
%%%   createmultisig <n> []         -32602 (two different messages)  (Core -1)
%%%   disconnectnode ["", <id>]     -32602 usage string              (Core -29)
%%%
%%% Core's UniValue::getInt<T> runs std::from_chars INTO THE DESTINATION
%%% WIDTH, so the width check fires inside the conversion and only surviving
%%% values reach the lookup or the domain test.  Erlang integers are
%%% ARBITRARY-PRECISION, so nothing overflowed anywhere -- every handler
%%% simply carried a value Core refuses into a lookup Core never performs.
%%%
%%% createmultisig split its four hostile widths across TWO different -32602
%%% messages depending on the sign, which is the tell that the nrequired
%%% domain test was running before any conversion.
%%%
%%% disconnectnode read only params[0] and answered a usage string for every
%%% by-id call -- the form getpeerinfo's "id" field exists to feed.
%%%
%%% TEETH: a handler that rejected everything would satisfy every rejection
%%% assertion here, so each group carries a CONTROL that must reach the REAL
%%% answer (-8 for an in-range illegal height, -29 for an unconnected
%%% address), and the int32 boundary values must convert cleanly.
-module(beamchain_rpc_conversion_before_lookup_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TXID, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>).
-define(ABSENT_HASH,
        <<"00000000000000000000000000000000000000000000000000000000000000ff">>).
-define(OUT_OF_INT32, [2147483648, -2147483649, 4294967296, -4294967297]).
-define(RANGE_ERR, {error, -1, <<"JSON integer out of range">>}).

rpc(M, Params) ->
    beamchain_rpc:handle_method(M, Params, undefined).

%% The peer-manager handlers fold over a named ETS table that only exists
%% inside a running node.  Create an EMPTY one so the by-nodeid path reaches
%% its real "no such peer" answer instead of dying on badarg -- a crash would
%% make these tests fail for a reason that has nothing to do with the fix.
with_empty_peer_table(F) ->
    Existing = ets:whereis(beamchain_peers),
    Owned = case Existing of
                undefined ->
                    ets:new(beamchain_peers, [named_table, public, set,
                                              {keypos, 2}]),
                    true;
                _ -> false
            end,
    try F()
    after
        case Owned of
            true -> ets:delete(beamchain_peers);
            false -> ok
        end
    end.

%% parse_node_addr/1 reads the network params (for the default P2P port), which
%% only exist inside a running node.  Seed regtest params so the by-address
%% CONTROL reaches its real answer.
with_regtest_params(F) ->
    Tab = beamchain_config_ets,
    Created = case ets:info(Tab) of
                  undefined ->
                      ets:new(Tab, [named_table, set, public]),
                      true;
                  _ -> false
              end,
    ets:insert(Tab, {network_params, beamchain_config:network_params(regtest)}),
    try F()
    after
        case Created of
            true  -> catch ets:delete(Tab);
            false -> ok
        end
    end.

%% Did the argument survive the CONVERSION?  A value that converts goes on to
%% a lookup that needs a live backend, so reaching an exception is itself the
%% proof it got past; a conversion failure would have returned cleanly.
survived_conversion(M, Params) ->
    try rpc(M, Params) of
        ?RANGE_ERR -> false;
        _          -> true
    catch _:_ -> true
    end.

%%% --- the conversion beats the domain test ---------------------------

getblockhash_conversion_beats_height_domain_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"getblockhash">>, [V]))
     || V <- ?OUT_OF_INT32].

getchaintxstats_conversion_beats_blockcount_domain_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"getchaintxstats">>, [V]))
     || V <- ?OUT_OF_INT32].

getchaintxstats_two_arg_form_also_converts_first_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"getchaintxstats">>, [V, ?ABSENT_HASH]))
     || V <- ?OUT_OF_INT32].

createmultisig_conversion_beats_nrequired_domain_test() ->
    %% Core answers -1 even though pubkeys is ALSO empty: the conversion runs
    %% before the array is examined.
    [?assertEqual(?RANGE_ERR, rpc(<<"createmultisig">>, [V, []]))
     || V <- ?OUT_OF_INT32].

%%% --- the conversion beats the lookup --------------------------------

getblock_verbosity_conversion_beats_lookup_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"getblock">>, [?ABSENT_HASH, V]))
     || V <- ?OUT_OF_INT32].

getrawtransaction_verbosity_conversion_beats_lookup_test() ->
    [?assertEqual(?RANGE_ERR, rpc(<<"getrawtransaction">>, [?TXID, V]))
     || V <- ?OUT_OF_INT32].

%%% --- disconnectnode honours nodeid ----------------------------------

disconnectnode_by_nodeid_is_minus_29_test() ->
    %% No peers connected, so every id misses -- but it must MISS with Core's
    %% -29, not be refused as a malformed call.
    with_empty_peer_table(
      fun() ->
        [?assertEqual({error, -29, <<"Node not found in connected nodes">>},
                      rpc(<<"disconnectnode">>, [<<>>, V]))
         || V <- [0, 99, -1] ++ ?OUT_OF_INT32]
      end).

disconnectnode_null_address_with_nodeid_test() ->
    with_empty_peer_table(
      fun() ->
        ?assertEqual({error, -29, <<"Node not found in connected nodes">>},
                     rpc(<<"disconnectnode">>, [null, 7]))
      end).

disconnectnode_both_address_and_nodeid_test() ->
    ?assertEqual({error, -32602,
                  <<"Only one of address and nodeid should be provided.">>},
                 rpc(<<"disconnectnode">>, [<<"1.2.3.4:8333">>, 0])).

%%% --- CONTROLS -------------------------------------------------------

%% A handler that rejected everything would satisfy every assertion above.
%% These must reach the REAL answers.

control_in_range_negative_height_keeps_domain_error_test() ->
    ?assertEqual({error, -8, <<"Block height out of range">>},
                 rpc(<<"getblockhash">>, [-1])).

control_int32_boundaries_convert_cleanly_test() ->
    %% A bound off by one in the tight direction would turn these into the
    %% conversion error.  A surviving value continues to the block-index
    %% lookup, which needs a live backend -- so "did not come back as the
    %% range error" is the honest assertion here.
    [?assert(survived_conversion(<<"getblockhash">>, [V]))
     || V <- [2147483647, -2147483648]].

control_in_range_nrequired_keeps_domain_error_test() ->
    %% 0 converts fine and must reach createmultisig's own message.
    ?assertEqual({error, -32602,
                  <<"a multisignature address must require at least one key "
                    "to redeem">>},
                 rpc(<<"createmultisig">>, [0, []])).

control_disconnectnode_by_address_still_works_test() ->
    with_regtest_params(
      fun() ->
        with_empty_peer_table(
          fun() ->
            ?assertEqual({error, -29, <<"Node not found in connected nodes">>},
                         rpc(<<"disconnectnode">>, [<<"192.0.2.99:8333">>]))
          end)
      end).
