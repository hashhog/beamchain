%% @doc Core's central RPC argument-count table (#103).
%%
%% GENERATED FILE -- do not edit by hand. Regenerate with:
%%
%%   python3 tools/gen_core_arity_erl.py > src/beamchain_core_arity.erl
%%
%% Maps a method name to {Required, Declared}, derived from Bitcoin Core's own
%% `help' signature line by tools/core-arity.py (87 methods). Core enforces
%% Required =< N =< Declared centrally, before any handler runs
%% (rpc/util.cpp:644 -> IsValidNumArgs, :733), and answers -1 otherwise.
%%
%% The table is COMPILED IN rather than read from priv/ at startup. beamchain
%% ships as an escript whose resources live inside the archive, and this
%% repo's deploy step moves binaries around: camlcoin shipped exactly this
%% check on 2026-08-31 reading its table from a relative path, and it silently
%% did nothing in production while every test passed.
-module(beamchain_core_arity).
-export([table/0, lookup/1]).

-spec table() -> #{binary() => {non_neg_integer(), non_neg_integer()}}.
table() ->
    #{
      <<"addnode">> => {2, 3},
      <<"analyzepsbt">> => {1, 1},
      <<"clearbanned">> => {0, 0},
      <<"combinepsbt">> => {1, 1},
      <<"combinerawtransaction">> => {1, 1},
      <<"converttopsbt">> => {1, 3},
      <<"createmultisig">> => {2, 3},
      <<"createpsbt">> => {2, 5},
      <<"createrawtransaction">> => {2, 5},
      <<"decodepsbt">> => {1, 1},
      <<"decoderawtransaction">> => {1, 2},
      <<"decodescript">> => {1, 1},
      <<"deriveaddresses">> => {1, 2},
      <<"descriptorprocesspsbt">> => {4, 7},
      <<"disconnectnode">> => {0, 2},
      <<"estimatesmartfee">> => {1, 2},
      <<"finalizepsbt">> => {1, 2},
      <<"getaddednodeinfo">> => {0, 1},
      <<"getaddrmaninfo">> => {0, 0},
      <<"getbestblockhash">> => {0, 0},
      <<"getblock">> => {1, 2},
      <<"getblockchaininfo">> => {0, 0},
      <<"getblockcount">> => {0, 0},
      <<"getblockfilter">> => {1, 2},
      <<"getblockfrompeer">> => {2, 2},
      <<"getblockhash">> => {1, 1},
      <<"getblockheader">> => {1, 2},
      <<"getblockstats">> => {1, 2},
      <<"getblocktemplate">> => {1, 1},
      <<"getchainstates">> => {0, 0},
      <<"getchaintips">> => {0, 0},
      <<"getchaintxstats">> => {0, 2},
      <<"getconnectioncount">> => {0, 0},
      <<"getdeploymentinfo">> => {0, 1},
      <<"getdescriptorinfo">> => {1, 1},
      <<"getdifficulty">> => {0, 0},
      <<"getindexinfo">> => {0, 1},
      <<"getmemoryinfo">> => {0, 1},
      <<"getmempoolancestors">> => {1, 2},
      <<"getmempooldescendants">> => {1, 2},
      <<"getmempoolentry">> => {1, 1},
      <<"getmempoolinfo">> => {0, 0},
      <<"getmininginfo">> => {0, 0},
      <<"getnettotals">> => {0, 0},
      <<"getnetworkhashps">> => {0, 2},
      <<"getnetworkinfo">> => {0, 0},
      <<"getnodeaddresses">> => {0, 2},
      <<"getpeerinfo">> => {0, 0},
      <<"getprioritisedtransactions">> => {0, 0},
      <<"getrawmempool">> => {0, 2},
      <<"getrawtransaction">> => {1, 3},
      <<"getrpcinfo">> => {0, 0},
      <<"gettxout">> => {2, 3},
      <<"gettxoutproof">> => {1, 2},
      <<"gettxoutsetinfo">> => {0, 3},
      <<"gettxspendingprevout">> => {1, 2},
      <<"help">> => {0, 1},
      <<"importmempool">> => {1, 2},
      <<"joinpsbts">> => {1, 1},
      <<"listbanned">> => {0, 0},
      <<"logging">> => {0, 2},
      <<"ping">> => {0, 0},
      <<"preciousblock">> => {1, 1},
      <<"prioritisetransaction">> => {1, 3},
      <<"pruneblockchain">> => {1, 1},
      <<"savemempool">> => {0, 0},
      <<"scanblocks">> => {1, 6},
      <<"scantxoutset">> => {1, 2},
      <<"sendrawtransaction">> => {1, 3},
      <<"setban">> => {2, 4},
      <<"setnetworkactive">> => {1, 1},
      <<"signmessagewithprivkey">> => {2, 2},
      <<"signrawtransactionwithkey">> => {2, 4},
      <<"stop">> => {0, 0},
      <<"submitblock">> => {1, 2},
      <<"submitheader">> => {1, 1},
      <<"submitpackage">> => {1, 3},
      <<"testmempoolaccept">> => {1, 2},
      <<"uptime">> => {0, 0},
      <<"utxoupdatepsbt">> => {1, 4},
      <<"validateaddress">> => {1, 1},
      <<"verifychain">> => {0, 2},
      <<"verifymessage">> => {3, 3},
      <<"verifytxoutproof">> => {1, 1},
      <<"waitforblock">> => {1, 2},
      <<"waitforblockheight">> => {1, 2},
      <<"waitfornewblock">> => {0, 2}
    }.

%% Returns `error' when the method is absent -- callers MUST fail OPEN.
%% Coverage is 87 of 103 Core methods; treating an unlisted method as
%% zero-arg would reject calls Core accepts.
-spec lookup(binary()) -> {ok, {non_neg_integer(), non_neg_integer()}} | error.
lookup(Method) when is_binary(Method) ->
    maps:find(Method, table());
lookup(_) ->
    error.
