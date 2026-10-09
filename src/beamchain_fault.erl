-module(beamchain_fault).

%%% Fault-injection hooks for the gate-6 tests (docs/RELEASE-CHECKLIST.md
%%% gate 6: a system fault -- OOM, I/O error, dead worker, timeout -- must
%%% lead to retry or halt, never to a reject or an accept).
%%%
%%% INERT IN PRODUCTION. Nothing outside eunit ever calls set/2, so every
%%% hook site costs one persistent_term:get/2 with a default and takes the
%%% `passthrough` branch. A hook is a fun(Args) that either returns the
%%% value the hooked call should return, returns `passthrough` (run the real
%%% code), or raises (simulating the fault).
%%%
%%% Hook points (one per simulated system fault):
%%%   ecdsa_verify_nif / schnorr_verify_nif -- the secp256k1 NIF call
%%%   verify_script        -- entry of beamchain_script:do_verify_script/5
%%%   direct_write_batch   -- the chainstate flush WriteBatch
%%%   direct_store_undo    -- the per-block undo write
%%%   direct_atomic_connect_writes -- block body + index WriteBatch
%%%   coins_spend_window   -- inside spend_utxo/2, between the two coin-table
%%%                           updates (F0 interleaving seam; return ignored)
%%%   scantxoutset_fold    -- each coin of a scantxoutset walk (return ignored)
%%%   utxo_snapshot_release -- beamchain_db:release_utxo_snapshot/1 (return
%%%                           ignored; fires after the RocksDB release)

-export([fire/2, set/2, clear/1, clear_all/0]).

-define(POINTS, [ecdsa_verify_nif, schnorr_verify_nif, verify_script,
                 direct_write_batch, direct_store_undo,
                 direct_atomic_connect_writes, coins_spend_window,
                 scantxoutset_fold, utxo_snapshot_release]).

-spec fire(atom(), [term()]) -> passthrough | term().
fire(Point, Args) ->
    case persistent_term:get({?MODULE, Point}, undefined) of
        undefined -> passthrough;
        Fun -> Fun(Args)
    end.

-spec set(atom(), fun(([term()]) -> term())) -> ok.
set(Point, Fun) when is_function(Fun, 1) ->
    persistent_term:put({?MODULE, Point}, Fun).

-spec clear(atom()) -> ok.
clear(Point) ->
    _ = persistent_term:erase({?MODULE, Point}),
    ok.

-spec clear_all() -> ok.
clear_all() ->
    lists:foreach(fun clear/1, ?POINTS).
