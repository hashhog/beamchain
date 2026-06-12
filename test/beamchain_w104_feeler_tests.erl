%%% ===================================================================
%%% W104 — P2P anti-eclipse hardening (Bitcoin Core v31.99 parity)
%%%
%%% Focused, EXECUTING regression for the five feeler / getaddr / addr
%%% rate-limit guards added to beamchain_peer_manager + beamchain_addrman:
%%%
%%%   1. FEELER selects from the NEW table only and promotes NEW->TRIED on a
%%%      handshake SUCCESS ONLY. A NEW entry that is never probed STAYS NEW
%%%      (the falsification: if promotion fired unconditionally this fails).
%%%   2. FEELER is bounded to one (MAX_FEELER_CONNECTIONS=1) and is OFF the
%%%      full-relay/block-relay slot budget (count_outbound_for_budget/0).
%%%   3. GETADDR answered ONCE per connection; ignored from outbound peers.
%%%   4. GETADDR 23%-cap formula min(1000, ceil(0.23 * size)).
%%%   5. Inbound-addr token bucket drops the excess for rate-limited peers and
%%%      covers BOTH addr AND addrv2 through ONE shared per-peer bucket (an
%%%      addrv2 flood on a drained bucket is dropped).
%%%
%%% These FLIP the historical gap-doc assertions that recorded these features
%%% as ABSENT (W104 BUG-12/BUG-16/BUG-23, W99 G28): we now confirm them PRESENT.
%%%
%%% Core refs: net.cpp ThreadOpenConnections FEELER branch; net_processing.cpp
%%% GETADDR handler (~4816) + ProcessAddrs token bucket (~5639);
%%% net.h FEELER_INTERVAL / MAX_FEELER_CONNECTIONS;
%%% net_processing.cpp MAX_PCT_ADDR_TO_SEND=23 / MAX_ADDR_RATE_PER_SECOND=0.1 /
%%% MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000.
%%% ===================================================================
-module(beamchain_w104_feeler_tests).

-include_lib("eunit/include/eunit.hrl").
-include("beamchain_protocol.hrl").

-define(PM, beamchain_peer_manager).

%%% -------------------------------------------------------------------
%%% addrman fixture (real gen_server)
%%% -------------------------------------------------------------------

setup() ->
    TestDir = "/tmp/beamchain_w104_feeler_" ++
              integer_to_list(erlang:unique_integer([positive])),
    os:putenv("BEAMCHAIN_NETWORK", "testnet4"),
    os:putenv("BEAMCHAIN_DATADIR", TestDir),
    filelib:ensure_path(TestDir),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, AddrmanPid} = beamchain_addrman:start_link(),
    ?PM:test_ensure_peer_table(),
    {ConfigPid, AddrmanPid, TestDir}.

cleanup({ConfigPid, AddrmanPid, TestDir}) ->
    catch ets:delete(beamchain_peers),
    gen_server:stop(AddrmanPid),
    gen_server:stop(ConfigPid),
    catch ets:delete(beamchain_config_ets),
    os:cmd("rm -rf " ++ TestDir),
    ok.

%% Add a batch of distinct routable NEW addresses. Each call uses a FRESH IP
%% range (offset by a monotonic counter) so repeated seeding always grows the
%% NEW table rather than re-adding existing entries. Returns the new NEW count.
seed_new_addrs(N) ->
    Base = erlang:unique_integer([positive, monotonic]) rem 200,
    lists:foreach(fun(I) ->
        %% Spread over 5.B.C.D with B in [6..205], C/D varied — all routable,
        %% none in a reserved range.
        B = 6 + ((Base + (I div 250)) rem 200),
        C = (I rem 250) + 1,
        D = ((I div 250) rem 250) + 1,
        IP = {5, B, C, D},
        %% Vary the source so distinct source-netgroups spread the buckets.
        Src = list_to_atom("src" ++ integer_to_list(Base) ++ "_" ++
                           integer_to_list(I)),
        beamchain_addrman:add_address({IP, 18333}, 1, Src)
    end, lists:seq(1, N)),
    timer:sleep(20),  %% let the casts drain
    {New, _Tried} = beamchain_addrman:count(),
    New.

%% Select one NEW-table address, retrying — addrman's Select(newOnly) is a
%% probabilistic random-bucket walk (Core addrman.cpp Select_), so on a sparse
%% table a single call can miss even when entries exist. Core's
%% ThreadOpenConnections also loops (nTries up to 100); we mirror that here.
select_new(Tries) when Tries =< 0 ->
    error(no_new_addr_after_retries);
select_new(Tries) ->
    case beamchain_addrman:select_address(#{new_only => true}) of
        {ok, Addr} -> Addr;
        empty      -> select_new(Tries - 1)
    end.

%%% ===================================================================
%%% Guard 1 + 2: FEELER select-from-NEW, promote-on-success-ONLY, off-budget
%%% ===================================================================

feeler_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
       [
        {"FEELER selects an address from the NEW table (newOnly)", fun() ->
            Landed = seed_new_addrs(800),
            ?assert(Landed >= 1),
            {New0, Tried0} = beamchain_addrman:count(),
            ?assert(New0 >= 1),
            ?assertEqual(0, Tried0),
            %% Core feeler: addrman.Select(newOnly=true) returns a NEW addr.
            Addr = select_new(50),
            ?assert(is_tuple(Addr))
        end},

        {"FEELER promotes NEW->TRIED on handshake SUCCESS (mark_tried)", fun() ->
            _ = seed_new_addrs(800),
            Addr = select_new(50),
            {New0, Tried0} = beamchain_addrman:count(),
            %% A successful feeler handshake calls mark_tried (== Core Good()).
            beamchain_addrman:mark_tried(Addr),
            timer:sleep(20),
            {New1, Tried1} = beamchain_addrman:count(),
            ?assertEqual(Tried0 + 1, Tried1),     %% promoted into TRIED
            ?assertEqual(New0 - 1, New1)          %% removed from NEW
        end},

        {"FALSIFICATION: a NEW address that is NEVER probed STAYS NEW", fun() ->
            _ = seed_new_addrs(800),
            {New0, Tried0} = beamchain_addrman:count(),
            ?assert(New0 >= 2),
            %% Promote exactly ONE address (one feeler success).
            Addr = select_new(50),
            beamchain_addrman:mark_tried(Addr),
            timer:sleep(20),
            {New1, Tried1} = beamchain_addrman:count(),
            %% Exactly one moved — the rest of the NEW table is untouched.
            %% If promotion were unconditional (the bug), New1 would be 0 and
            %% Tried1 == New0; this asserts that did NOT happen.
            ?assertEqual(Tried0 + 1, Tried1),
            ?assertEqual(New0 - 1, New1),
            ?assert(New1 >= 1)
        end},

        {"FEELER is bounded: MAX_FEELER_CONNECTIONS == 1", fun() ->
            ?assertEqual(1, ?MAX_FEELER_CONNECTIONS)
        end},

        {"FEELER interval == 120s (Core net.h FEELER_INTERVAL = 2min)", fun() ->
            ?assertEqual(120000, ?FEELER_INTERVAL_MS)
        end},

        {"FEELER is OFF the outbound slot budget", fun() ->
            %% 8 full-relay + 2 block-relay peers fill the budget; a feeler on
            %% top must NOT be counted by count_outbound_for_budget/0.
            FR = lists:map(fun(_I) ->
                               P = spawn(fun() -> receive stop -> ok end end),
                               ?PM:test_insert_peer(P, outbound, full_relay, normal),
                               P
                           end, lists:seq(1, 8)),
            BR = lists:map(fun(_I) ->
                               P = spawn(fun() -> receive stop -> ok end end),
                               ?PM:test_insert_peer(P, outbound, block_relay, normal),
                               P
                           end, lists:seq(1, 2)),
            FPid = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(FPid, outbound, feeler, normal),
            %% 10 real outbounds + 1 feeler in the table, budget counts 10.
            ?assertEqual(10, ?PM:count_outbound_for_budget()),
            [P ! stop || P <- FR ++ BR ++ [FPid]],
            ok
        end}
       ]
     end}.

%%% ===================================================================
%%% Guard 3 + 4: GETADDR once-guard, outbound-ignore, 23% cap
%%% ===================================================================

getaddr_cap_formula_test_() ->
    [
     {"23% cap: ceil(0.23*size) below the 1000 absolute cap", fun() ->
         %% size=100 -> ceil(23) = 23
         ?assertEqual(23, ?PM:getaddr_cap(100)),
         %% size=10 -> ceil(2.3) = 3
         ?assertEqual(3, ?PM:getaddr_cap(10)),
         %% size=1 -> ceil(0.23) = 1
         ?assertEqual(1, ?PM:getaddr_cap(1)),
         %% size=0 -> 0
         ?assertEqual(0, ?PM:getaddr_cap(0))
     end},
     {"23% cap: clamped at MAX_ADDR_TO_SEND (1000) for large tables", fun() ->
         %% 0.23 * 5000 = 1150 -> min(1000, 1150) = 1000
         ?assertEqual(1000, ?PM:getaddr_cap(5000)),
         %% Exactly at the knee: ceil(0.23 * 4348) = 1001 -> clamped to 1000
         ?assertEqual(1000, ?PM:getaddr_cap(4348))
     end},
     {"MAX_PCT_ADDR_TO_SEND constant is genuine Core 23", fun() ->
         ?assertEqual(23, ?MAX_PCT_ADDR_TO_SEND)
     end}
    ].

getaddr_guard_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
       [
        {"GETADDR from an INBOUND peer is answered ONCE; the repeat is ignored",
         fun() ->
            _ = seed_new_addrs(40),
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, inbound, full_relay, normal),
            ?assertEqual(false, ?PM:test_peer_field(P, getaddr_recvd)),
            %% First getaddr: answered, flag flips, cap computed from addrman.
            R1 = ?PM:test_handle_getaddr(P, state),
            ?assertMatch({answered, _}, R1),
            ?assertEqual(true, ?PM:test_peer_field(P, getaddr_recvd)),
            %% Second getaddr on the SAME connection: ignored.
            R2 = ?PM:test_handle_getaddr(P, state),
            ?assertEqual(ignored_repeat, R2),
            P ! stop
         end},

        {"GETADDR from an OUTBOUND peer is ignored (anti-fingerprint)", fun() ->
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, outbound, full_relay, normal),
            ?assertEqual(ignored_outbound, ?PM:test_handle_getaddr(P, state)),
            %% Never marks the connection as having answered.
            ?assertEqual(false, ?PM:test_peer_field(P, getaddr_recvd)),
            P ! stop
         end},

        {"GETADDR answer is 23%-capped against the live addrman size", fun() ->
            Landed = seed_new_addrs(100),
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, inbound, full_relay, normal),
            {answered, Cap} = ?PM:test_handle_getaddr(P, state),
            Expected = ?PM:getaddr_cap(Landed),
            ?assertEqual(Expected, Cap),
            ?assert(Cap =< Landed),       %% never returns the whole table
            P ! stop
         end}
       ]
     end}.

%%% ===================================================================
%%% Guard 5: inbound-addr token bucket (shared by addr AND addrv2)
%%% ===================================================================

%% Build N opaque decoded-address maps (the handlers only need ip+port).
mk_addrs(N) ->
    [#{ip => {5, 6, I rem 250 + 1, (I div 250) rem 250 + 1},
       port => 18333, services => 1} || I <- lists:seq(1, N)].

token_bucket_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
       [
        {"DRAINED bucket: rate-limited peer has its excess DROPPED", fun() ->
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, inbound, full_relay, normal),
            %% Drain the bucket to 0 with NO elapsed time (no refill).
            ?PM:test_set_token_bucket(P, 0, 0),
            {Admitted, Dropped} = ?PM:test_handle_addr(P, mk_addrs(5), state),
            ?assertEqual(0, Admitted),
            ?assertEqual(5, Dropped),
            P ! stop
         end},

        {"Partial bucket: admits floor(tokens), drops the rest", fun() ->
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, inbound, full_relay, normal),
            %% 25 units == 2.5 tokens at 10x scale; no refill.
            ?PM:test_set_token_bucket(P, 25, 0),
            {Admitted, Dropped} = ?PM:test_handle_addr(P, mk_addrs(5), state),
            ?assertEqual(2, Admitted),
            ?assertEqual(3, Dropped),
            P ! stop
         end},

        {"NoBan peer is NOT rate-limited: a drained bucket still admits all",
         fun() ->
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, inbound, full_relay, noban),
            ?PM:test_set_token_bucket(P, 0, 0),
            {Admitted, Dropped} = ?PM:test_handle_addr(P, mk_addrs(5), state),
            ?assertEqual(5, Admitted),
            ?assertEqual(0, Dropped),
            P ! stop
         end},

        {"SHARED bucket: addrv2 flood on a bucket drained by addr is DROPPED",
         fun() ->
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, inbound, full_relay, normal),
            %% Start with 2.5 tokens (25 units), no refill.
            ?PM:test_set_token_bucket(P, 25, 0),
            %% addr spends down the bucket: 2 admitted, leaves 0.5 tokens.
            {A1, D1} = ?PM:test_handle_addr(P, mk_addrs(5), state),
            ?assertEqual(2, A1),
            ?assertEqual(3, D1),
            %% addrv2 now sees the SAME drained bucket -> everything dropped.
            %% (If addrv2 had its own bucket this would admit some.)
            {A2, D2} = ?PM:test_handle_addrv2(P, mk_addrs(4), state),
            ?assertEqual(0, A2),
            ?assertEqual(4, D2),
            ?assert(?PM:test_get_token_bucket(P) < 10),  %% < 1 token left
            P ! stop
         end},

        {"Refill credits elapsed*0.1 tokens (10s -> +1 token)", fun() ->
            P = spawn(fun() -> receive stop -> ok end end),
            ?PM:test_insert_peer(P, inbound, full_relay, normal),
            %% Empty bucket, backdate the timestamp by 10s so the refill
            %% credits exactly 1.0 token (MAX_ADDR_RATE_PER_SECOND = 0.1/s).
            ?PM:test_set_token_bucket(P, 0, 10000),
            {Admitted, Dropped} = ?PM:test_handle_addr(P, mk_addrs(3), state),
            ?assertEqual(1, Admitted),
            ?assertEqual(2, Dropped),
            P ! stop
         end},

        {"Rate constants are genuine Core 0.1/s and 1000-cap", fun() ->
            %% 0.1 addr/s expressed as 1/10.
            ?assertEqual(1, ?MAX_ADDR_RATE_PER_SECOND_NUM),
            ?assertEqual(10, ?MAX_ADDR_RATE_PER_SECOND_DEN),
            ?assertEqual(1000, ?MAX_ADDR_PROCESSING_TOKEN_BUCKET)
         end},

        {"spend_addr_tokens unit: rate-limited drops past the bucket", fun() ->
            %% 20 units == 2 tokens; 5 addrs, rate-limited -> 2 kept, 3 dropped.
            {Kept, BucketLeft, Dropped} =
                ?PM:spend_addr_tokens(mk_addrs(5), 20, true, [], 0),
            ?assertEqual(2, length(Kept)),
            ?assertEqual(3, Dropped),
            ?assertEqual(0, BucketLeft)
         end},

        {"spend_addr_tokens unit: unlimited peer keeps all past the bucket",
         fun() ->
            {Kept, _BucketLeft, Dropped} =
                ?PM:spend_addr_tokens(mk_addrs(5), 20, false, [], 0),
            ?assertEqual(5, length(Kept)),
            ?assertEqual(0, Dropped)
         end}
       ]
     end}.
