%%% ===================================================================
%%% Finding 3G — addr/addrv2 timestamp clamping (Bitcoin Core parity)
%%%
%%% Bitcoin Core net_processing.cpp ProcessAddrs:5678-5680:
%%%   if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > now + 10min)
%%%       addr.nTime = current_time - 5*24h;
%%%
%%% Before this fix, beamchain passed the peer-supplied timestamp through
%%% unclamped to both addrman and relay recipients. The fix adds
%%% clamp_addr_timestamp/2 and applies it in handle_addr_msg /
%%% handle_addrv2_msg after rate-limiting.
%%%
%%% These tests operate on the pure function clamp_addr_timestamp/2 which
%%% is exported under -ifdef(TEST). No gen_server infrastructure required.
%%% ===================================================================
-module(beamchain_addr_timestamp_clamp_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PM, beamchain_peer_manager).

%% Shorthand: call clamp with a given peer-supplied T and a fixed "now".
clamp(T, Now) ->
    Entry = #{timestamp => T, ip => {5, 6, 7, 8}, port => 18333, services => 1},
    #{timestamp := Clamped} = ?PM:clamp_addr_timestamp(Entry, Now),
    Clamped.

%% Core's fallback value: now - 5 * 24 * 3600 = now - 432000
fallback(Now) -> Now - 432000.

%%% ===================================================================
%%% Unit tests for clamp_addr_timestamp/2
%%% ===================================================================

clamp_addr_timestamp_test_() ->
    Now = 1720000000,  %% fixed "now" (2024-07-03, well after 2001)
    [
     %% ── Condition 1: pre-2001 timestamps (T <= 100000000) ──────────
     {"T == 0 is clamped to (now - 5 days) [pre-2001]", fun() ->
         ?assertEqual(fallback(Now), clamp(0, Now))
     end},

     {"T == 1 is clamped to (now - 5 days) [pre-2001]", fun() ->
         ?assertEqual(fallback(Now), clamp(1, Now))
     end},

     {"T == 100000000 is clamped (boundary: exactly the pre-2001 limit)", fun() ->
         %% Core condition: nTime <= 100000000 → clamp. The boundary IS clamped.
         ?assertEqual(fallback(Now), clamp(100000000, Now))
     end},

     {"T == 100000001 is NOT clamped (just past the pre-2001 boundary)", fun() ->
         ?assertEqual(100000001, clamp(100000001, Now))
     end},

     %% ── Condition 2: more than 10 min in the future ─────────────────
     {"T == now + 601 is clamped (> 10 min future)", fun() ->
         %% Core: addr.nTime > current_time + 10min  → clamp
         ?assertEqual(fallback(Now), clamp(Now + 601, Now))
     end},

     {"T == now + 600 is NOT clamped (exactly 10 min future = boundary)", fun() ->
         %% Core uses strict '>': now + 600 is NOT > now + 600, so no clamp.
         ?assertEqual(Now + 600, clamp(Now + 600, Now))
     end},

     {"T == now + 599 is NOT clamped (inside the 10-min window)", fun() ->
         ?assertEqual(Now + 599, clamp(Now + 599, Now))
     end},

     %% ── Happy path: recent, sane timestamps pass through unchanged ──
     {"A recent timestamp (now - 1h) passes through unchanged", fun() ->
         T = Now - 3600,
         ?assertEqual(T, clamp(T, Now))
     end},

     {"T == now is NOT clamped", fun() ->
         ?assertEqual(Now, clamp(Now, Now))
     end},

     %% ── Clamped value is exactly (now - 432000) ─────────────────────
     {"Clamped value is exactly now - 432000 (5 days), not 0 or epoch", fun() ->
         %% FALSIFICATION: before the fix, unclamped T flowed through for
         %% bogus timestamps. Verify the clamped value is the Core fallback,
         %% not the raw peer value (0) or any other sentinel.
         ?assertEqual(Now - 432000, clamp(0, Now)),
         ?assertEqual(Now - 432000, clamp(Now + 9999, Now))
     end},

     %% ── No-timestamp entry is left untouched ─────────────────────────
     {"Entry without a timestamp field passes through unchanged", fun() ->
         Entry = #{ip => {5, 6, 7, 8}, port => 18333},
         Result = ?PM:clamp_addr_timestamp(Entry, Now),
         ?assertEqual(Entry, Result)
     end}
    ].
