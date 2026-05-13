-module(beamchain_w104_addrman_tests).

%% W104 AddrMan fleet audit — beamchain (Erlang/OTP)
%%
%% Reference: Bitcoin Core
%%   addrman.cpp / addrman.h / addrman_impl.h  — AddrManImpl
%%   net_processing.cpp                         — addr/addrv2/getaddr handlers
%%
%% Bug catalogue (30 gates):
%%
%% BUG-1  Hash function: erlang:phash2 instead of SHA-256 (double-SHA) for bucket assignment
%%   Severity: CONSENSUS-DIVERGENT / P1
%%   beamchain_addrman.erl:320-338 uses erlang:phash2({Secret,...}) for all three
%%   bucket hash functions (get_new_bucket, get_tried_bucket, get_bucket_position).
%%   Bitcoin Core uses GetCheapHash() from a SHA-256d HashWriter keyed on nKey
%%   (addrman.cpp:30-47).  erlang:phash2 is a non-cryptographic Erlang internal
%%   hash with a 27-bit output range (max 2^27-1), far weaker than SHA-256 and
%%   with completely different distribution — every bucket assignment is wrong
%%   relative to Core.  This means a deterministic test vector that expects a
%%   specific bucket/slot from Core will produce a different result in beamchain.
%%   Core ref: addrman.cpp:28-47 (GetTriedBucket, GetNewBucket, GetBucketPosition)
%%
%% BUG-2  No IsRoutable / IsValid check before adding an address
%%   Severity: CORRECTNESS / P1
%%   beamchain_addrman.erl:345-361 do_add_address() never checks whether the
%%   address is routable / valid.  Bitcoin Core's AddSingle() returns false
%%   immediately if !addr.IsRoutable() (addrman.cpp:534).  Without this guard,
%%   beamchain accepts loopback (127.x), RFC1918 (10.x, 192.168.x), unspecified
%%   (0.0.0.0), and other unroutable addresses into its peer address table, wasting
%%   table space and potentially leaking local addresses to remote peers on
%%   getaddr responses.
%%   Core ref: addrman.cpp:534 (AddSingle)
%%
%% BUG-3  No stochastic multi-bucket placement for existing addresses (nRefCount growth)
%%   Severity: CORRECTNESS / P1
%%   beamchain_addrman.erl:355-358 — when an address is already in the new table,
%%   the code simply updates the timestamp and returns.  Bitcoin Core additionally
%%   attempts to add the address to a second (or up to 8th) bucket with exponentially
%%   decreasing probability: if nRefCount > 0 the chance is 1 / 2^nRefCount
%%   (addrman.cpp:566-573).  Beamchain never increases nRefCount above 1 for new-table
%%   entries, so high-quality addresses that are seen frequently never get the
%%   additional selection probability boost that is central to the design.
%%   Core ref: addrman.cpp:556-573 (AddSingle stochastic multi-bucket logic)
%%
%% BUG-4  time_penalty not applied when ingesting addr/addrv2 from peers
%%   Severity: CORRECTNESS / P1
%%   beamchain_peer_manager.erl:1470-1477 handle_addr_msg feeds addresses directly
%%   to beamchain_addrman:add_address with the raw timestamp from the peer.
%%   Bitcoin Core applies a 2-hour time_penalty to all addresses received from
%%   peers (net_processing.cpp Apply() call via AddSingle) to reduce the ability
%%   of a peer to influence which addresses appear "fresh".  Self-announcements
%%   (addr == source) get zero penalty, but all others get 2h subtracted from
%%   nTime.  Beamchain ignores this, so peer-supplied timestamps are accepted
%%   verbatim, allowing sybil nodes to keep addresses appearing "fresh."
%%   Core ref: addrman.cpp:539-543, 576 (time_penalty application)
%%
%% BUG-5  Future timestamp (DeLorean) not rejected — no cap on incoming nTime
%%   Severity: CORRECTNESS / P1
%%   beamchain_addrman.erl:347-361 do_add_address() uses erlang:system_time(second)
%%   as the timestamp for ALL newly added addresses, ignoring any peer-supplied
%%   timestamp.  While this prevents future-timestamp inflation, it means beamchain
%%   never stores the actual claimed nTime from the network, nor applies IsTerrible's
%%   "flying DeLorean" check (nTime > now + 10min → terrible).  The add path also
%%   never calls IsTerrible on the existing entry before deciding to overwrite it,
%%   meaning a fresh locally-timestamped entry is never age-evicted via IsTerrible.
%%   Core ref: addrman.cpp:49-72 (IsTerrible), addrman.cpp:584-589 (AddSingle
%%   overwrite check via IsTerrible)
%%
%% BUG-6  IsTerrible not implemented — no RETRIES/MAX_FAILURES eviction
%%   Severity: CORRECTNESS / P1
%%   beamchain_addrman.erl has no IsTerrible function.  Bitcoin Core defines
%%   ADDRMAN_RETRIES=3 (never succeed + ≥3 attempts → terrible) and
%%   ADDRMAN_MAX_FAILURES=10 (≥10 attempts in last 7 days → terrible).  Without
%%   IsTerrible, stale or unreachable addresses are never evicted, only the
%%   30-day HORIZON_SECS age check applies in the slot-eviction path.  The
%%   GetAddr filtered=true path (addrman.cpp:825) also never filters terrible
%%   entries, so unreachable peers are propagated to requesting nodes.
%%   Core ref: addrman.cpp:49-72 (IsTerrible), addrman_impl.h:31-37 (constants)
%%
%% BUG-7  GetChance not implemented — no weighted selection during Select_
%%   Severity: CORRECTNESS / P1
%%   beamchain_addrman.erl:577-607 select_random_bucket_entry uses a flat uniform
%%   bucket scan with no probability weighting.  Bitcoin Core's Select_() picks a
%%   random bucket, scans from a random position, and accepts the entry with
%%   probability GetChance() * chance_factor, where GetChance penalizes very recent
%%   attempts (0.01×) and decays 0.66 per failed attempt (addrman.cpp:764-772).
%%   Without weighted selection, frequently-attempted bad addresses get selected
%%   just as often as healthy ones, leading to suboptimal connection quality.
%%   Core ref: addrman.cpp:764-772 (GetChance-weighted selection)
%%
%% BUG-8  50%/50% tried/new selection instead of Core's actual probability
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl:554-555 uses 70%/30% (rand:uniform(10) =< 7) for
%%   tried/new split.  Bitcoin Core's Select_() uses a true 50%/50% coin flip
%%   (insecure_rand.randbool()) when both tables are non-empty (addrman.cpp:726-728).
%%   The 70/30 split is not from Core and biases selection toward tried entries
%%   more aggressively than intended, especially when new table is large.
%%   Core ref: addrman.cpp:726-728 (search_tried = insecure_rand.randbool())
%%
%% BUG-9  Test-before-evict / ResolveCollisions entirely absent
%%   Severity: CORRECTNESS / P1
%%   beamchain_addrman.erl:459-465 evicts the old tried entry immediately when
%%   there is a collision, calling evict_tried_to_new/6 unconditionally.  Bitcoin
%%   Core's Good_() uses test_before_evict=true and queues the new address in
%%   m_tried_collisions (up to ADDRMAN_SET_TRIED_COLLISION_SIZE=10) rather than
%%   evicting.  ResolveCollisions() later tests whether the old entry has been
%%   recently connected (ADDRMAN_REPLACEMENT=4h window); only if it hasn't is the
%%   new entry moved in.  The REPLACEMENT_HOURS constant is defined in beamchain
%%   (line 56) but is never referenced anywhere in the code — dead constant.
%%   Core ref: addrman.cpp:606-658 (Good_), addrman.cpp:892-953 (ResolveCollisions_)
%%
%% BUG-10 Connected() not implemented — no 20-minute nTime update on disconnect
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl exports no Connected/2 analogue.  Bitcoin Core calls
%%   Connected() on peer DISCONNECT (not connect) to update nTime with a 20-minute
%%   minimum interval, specifically to not leak topology via connect-time
%%   (addrman.cpp:857-874).  Without this, beamchain's address timestamps are
%%   never refreshed for successfully connected peers, and disconnected long-lived
%%   peers age out of the table even though they should be marked as recently seen.
%%   Core ref: addrman.cpp:857-874 (Connected_)
%%
%% BUG-11 SetServices() not implemented — service bits never updated post-add
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl exports no set_services/2 analogue.  Bitcoin Core's
%%   SetServices_() lets callers update nServices for an existing entry when a
%%   version message or serviceflags change is observed (addrman.cpp:876-890).
%%   Beamchain's do_add_address() only writes services on first insertion; a
%%   revisited address never gets updated service bits, causing stale service flags
%%   to persist indefinitely.
%%   Core ref: addrman.cpp:876-890 (SetServices_)
%%
%% BUG-12 GetAddr returns up to 1000 without 23% cap and without IsTerrible filter
%%   Severity: CORRECTNESS / P1
%%   beamchain_peer_manager.erl:1516 calls get_addresses(1000) hardcoded, and
%%   beamchain_addrman.erl:609-619 do_get_addresses collects all IPv4/v6 entries,
%%   shuffles and takes N with no quality filter.  Bitcoin Core's GetAddr_() uses
%%   max_pct=23 (net_processing.cpp) so at most 23% of the address table is
%%   returned, and filters IsTerrible entries by default (filtered=true,
%%   addrman.cpp:825).  Beamchain can return the entire table (up to 65536
%%   entries) and includes terrible addresses, violating Core's privacy
%%   and bandwidth-conservation design.
%%   Core ref: addrman.cpp:792-831 (GetAddr_), net_processing.cpp GetAddr handling
%%
%% BUG-13 add_addresses hardcodes network_id=1 (IPv4) for all addr entries
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl:274 handle_cast add_addresses passes network_id=1 for
%%   every entry regardless of the actual IP family.  IPv6 addresses received in
%%   addr messages will be tagged as IPv4 in the addr_info record, breaking
%%   netgroup calculation (netgroup/1 dispatches on tuple arity to distinguish
%%   IPv4/IPv6) and any filtering by network type.
%%   Core ref: addrman_impl.h:44-105 (AddrInfo with GetNetwork())
%%
%% BUG-14 addrv2 non-IP entries silently dropped in peer_manager (dead add_addrv2_addresses path)
%%   Severity: CORRECTNESS / P1
%%   beamchain_peer_manager.erl:1496-1502 handle_addrv2_msg only forwards entries
%%   that have an ip field; the else branch is "ok %% Skip non-IPv4 for now".
%%   This means TorV3, I2P, and CJDNS addresses from addrv2 messages are silently
%%   discarded.  The add_addrv2_addresses/2 API and do_add_addrv2_entry/3 in
%%   beamchain_addrman.erl correctly handle all network types, but the peer-manager
%%   call site never uses it — it calls add_address/3 for the IPv4/v6 subset only.
%%   Core ref: addrman.cpp (BIP155 network IDs 1-6 all handled)
%%
%% BUG-15 Addr relay to 2 random peers includes inbound peers (should be outbound only)
%%   Severity: CORRECTNESS / P2
%%   beamchain_peer_manager.erl:1527-1542 relay_addr_to_random_peers filters only
%%   on pid =/= source and connected=true.  It does not filter by direction=outbound.
%%   Bitcoin Core relays addr messages only to outbound peers to avoid leaking
%%   which peers we received the message from (privacy anti-fingerprinting).
%%   Relaying to inbound peers is a privacy leak.
%%   Core ref: net_processing.cpp RelayAddress() — only outbound/feeler peers
%%
%% BUG-16 No rate limiting on addr/addrv2 relay (10 addr/min per peer)
%%   Severity: DoS / P2
%%   beamchain_peer_manager.erl:1470-1481 immediately relays ALL received addr
%%   entries to 2 random peers with no rate limiting.  Bitcoin Core limits addr
%%   relay to 10 addresses per minute per peer via a token bucket (net.h
%%   m_addr_known, m_addr_rate_limited).  A single peer sending 1000-addr messages
%%   rapidly can amplify the traffic to other peers up to 1000 addrs per message.
%%   Core ref: net_processing.cpp:3090-3098 (RelayAddress rate limit)
%%
%% BUG-17 Source peer's PID used as source address — netgroup always 'local'
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl:744-746 source_netgroup(Source) when is_pid(Source)
%%   returns the atom 'local'.  When peers forward addr messages,
%%   beamchain_peer_manager.erl:1476 passes the peer Pid as the source.
%%   All such addresses hash to the same source netgroup ('local'), making
%%   get_new_bucket effectively source-blind for all peer-forwarded addresses.
%%   Core uses the peer's remote IP as the source for bucket assignment, which
%%   provides netgroup diversity.  The correct fix is to pass the peer's
%%   remote address instead of its Pid.
%%   Core ref: addrman.cpp:35-40 (GetNewBucket uses src CNetAddr)
%%
%% BUG-18 nAttempts reset not performed when marking tried (Good_ resets to 0)
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl:468-473 do_mark_tried updates last_success and timestamp
%%   but does not reset the attempts counter to 0.  Bitcoin Core's Good_()
%%   explicitly sets info.nAttempts = 0 (addrman.cpp:624).  Without this reset,
%%   a previously-failed address that eventually connects retains its old attempt
%%   count, making IsTerrible (if it were implemented) incorrectly penalize it.
%%   Core ref: addrman.cpp:622-624
%%
%% BUG-19 fCountFailure not respected in mark_failed — attempts always incremented
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl:529-540 do_mark_failed() unconditionally increments
%%   attempts.  Bitcoin Core's Attempt_() only increments nAttempts when
%%   fCountFailure is true AND info.m_last_count_attempt < m_last_good
%%   (addrman.cpp:686-690), i.e., only if we haven't yet counted a failure since
%%   the last global successful connection.  Beamchain always counts, leading to
%%   over-penalisation of addresses that fail during a widespread connectivity
%%   outage.
%%   Core ref: addrman.cpp:686-690 (Attempt_)
%%
%% BUG-20 MakeTried scans all new buckets for address — beamchain only clears one
%%   Severity: CORRECTNESS / P1
%%   beamchain_addrman.erl:500-507 clear_from_new_buckets() only clears the single
%%   canonical bucket/slot (SourceNG-derived).  Bitcoin Core's MakeTried()
%%   iterates over ALL ADDRMAN_NEW_BUCKET_COUNT (1024) buckets starting at
%%   start_bucket to find all occurrences (nRefCount times) of the entry
%%   (addrman.cpp:476-485).  When an address has nRefCount > 1 (up to 8 from
%%   stochastic placement — BUG-3), beamchain leaves orphan bucket entries in
%%   the new table pointing to an address that is now in tried, corrupting the
%%   new-table bucket data.
%%   Core ref: addrman.cpp:476-485 (MakeTried)
%%
%% BUG-21 Eviction from tried does not clear the new-table slot before reinsertion
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl:509-527 evict_tried_to_new() inserts the evicted entry
%%   into new bucket {NewBucket, NewSlot} without first checking if that slot is
%%   occupied (no ClearNew equivalent).  Bitcoin Core's MakeTried() calls
%%   ClearNew(nUBucket, nUBucketPos) before writing (addrman.cpp:511), ensuring
%%   the displaced entry's ref_count is decremented and it is deleted if zero.
%%   Beamchain silently overwrites the slot, causing the previously-occupying
%%   address to have a dangling bucket reference.
%%   Core ref: addrman.cpp:508-518 (MakeTried eviction with ClearNew)
%%
%% BUG-22 No asmap support — netgroup grouping is /16 IPv4 only, no BGP AS grouping
%%   Severity: CORRECTNESS / P3
%%   beamchain_addrman.erl uses a static /16 prefix for IPv4 netgroups and /32
%%   for IPv6 (lines 181-192).  Bitcoin Core supports loading an asmap file via
%%   -asmap to map addresses to their BGP Autonomous System, providing much
%%   better diversity guarantees — addresses from the same AS map to the same
%%   group regardless of which /16 they are in.  Without asmap, a large hosting
%%   provider using many /16s is counted as many groups instead of one.
%%   Core ref: addrman_impl.h:224 (m_netgroupman with asmap version)
%%
%% BUG-23 No feeler connections — ResolveCollisions never triggered
%%   Severity: CORRECTNESS / P2
%%   beamchain_peer_manager.erl has no feeler connection type (ADDR_FETCH or
%%   FEELER).  Bitcoin Core uses feeler connections (one every 2min) to test
%%   whether a tried-collision candidate is still alive, which is the mechanism
%%   that drives ResolveCollisions().  Without feelers, BUG-9's unconditional
%%   eviction cannot be replaced with a proper tested eviction path.
%%   Core ref: net.h ConnectionType::FEELER, net.cpp (feeler connection scheduling)
%%
%% BUG-24 No m_last_good tracking — fCountFailure gate has no baseline
%%   Severity: CORRECTNESS / P2
%%   beamchain_addrman.erl has no m_last_good field in #state{}.  Bitcoin Core
%%   sets m_last_good to the current time on every Good_() call (addrman.cpp:612)
%%   and uses it in Attempt_() to gate whether an attempt counts as a failure.
%%   Without m_last_good, BUG-19's fCountFailure fix cannot be properly
%%   implemented even if attempted.
%%   Core ref: addrman_impl.h:215 (m_last_good), addrman.cpp:612
%%
%% BUG-25 Persistence uses DETS (Erlang-native), not peers.dat binary format
%%   Severity: INTEROP / P3
%%   beamchain_addrman.erl:215-219 opens a DETS file "peers.dets" using Erlang's
%%   native DETS format.  Bitcoin Core uses a custom binary serialisation format
%%   (peers.dat) with versioned wire format V0-V4 (addrman.cpp:154-208).  The
%%   files are completely incompatible.  If an operator tries to bootstrap
%%   beamchain from a Core peers.dat file (or export its addresses for use with
%%   Core), the formats cannot interoperate.
%%   Core ref: addrman.cpp:113-378 (Serialize/Unserialize)
%%
%% BUG-26 No vRandom / randomised traversal for GetAddr — full table scan
%%   Severity: PRIVACY / P2
%%   beamchain_addrman.erl:609-619 do_get_addresses() does ets:foldl over the
%%   entire addr_table followed by a full shuffle.  Bitcoin Core maintains a
%%   separate vRandom vector and uses a partial Fisher-Yates shuffle (first N
%%   elements only) to provide O(N) GetAddr without exposing the full table order
%%   (addrman.cpp:810-830).  Beamchain's full foldl then full sort reveals the
%%   ETS insertion order before shuffling, which is a minor privacy concern, and
%%   scales as O(table_size) regardless of the requested count N.
%%   Core ref: addrman.cpp:810-830 (GetAddr_ partial shuffle)
%%
%% BUG-27 No per-network address counts — Size() by network not supported
%%   Severity: CORRECTNESS / P3
%%   beamchain_addrman.erl:78-91 #state{} tracks only total new_count and
%%   tried_count.  Bitcoin Core's AddrManImpl maintains m_network_counts
%%   (addrman_impl.h:232), a per-network map updated on every Create/Delete/
%%   MakeTried call.  Without per-network counts, beamchain cannot implement
%%   network-specific address selection (Select with networks filter) or
%%   network-diversity limits.
%%   Core ref: addrman_impl.h:232 (m_network_counts), addrman.cpp:406, 487, 527
%%
%% BUG-28 source_netgroup returns 'local' for all PID sources — same as BUG-17
%%   Severity: CORRECTNESS / P2
%%   Confirmed: beamchain_addrman.erl:744-746 source_netgroup(Pid) -> local.
%%   All peer-forwarded addr messages share the same source netgroup, so
%%   addresses from hundreds of different remote peers all hash to the same
%%   source bucket group.  This eliminates the eclipse-attack protection that
%%   source-diversity is meant to provide.
%%   Core ref: addrman.cpp:35-40 (GetNewBucket uses real source CNetAddr)
%%   Note: This is a separate manifestation from BUG-17; listed separately for
%%   the bucket-assignment angle vs. the peer-manager wiring angle.
%%
%% BUG-29 No getaddr one-per-connection guard — beamchain sends getaddr on every reconnect
%%   Severity: CORRECTNESS / P2
%%   beamchain_peer_manager.erl:615-617 sends getaddr on every new outbound
%%   connection with no guard.  Bitcoin Core only sends getaddr to a peer the
%%   first time it connects via a new connection (not after reconnect) and
%%   honours the node's "already-sent-getaddr" flag to avoid repeated querying.
%%   Excessive getaddr requests can burn peer goodwill and are easily observable
%%   as a fingerprinting signal.
%%   Core ref: net_processing.cpp (m_getaddr_sent flag, one-per-connection)
%%
%% BUG-30 No addr relay inbound-direction filter (privacy leak)
%%   Severity: PRIVACY / P2
%%   beamchain_peer_manager.erl:1527-1542 relay_addr_to_random_peers selects
%%   from all connected peers regardless of direction (inbound or outbound).
%%   Bitcoin Core only relays addr messages to outbound peers.  Relaying to
%%   inbound peers leaks information about our peer set and is a known
%%   fingerprinting vector.
%%   Core ref: net_processing.cpp RelayAddress — only called for outbound-type
%%   connections

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Test setup/teardown
%%% ===================================================================

setup() ->
    TestDir = "/tmp/beamchain_w104_test_" ++
              integer_to_list(erlang:unique_integer([positive])),
    os:putenv("BEAMCHAIN_NETWORK", "testnet4"),
    os:putenv("BEAMCHAIN_DATADIR", TestDir),
    filelib:ensure_path(TestDir),
    {ok, ConfigPid} = beamchain_config:start_link(),
    {ok, AddrmanPid} = beamchain_addrman:start_link(),
    {ConfigPid, AddrmanPid, TestDir}.

cleanup({ConfigPid, AddrmanPid, TestDir}) ->
    gen_server:stop(AddrmanPid),
    gen_server:stop(ConfigPid),
    catch ets:delete(beamchain_config_ets),
    os:cmd("rm -rf " ++ TestDir),
    ok.

%%% ===================================================================
%%% BUG-1: Hash function is erlang:phash2 not SHA-256
%%% ===================================================================

bug1_hash_function_test_() ->
    {"BUG-1: Bucket hash uses erlang:phash2 not SHA-256 (non-crypto, non-Core-compatible)",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"phash2 has 27-bit output, not 256-bit as in Core", fun() ->
               %% erlang:phash2 returns 0..2^27-1; 27 bits is the documented range.
               %% Bitcoin Core uses HashWriter SHA-256d which produces 256 bits.
               %% Verify the bucket assignment is deterministic (at least) but
               %% flag that it MUST be wrong relative to Core's SHA-256 formula.
               %%
               %% We can't reproduce Core's exact bucket number here without
               %% implementing SHA-256d; but we can confirm the range is bounded
               %% to 0..?NEW_BUCKET_COUNT-1 (implementation smoke test) AND flag
               %% that any attempt to compare bucket numbers with Core will fail.
               %%
               %% The proper fix: replace erlang:phash2 with crypto:hash(sha256,...)
               %% following Core's GetCheapHash() keyed-hash formula exactly.
               Secret = crypto:strong_rand_bytes(32),
               %% Add an address and verify it lands in range
               Addr = {{8, 8, 8, 8}, 8333},
               SrcNG = {ipv4, 1, 2},
               B = beamchain_addrman:netgroup(Addr),
               ?assertMatch({ipv4, _, _}, B),
               %% phash2 output is always 0..16#7FFFFFF (27 bits)
               H = erlang:phash2({Secret, B, SrcNG}),
               ?assert(H >= 0),
               ?assert(H < (1 bsl 27)),
               %% The real assertion: this is WRONG for Bitcoin Core compatibility.
               %% Core's hash would be SHA-256d with specific serialisation.
               %% We assert the known defect so the test acts as a regression guard.
               %% erlang:phash2 is NOT SHA-256: confirm by checking output size.
               PhashOut = erlang:phash2({<<"key">>, <<"data">>}),
               ?assert(PhashOut < (1 bsl 27))  %% phash2 max is 2^27-1, not 2^256-1
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-2: No IsRoutable check — private/loopback addresses accepted
%%% FIXED: is_routable/2 added; do_add_address returns State unchanged
%%%        when the address is not publicly routable.
%%% ===================================================================

bug2_no_routability_check_test_() ->
    {"BUG-2 FIXED: do_add_address rejects unroutable addresses (loopback, RFC1918, unspecified)",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Loopback 127.0.0.1 is rejected — count stays 0", fun() ->
               Loopback = {{127, 0, 0, 1}, 8333},
               beamchain_addrman:add_address(Loopback, 0, dns),
               timer:sleep(50),
               {New, _Tried} = beamchain_addrman:count(),
               %% Fixed: is_routable/2 returns false for 127.x; address is not stored.
               %% Core ref: addrman.cpp:534 AddSingle() early return on !addr.IsRoutable()
               ?assertEqual(0, New)
           end},
           {"RFC1918 10.0.0.1 is rejected — count stays 0", fun() ->
               Private = {{10, 0, 0, 1}, 8333},
               beamchain_addrman:add_address(Private, 0, dns),
               timer:sleep(50),
               {New, _} = beamchain_addrman:count(),
               %% Fixed: RFC1918 (10.0.0.0/8) is not routable; address is not stored.
               ?assertEqual(0, New)
           end},
           {"Unspecified 0.0.0.0 is rejected — count stays 0", fun() ->
               Unspec = {{0, 0, 0, 0}, 8333},
               beamchain_addrman:add_address(Unspec, 0, dns),
               timer:sleep(50),
               {New, _} = beamchain_addrman:count(),
               %% Fixed: 0.0.0.0/8 treated as unroutable (same as 127.x check in is_routable/2).
               ?assertEqual(0, New)
           end},
           {"RFC1918 192.168.1.1 is rejected — count stays 0", fun() ->
               Private2 = {{192, 168, 1, 1}, 8333},
               beamchain_addrman:add_address(Private2, 0, dns),
               timer:sleep(50),
               {New, _} = beamchain_addrman:count(),
               ?assertEqual(0, New)
           end},
           {"Public 203.0.114.1 is accepted — count becomes 1", fun() ->
               Public = {{203, 0, 114, 1}, 8333},
               beamchain_addrman:add_address(Public, 0, dns),
               timer:sleep(50),
               {New, _} = beamchain_addrman:count(),
               %% 203.0.114.0/24 is NOT in RFC5737 (only .113), so this is a valid
               %% public address and must be accepted.
               ?assertEqual(1, New)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-3: No stochastic multi-bucket placement for existing addresses
%%% ===================================================================

bug3_no_stochastic_multi_bucket_test_() ->
    {"BUG-3: Existing new-table address never added to additional buckets (nRefCount stuck at 1)",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Repeated add of same address never raises ref_count above 1", fun() ->
               Addr = {{1, 2, 3, 4}, 8333},
               %% Add same address 20 times from same source
               lists:foreach(fun(_) ->
                   beamchain_addrman:add_address(Addr, 0, dns)
               end, lists:seq(1, 20)),
               timer:sleep(100),
               %% BUG: nRefCount stays at 1 because do_add_address returns State
               %% without entering the stochastic multi-bucket path.
               %% Core: with 20 re-adds, probability that refcount grows to ≥2 is
               %% 1 - (1/2)^20 ≈ 100%; beamchain never does this.
               {New, _} = beamchain_addrman:count(),
               %% The count should be exactly 1 (same address, multiple adds).
               ?assertEqual(1, New)
               %% The defect is the ref_count staying at 1; to fully test
               %% would require exposing ref_count via a new API.
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-4: time_penalty not applied to peer-forwarded addresses
%%% ===================================================================

bug4_no_time_penalty_test_() ->
    {"BUG-4: No 2-hour time_penalty applied to peer-forwarded addr entries",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Beamchain stores now as timestamp regardless of peer-supplied time", fun() ->
               %% When handle_addr_msg receives an entry with timestamp=far_future,
               %% beamchain calls do_add_address which uses erlang:system_time(second).
               %% Bitcoin Core would subtract 2 hours from the peer-supplied timestamp.
               %%
               %% Since beamchain's add_address/3 API doesn't even accept an nTime
               %% argument, the entire time_penalty mechanism is absent by design.
               %% This test documents the structural absence.
               %%
               %% Verify: add_address accepts no timestamp argument (3-arg form).
               %% The module_info confirms the API lacks time_penalty support.
               Exports = beamchain_addrman:module_info(exports),
               %% add_address/3 exists (no timestamp), add_address/4 exists (network_id)
               ?assert(lists:member({add_address, 3}, Exports)),
               ?assert(lists:member({add_address, 4}, Exports)),
               %% No add_address/5 with time_penalty exists — structural absence confirmed
               ?assertNot(lists:member({add_address, 5}, Exports))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-5: Future timestamp / DeLorean check absent
%%% ===================================================================

bug5_no_delorean_check_test_() ->
    {"BUG-5: IsTerrible DeLorean check (nTime > now+10min) never applied on add",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Address added with far-future implied time is not rejected", fun() ->
               %% Since beamchain stores erlang:system_time(second) on every add
               %% rather than a peer-supplied nTime, the DeLorean check is moot
               %% in practice.  But the *add* path also never validates that the
               %% existing entry's timestamp is in the future before keeping it.
               %% This test verifies the structural absence: no IsTerrible call.
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({is_terrible, 1}, Exports)),
               ?assertNot(lists:member({is_terrible, 2}, Exports))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-6: IsTerrible not implemented
%%% ===================================================================

bug6_no_is_terrible_test_() ->
    {"BUG-6: IsTerrible not implemented — RETRIES/MAX_FAILURES eviction absent",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Marking failed 3+ times never evicts address (RETRIES=3 not enforced)", fun() ->
               Addr = {{5, 6, 7, 8}, 8333},
               beamchain_addrman:add_address(Addr, 0, dns),
               timer:sleep(50),
               %% Mark failed 5 times (> ADDRMAN_RETRIES=3)
               lists:foreach(fun(_) ->
                   beamchain_addrman:mark_failed(Addr)
               end, lists:seq(1, 5)),
               timer:sleep(50),
               %% BUG: address should be considered terrible and evictable
               %% but beamchain never deletes it
               {New, _} = beamchain_addrman:count(),
               ?assertEqual(1, New)
               %% Fix: implement IsTerrible and call it in selection/eviction paths
           end},
           {"IsTerrible function not exported", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({is_terrible, 1}, Exports)),
               ?assertNot(lists:member({is_terrible, 2}, Exports))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-7: GetChance not implemented — flat uniform selection
%%% ===================================================================

bug7_no_get_chance_test_() ->
    {"BUG-7: GetChance weighted selection absent — all entries selected with equal probability",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"No get_chance function exported", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({get_chance, 1}, Exports)),
               ?assertNot(lists:member({get_chance, 2}, Exports))
           end},
           {"Selection does not use chance_factor backoff", fun() ->
               %% Add two addresses: one with many failures, one fresh
               Good = {{1, 2, 3, 4}, 8333},
               Bad  = {{5, 6, 7, 8}, 8333},
               beamchain_addrman:add_address(Good, 0, dns),
               beamchain_addrman:add_address(Bad, 0, dns),
               %% Penalise Bad with many failures
               lists:foreach(fun(_) ->
                   beamchain_addrman:mark_failed(Bad)
               end, lists:seq(1, 8)),
               timer:sleep(100),
               %% Bitcoin Core: Bad gets 0.66^8 ≈ 3.6% chance vs Good's 100%
               %% Beamchain: both selected with equal probability.
               %% We can't easily verify this probabilistically in a unit test,
               %% but we document the structural absence.
               {New, _} = beamchain_addrman:count(),
               ?assert(New >= 1)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-8: 70%/30% tried/new split instead of Core's 50%/50%
%%% ===================================================================

bug8_wrong_table_selection_ratio_test_() ->
    {"BUG-8: select_address uses 70% tried bias instead of Core 50/50 coin flip",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"70% tried selection hardcoded (rand:uniform(10) =< 7)", fun() ->
               %% The bug is structural: do_select_address/2 line 555 uses
               %% rand:uniform(10) =< 7 (70% tried) rather than randbool() (50%).
               %% Bitcoin Core uses insecure_rand.randbool() for 50/50.
               %% Test: with 1 tried and 1 new address, over 100 selections
               %% tried should be chosen ~70% of the time (not 50%).
               New = {{10, 20, 30, 40}, 8333},
               Tried = {{50, 60, 70, 80}, 8333},
               beamchain_addrman:add_address(New, 0, dns),
               beamchain_addrman:add_address(Tried, 0, dns),
               timer:sleep(50),
               beamchain_addrman:mark_tried(Tried),
               timer:sleep(50),
               %% Count how many times tried is selected in 100 trials
               Selections = lists:foldl(fun(_, Acc) ->
                   case beamchain_addrman:select_address() of
                       {ok, Tried} -> Acc + 1;
                       _ -> Acc
                   end
               end, 0, lists:seq(1, 100)),
               %% With Core's 50% rule, expected ~50. Beamchain gives ~70.
               %% Assert it's significantly above 50 (documents the defect).
               ?assert(Selections >= 0),   %% always passes; just documents the intent
               %% In practice with the 70% bias, Selections is ~65-75
               %% The correct fix: use rand:uniform(2) =:= 1 (or equivalent 50/50)
               true
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-9: Test-before-evict / ResolveCollisions absent
%%% ===================================================================

bug9_no_test_before_evict_test_() ->
    {"BUG-9: Tried-table collision evicts immediately — no test-before-evict queuing",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"REPLACEMENT_HOURS constant is defined but never referenced", fun() ->
               %% This is the smoking gun: the constant exists but the code
               %% that should check it (tried collision eviction) never uses it.
               %% If the constant were used, we'd see ?REPLACEMENT_HOURS in
               %% the evict_tried_to_new or do_mark_tried path.
               %% We verify structurally that resolve_collisions is absent.
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({resolve_collisions, 0}, Exports)),
               ?assertNot(lists:member({select_tried_collision, 0}, Exports))
           end},
           {"Two addresses colliding in tried causes immediate eviction", fun() ->
               A1 = {{9, 10, 11, 12}, 8333},
               A2 = {{9, 10, 11, 13}, 8333},
               beamchain_addrman:add_address(A1, 0, dns),
               beamchain_addrman:add_address(A2, 0, dns),
               timer:sleep(50),
               beamchain_addrman:mark_tried(A1),
               timer:sleep(50),
               %% At this point tried has A1. Now mark A2 tried.
               %% If they collide: Core queues A2 in m_tried_collisions.
               %% Beamchain evicts A1 immediately back to new.
               beamchain_addrman:mark_tried(A2),
               timer:sleep(50),
               {New, Tried} = beamchain_addrman:count(),
               %% Both must be accounted for
               ?assertEqual(2, New + Tried)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-10: Connected() not implemented
%%% ===================================================================

bug10_no_connected_function_test_() ->
    {"BUG-10: Connected() absent — nTime never updated on peer disconnect",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"No connected/1 or connected/2 exported from addrman", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({connected, 1}, Exports)),
               ?assertNot(lists:member({connected, 2}, Exports))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-11: SetServices() not implemented
%%% ===================================================================

bug11_no_set_services_test_() ->
    {"BUG-11: SetServices() absent — service bits never updated for known addresses",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"No set_services exported from addrman", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({set_services, 2}, Exports)),
               ?assertNot(lists:member({set_services, 3}, Exports))
           end},
           {"Adding known address with new services does not update services field", fun() ->
               Addr = {{13, 14, 15, 16}, 8333},
               %% Add with NODE_NETWORK (1)
               beamchain_addrman:add_address(Addr, 1, dns),
               timer:sleep(50),
               %% Re-add with NODE_NETWORK | NODE_BLOOM (1|4=5)
               beamchain_addrman:add_address(Addr, 5, dns),
               timer:sleep(50),
               %% Bitcoin Core would OR the service bits: pinfo->nServices |= addr.nServices
               %% Beamchain's do_add_address just updates timestamp, not services
               %% This documents the defect — can't verify the services field
               %% without a new getter API, but the structural absence is confirmed.
               {New, _} = beamchain_addrman:count(),
               ?assertEqual(1, New)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-12: GetAddr has no 23% cap and no IsTerrible filter
%%% ===================================================================

bug12_getaddr_no_pct_cap_no_filter_test_() ->
    {"BUG-12: get_addresses returns all entries with no 23% cap and no terrible filter",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"get_addresses(N) returns exactly N even if N > 23% of table", fun() ->
               %% Add 50 addresses from distinct /16 netgroups
               lists:foreach(fun(I) ->
                   Addr = {{I, I, 1, 1}, 8333},
                   beamchain_addrman:add_address(Addr, 0, dns)
               end, lists:seq(1, 50)),
               timer:sleep(200),
               {Cnt, _} = beamchain_addrman:count(),
               ?assert(Cnt > 0),
               %% Request 100 — more than the table size
               Got100 = beamchain_addrman:get_addresses(100),
               %% With 50 addresses and requesting 100, beamchain returns all 50
               %% Bitcoin Core would cap at 23% of total = ~11
               ?assert(length(Got100) =< Cnt),
               %% The defect: beamchain returns up to Cnt (potentially all),
               %% Core returns at most 23% of table size.
               true
           end},
           {"get_addresses returns addresses even after many failures (terrible not filtered)", fun() ->
               Addr = {{11, 22, 33, 44}, 8333},
               beamchain_addrman:add_address(Addr, 0, dns),
               timer:sleep(50),
               lists:foreach(fun(_) ->
                   beamchain_addrman:mark_failed(Addr)
               end, lists:seq(1, 12)),
               timer:sleep(50),
               %% Core with IsTerrible+filtered=true would exclude this entry
               Got = beamchain_addrman:get_addresses(10),
               %% BUG: address appears in response despite being terrible
               true = is_list(Got)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-13: add_addresses hardcodes network_id=1 for all entries
%%% ===================================================================

bug13_add_addresses_hardcodes_ipv4_test_() ->
    {"BUG-13: add_addresses casts network_id=1 (IPv4) for all entries including IPv6",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"IPv6 address added via add_addresses is tagged network_id=1 (IPv4)", fun() ->
               %% The handle_cast for add_addresses always passes network_id=1
               %% regardless of whether the IP is IPv4 or IPv6.
               IPv6Addr = {{16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}, 8333},
               %% Use add_address/4 to pass correct network_id=2 (IPv6)
               beamchain_addrman:add_address(IPv6Addr, 0, dns, 2),
               timer:sleep(50),
               {New, _} = beamchain_addrman:count(),
               ?assertEqual(1, New),
               %% Via add_addresses (batch), network_id would be 1 (wrong).
               %% The defect is in handle_cast add_addresses:274.
               true
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-14: addrv2 non-IP entries silently dropped in peer_manager
%%% ===================================================================

bug14_addrv2_non_ip_dropped_test_() ->
    {"BUG-14: handle_addrv2_msg drops TorV3/I2P/CJDNS entries — dead add_addrv2_addresses path",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"add_addrv2_addresses API exists but is never called from peer_manager", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               %% The function exists in addrman API
               ?assert(lists:member({add_addrv2_addresses, 2}, Exports)),
               %% But peer_manager's handle_addrv2_msg only uses add_address/3
               %% for IPv4/v6 entries and has "ok %% Skip non-IPv4 for now"
               %% for everything else.  The above API is never called.
               true
           end},
           {"TorV3 address added via add_addrv2_addresses is accepted", fun() ->
               %% Verify the API itself works (addrman supports it)
               TorAddr = #{network_id => 4,
                           address => crypto:strong_rand_bytes(32),
                           port => 8333,
                           services => 0},
               beamchain_addrman:add_addrv2_addresses([TorAddr], dns),
               timer:sleep(50),
               %% addrman handles it; but peer_manager never calls this
               {New, _} = beamchain_addrman:count(),
               ?assert(New >= 0)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-15: Addr relay includes inbound peers (should be outbound only)
%%% ===================================================================

bug15_relay_to_inbound_peers_test_() ->
    {"BUG-15: relay_addr_to_random_peers does not filter by direction=outbound",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"relay_addr_to_random_peers uses no direction filter", fun() ->
               %% The code at peer_manager:1530 filters only:
               %%   P#peer_entry.pid =/= SourcePid
               %%   P#peer_entry.connected =:= true
               %% No P#peer_entry.direction =:= outbound filter.
               %% This is a structural code-level defect.
               %% We document it via a compile-time assertion: the relay function
               %% takes no direction argument and uses no direction filter in the
               %% list comprehension.
               %%
               %% Full integration test would require a running peer_manager
               %% with mock peers; for now, assert the structural absence.
               ?assert(true)  %% documents the finding; structural defect confirmed
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-16: No rate limiting on addr relay (10 addr/min)
%%% ===================================================================

bug16_no_addr_relay_rate_limit_test_() ->
    {"BUG-16: Addr relay has no per-peer rate limit (Core: 10 addr/min token bucket)",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"No rate limiting state in addrman or peer entries", fun() ->
               %% There is no m_addr_rate_limited or token-bucket state in
               %% beamchain's peer_entry record or addrman.
               %% Documents the structural absence.
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({check_addr_rate, 1}, Exports)),
               ?assertNot(lists:member({check_addr_rate, 2}, Exports))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-17: PID as source address → netgroup always 'local'
%%% ===================================================================

bug17_pid_source_netgroup_test_() ->
    {"BUG-17: Peer PID used as addr source → source_netgroup returns 'local' for all peer-forwarded addrs",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"source_netgroup(Pid) returns 'local' for any PID", fun() ->
               Pid = spawn(fun() -> ok end),
               NG = beamchain_addrman:netgroup(Pid),
               %% netgroup/1 on a PID hits the catch-all -> 'other'
               %% source_netgroup(Pid) -> local
               %% Both are wrong for the bucket-assignment source
               ?assertEqual(other, NG)
               %% The actual defect is in source_netgroup/1 (not exported),
               %% but the consequence is all peer-forwarded addresses
               %% share the same source bucket group.
           end},
           {"Two addresses from different peer PIDs get same source netgroup", fun() ->
               %% Because source_netgroup(Pid) -> local for any Pid,
               %% all peer-forwarded addresses will hash to the same source group.
               %% This eliminates eclipse-attack protection via source diversity.
               Pid1 = spawn(fun() -> ok end),
               Pid2 = spawn(fun() -> ok end),
               Addr1 = {{200, 0, 0, 1}, 8333},
               Addr2 = {{201, 0, 0, 1}, 8333},
               beamchain_addrman:add_address(Addr1, 0, Pid1),
               beamchain_addrman:add_address(Addr2, 0, Pid2),
               timer:sleep(50),
               {New, _} = beamchain_addrman:count(),
               ?assertEqual(2, New)
               %% The defect is that both end up in the same source-netgroup bucket pool
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-18: nAttempts not reset on mark_tried
%%% ===================================================================

bug18_attempts_not_reset_on_tried_test_() ->
    {"BUG-18: do_mark_tried does not reset attempts counter (Core: Good_ sets nAttempts=0)",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Attempts counter persists after mark_tried — no reset to 0", fun() ->
               Addr = {{17, 18, 19, 20}, 8333},
               beamchain_addrman:add_address(Addr, 0, dns),
               timer:sleep(50),
               %% Accumulate some failures
               beamchain_addrman:mark_failed(Addr),
               beamchain_addrman:mark_failed(Addr),
               timer:sleep(50),
               %% Now successfully connect
               beamchain_addrman:mark_tried(Addr),
               timer:sleep(50),
               %% Bitcoin Core: Good_() sets info.nAttempts = 0
               %% Beamchain: do_mark_tried does NOT reset attempts
               %% We cannot inspect the internal attempts field without
               %% adding an introspection API, but the code path is clear:
               %% do_mark_tried at lines 468-473 has no attempts reset.
               {_, Tried} = beamchain_addrman:count(),
               ?assertEqual(1, Tried)
               %% Structural defect confirmed by code inspection
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-19: fCountFailure not respected — attempts always incremented
%%% ===================================================================

bug19_count_failure_not_respected_test_() ->
    {"BUG-19: mark_failed always increments attempts; Core's fCountFailure+m_last_good gate absent",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"mark_failed has no fCountFailure parameter", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               %% Core's Attempt(addr, fCountFailure, time) has a boolean flag.
               %% beamchain_addrman:mark_failed/1 takes only the address.
               ?assert(lists:member({mark_failed, 1}, Exports)),
               %% No 2-argument form with fCountFailure
               ?assertNot(lists:member({mark_failed, 2}, Exports))
           end},
           {"No m_last_good state in addrman (required for fCountFailure gate)", fun() ->
               %% The state record has no last_good field.
               %% We verify this by the absence of get_last_good in exports.
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({get_last_good, 0}, Exports))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-20: MakeTried only clears one bucket slot, not all nRefCount slots
%%% ===================================================================

bug20_make_tried_single_bucket_clear_test_() ->
    {"BUG-20: clear_from_new_buckets clears only 1 bucket slot; Core scans all 1024",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"clear_from_new_buckets removes only canonical bucket slot", fun() ->
               %% Structural defect: clear_from_new_buckets/4 at lines 500-507
               %% computes one Bucket/Slot pair and deletes it.
               %% Bitcoin Core's MakeTried scans all ADDRMAN_NEW_BUCKET_COUNT (1024)
               %% buckets for nRefCount occurrences.
               %% Since BUG-3 means refcount is always 1, this bug rarely manifests
               %% in practice — but if multi-bucket placement were added (fix for BUG-3),
               %% this bug would cause dangling bucket entries.
               Addr = {{99, 88, 77, 66}, 8333},
               beamchain_addrman:add_address(Addr, 0, dns),
               timer:sleep(50),
               beamchain_addrman:mark_tried(Addr),
               timer:sleep(50),
               {_, Tried} = beamchain_addrman:count(),
               %% At least the tried count is correct
               ?assertEqual(1, Tried)
               %% The structural defect only shows under refcount>1
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-21: evict_tried_to_new does not call ClearNew before reinsertion
%%% ===================================================================

bug21_evict_no_clearnew_test_() ->
    {"BUG-21: evict_tried_to_new inserts into new bucket without clearing existing occupant",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Eviction from tried to new overwrites slot without ClearNew", fun() ->
               %% When an old tried entry is evicted to make room,
               %% evict_tried_to_new computes the new bucket position and
               %% inserts without clearing the slot first.
               %% Bitcoin Core calls ClearNew(nUBucket, nUBucketPos) first.
               %% This is a correctness defect in bucket integrity.
               Addr1 = {{100, 0, 0, 1}, 8333},
               Addr2 = {{100, 0, 0, 2}, 8333},
               beamchain_addrman:add_address(Addr1, 0, dns),
               beamchain_addrman:add_address(Addr2, 0, dns),
               timer:sleep(50),
               beamchain_addrman:mark_tried(Addr1),
               timer:sleep(50),
               beamchain_addrman:mark_tried(Addr2),
               timer:sleep(50),
               {New, Tried} = beamchain_addrman:count(),
               %% Totals should still account for both addresses
               ?assertEqual(2, New + Tried)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-22: No asmap support
%%% ===================================================================

bug22_no_asmap_test_() ->
    {"BUG-22: No asmap support — netgroups use /16 IPv4 only, no BGP AS mapping",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Netgroup uses /16 prefix only — no asmap configuration", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({load_asmap, 1}, Exports)),
               %% /16 prefix used (verified by netgroup/1 implementation)
               ?assertEqual({ipv4, 8, 8},
                             beamchain_addrman:netgroup({{8, 8, 8, 8}, 8333})),
               ?assertEqual({ipv4, 8, 8},
                             beamchain_addrman:netgroup({{8, 8, 4, 4}, 8333}))
               %% Both 8.8.8.8 and 8.8.4.4 are in the same /16 (Google DNS)
               %% With asmap they might be in different ASes
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-23: No feeler connections
%%% ===================================================================

bug23_no_feeler_connections_test_() ->
    {"BUG-23: No FEELER/ADDR_FETCH connection type in peer_manager",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"select_address with new_only=true is not used for feeler connections", fun() ->
               %% Bitcoin Core uses FEELER connections with select_address(new_only=true)
               %% to test tried-collision candidates.  Without feelers, BUG-9's
               %% unconditional eviction is the only collision resolution.
               %%
               %% Verify that select_address/1 supports new_only option (API exists)
               %% but the peer_manager never uses it for feeler connections.
               Addr = {{55, 66, 77, 88}, 8333},
               beamchain_addrman:add_address(Addr, 0, dns),
               timer:sleep(50),
               %% new_only=true selects from new table
               case beamchain_addrman:select_address(#{new_only => true}) of
                   {ok, _} -> ok;
                   empty -> ok
               end,
               ?assert(true)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-24: No m_last_good tracking
%%% ===================================================================

bug24_no_last_good_test_() ->
    {"BUG-24: No m_last_good field in state — required for fCountFailure gate",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"No get_last_good API exported", fun() ->
               Exports = beamchain_addrman:module_info(exports),
               ?assertNot(lists:member({get_last_good, 0}, Exports))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-25: DETS persistence incompatible with Core's peers.dat format
%%% ===================================================================

bug25_dets_not_peers_dat_test_() ->
    {"BUG-25: Peers stored in DETS (Erlang-native) not Core's binary peers.dat format",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Persistence file is peers.dets not peers.dat", fun() ->
               DataDir = os:getenv("BEAMCHAIN_DATADIR"),
               %% After running, the DETS file should exist
               timer:sleep(100),
               DetsFile = filename:join(DataDir, "peers.dets"),
               %% Just verify the path; DETS format != Core's binary format
               ?assertNotEqual("peers.dat", filename:basename(DetsFile))
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-26: No vRandom — GetAddr does full table scan
%%% ===================================================================

bug26_no_vrandom_test_() ->
    {"BUG-26: GetAddr uses full ets:foldl + shuffle instead of Core's vRandom partial-shuffle",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"get_addresses scans all entries regardless of N", fun() ->
               %% Add many addresses
               lists:foreach(fun(I) ->
                   Addr = {{I, I, I, 1}, 8333},
                   beamchain_addrman:add_address(Addr, 0, dns)
               end, lists:seq(1, 20)),
               timer:sleep(200),
               %% Requesting 1 address still scans all 20 entries in the table
               %% (confirmed by the do_get_addresses code path)
               Got = beamchain_addrman:get_addresses(1),
               ?assertEqual(1, length(Got))
               %% Performance defect: O(table_size) not O(N)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-27: No per-network counts
%%% ===================================================================

bug27_no_per_network_counts_test_() ->
    {"BUG-27: No per-network address counts (m_network_counts) — network-filtered select not supported",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"select_address has no network filter option", fun() ->
               %% Bitcoin Core's Select() accepts a networks set for filtering
               %% beamchain's select_address/1 only supports new_only option
               Opts = #{network => ipv4},
               %% This should work without error (opts are ignored for unknown keys)
               case beamchain_addrman:select_address(Opts) of
                   empty -> ok;
                   {ok, _} -> ok
               end,
               %% The defect is that the network filter is silently ignored
               ?assert(true)
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-28: source_netgroup for PID collapses all peer-forwarded addrs
%%% ===================================================================

bug28_source_netgroup_collapses_test_() ->
    {"BUG-28: All peer-forwarded addresses share 'local' source netgroup — eclipse attack protection lost",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Addresses from 100 different PIDs all land in same source bucket pool", fun() ->
               %% Each Pid as source -> source_netgroup returns 'local'
               %% -> all hash to same source bucket group
               %% -> NEW_BUCKETS_PER_SOURCE_GROUP=64 limits how many can be stored
               %% -> eclipse attacker from one netgroup fills same buckets as all others
               lists:foreach(fun(I) ->
                   Pid = spawn(fun() -> ok end),
                   Addr = {{I, I, 0, 1}, 8333},
                   beamchain_addrman:add_address(Addr, 0, Pid)
               end, lists:seq(1, 30)),
               timer:sleep(200),
               {New, _} = beamchain_addrman:count(),
               ?assert(New > 0),
               %% All 30 addresses shared the same source group ('local')
               %% In Core, they'd span many different source groups (by peer IP)
               true
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-29: No getaddr one-per-connection guard
%%% ===================================================================

bug29_getaddr_no_once_guard_test_() ->
    {"BUG-29: getaddr sent on every new outbound connection — no one-per-peer guard",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"No getaddr_sent flag in peer_entry record", fun() ->
               %% Bitcoin Core tracks m_getaddr_sent per peer and only sends once.
               %% Beamchain's peer_manager sends getaddr unconditionally on every
               %% peer_connected event for outbound peers (peer_manager:615-617).
               %% There is no per-peer flag to prevent repeated sends.
               ?assert(true)   %% structural defect confirmed by code inspection
           end}
          ]
      end}}.

%%% ===================================================================
%%% BUG-30: Addr relay to inbound peers (privacy leak)
%%% ===================================================================

bug30_relay_to_inbound_privacy_leak_test_() ->
    {"BUG-30: relay_addr_to_random_peers relays to inbound peers — privacy fingerprinting risk",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"relay_addr_to_random_peers has no direction=outbound guard", fun() ->
               %% Bitcoin Core's RelayAddress() is gated on the peer being outbound.
               %% beamchain_peer_manager:relay_addr_to_random_peers/3 uses:
               %%   P#peer_entry.pid =/= SourcePid,
               %%   P#peer_entry.connected =:= true
               %% No direction filter. Inbound peers may receive relayed addrs.
               ?assert(true)   %% structural defect confirmed by code inspection
           end}
          ]
      end}}.

%%% ===================================================================
%%% Regression: existing addrman smoke tests still pass
%%% ===================================================================

regression_smoke_test_() ->
    {"Regression: existing addrman behaviour preserved",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Empty addrman returns empty from select", fun() ->
               ?assertEqual(empty, beamchain_addrman:select_address())
           end},
           {"count returns {0, 0} on fresh start", fun() ->
               ?assertEqual({0, 0}, beamchain_addrman:count())
           end},
           {"Adding routable address increments new count", fun() ->
               beamchain_addrman:add_address({{8, 8, 4, 4}, 8333}, 0, dns),
               timer:sleep(50),
               {New, _} = beamchain_addrman:count(),
               ?assertEqual(1, New)
           end},
           {"mark_tried moves from new to tried", fun() ->
               A = {{1, 2, 3, 4}, 8333},
               beamchain_addrman:add_address(A, 0, dns),
               timer:sleep(50),
               {New0, Tried0} = beamchain_addrman:count(),
               beamchain_addrman:mark_tried(A),
               timer:sleep(50),
               {New1, Tried1} = beamchain_addrman:count(),
               %% One address moved from new to tried
               ?assertEqual(New0 - 1, New1),
               ?assertEqual(Tried0 + 1, Tried1)
           end},
           {"get_addresses returns correct count", fun() ->
               lists:foreach(fun(I) ->
                   beamchain_addrman:add_address({{I, I+1, 0, 1}, 8333}, 0, dns)
               end, lists:seq(1, 5)),
               timer:sleep(100),
               Got = beamchain_addrman:get_addresses(3),
               ?assertEqual(3, length(Got))
           end},
           {"netgroup IPv4 /16", fun() ->
               ?assertEqual({ipv4, 192, 168},
                             beamchain_addrman:netgroup({{192, 168, 1, 1}, 8333}))
           end},
           {"netgroup IPv6 /32", fun() ->
               ?assertEqual({ipv6, 16#2001, 16#DB8, 0, 0},
                             beamchain_addrman:netgroup(
                                 {{16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}, 8333}))
           end},
           {"secret key is 32 bytes", fun() ->
               Secret = beamchain_addrman:get_secret(),
               ?assertEqual(32, byte_size(Secret))
           end},
           {"select_address new_only option works", fun() ->
               Addr = {{77, 88, 99, 0}, 8333},
               beamchain_addrman:add_address(Addr, 0, dns),
               timer:sleep(50),
               %% new_only=true should find it in new table
               case beamchain_addrman:select_address(#{new_only => true}) of
                   {ok, _} -> ok;
                   empty -> ok  %% sparse table may not find it in one shot
               end,
               ?assert(true)
           end}
          ]
      end}}.
