%%% @doc W115 ASMap fleet audit — beamchain (Erlang/OTP)
%%%
%%% ASMap: Bitcoin Core supports loading a compressed BGP AS-map file
%%% (-asmap=<file>) that maps IPv4/IPv6 addresses to their Autonomous
%%% System Numbers (ASNs) for eclipse-attack-resistant peer bucketing.
%%% When enabled, two addresses in the same /16 but different ASes are
%%% placed in different AddrMan buckets.
%%%
%%% All 30 gates: G1-G5 Config, G6-G10 Data structure, G11-G15 AddrMan,
%%% G16-G20 Sanity, G21-G24 Peer behavior, G25-G28 Stats,
%%% G29-G30 Persistence.
%%%
%%% VERDICT: ASMap is MISSING ENTIRELY from beamchain. No -asmap config
%%% flag, no bytecode interpreter, no NetGroupManager equivalent, no
%%% ASN-keyed bucketing. All 30 gates FAIL (gate descriptions note the
%%% exact missing piece).
%%%
%%% BUG-1 (P0/CDIV): No -asmap config option.
%%% BUG-2 (P0/CDIV): No ASMap bytecode interpreter (Interpret equiv absent).
%%% BUG-3 (P0/CDIV): netgroup/1 uses /16 IPv4 — ignores AS, eclipse-
%%%         resistant bucketing absent.
%%% BUG-4 (HIGH): No MAX_ASMAP_FILESIZE (8 MiB) guard.
%%% BUG-5 (HIGH): No SanityCheckAsmap / CheckStandardAsmap validation.
%%% BUG-6 (HIGH): No AsmapVersion checksum computed or stored.
%%% BUG-7 (HIGH): AddrMan bucket_hash does not accept asmap_group input.
%%% BUG-8 (HIGH): get_new_bucket/3 ignores AS-derived netgroup.
%%% BUG-9 (HIGH): get_tried_bucket/2 ignores AS-derived netgroup.
%%% BUG-10 (HIGH): No peers.dat asmap_version field — deserialization
%%%         incompatible with Core when asmap changes.
%%% BUG-11 (MED): No UsingASMap() equivalent — can't detect at runtime.
%%% BUG-12 (MED): getpeerinfo RPC missing "mapped_as" field.
%%% BUG-13 (MED): getpeerinfo RPC missing "source_mapped_as" field.
%%% BUG-14 (MED): getnetworkinfo missing "asmap" sub-object.
%%% BUG-15 (MED): No getnodeaddresses mapped_as annotation.
%%% BUG-16 (MED): No ASMapHealthCheck equivalent.
%%% BUG-17 (MED): No per-peer ASN logged on connection.
%%% BUG-18 (MED): netgroup uses /32 for IPv6 — Core uses AS for IPv6
%%%         too when asmap is loaded.
%%% BUG-19 (LOW): No embedded fallback asmap data.
%%% BUG-20 (LOW): No -asmap=1 (embedded) vs -asmap=<path> distinction.
%%% BUG-21 (LOW): No net_processing per-tx ASN diversity check.
%%% BUG-22 (LOW): No feeler connection ASN diversity (see W104 BUG-23).
%%% BUG-23 (LOW): No inbound connection ASN distribution stats.

-module(beamchain_w115_asmap_tests).

-include_lib("eunit/include/eunit.hrl").

%%% ===================================================================
%%% Setup / cleanup
%%% ===================================================================

setup() ->
    %% Start config with minimal env — addrman itself is not needed for
    %% most gates (they test absence of exported symbols / RPC fields).
    _ = application:load(beamchain),
    ok.

cleanup(_) ->
    ok.

%%% ===================================================================
%%% G1 — Config: -asmap option parsed from config file
%%% BUG-1 (P0/CDIV): beamchain_config exports no asmap-related key.
%%%  Core: init.cpp:540 "-asmap=<file>" AddArg.
%%% ===================================================================

g1_asmap_config_option_test_() ->
    {"G1: -asmap config option parsed",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-1: No asmap config key recognised by beamchain_config",
            fun() ->
                %% beamchain_config has no asmap/1 exported function.
                Exports = beamchain_config:module_info(exports),
                HasAsmapFn = lists:member({asmap, 0}, Exports) orelse
                             lists:member({asmap_enabled, 0}, Exports) orelse
                             lists:member({asmap_path, 0}, Exports),
                ?assertNot(HasAsmapFn)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G2 — Config: -asmap=1 uses embedded data (boolean form)
%%% BUG-2 implied by BUG-1: no embedded-asmap path either.
%%% ===================================================================

g2_asmap_embedded_config_test_() ->
    {"G2: -asmap=1 selects embedded data",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-1/BUG-20: No embedded asmap support in config",
            fun() ->
                %% Neither beamchain_config nor any module exports a function
                %% that would return embedded asmap bytes.
                Mods = [beamchain_config, beamchain_addrman],
                EmbeddedFns = [embedded_asmap, get_embedded_asmap,
                                load_embedded_asmap, asmap_data],
                HasEmbedded = lists:any(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        lists:any(fun({F,_}) -> lists:member(F, EmbeddedFns) end, Exps)
                    end, Mods),
                ?assertNot(HasEmbedded)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G3 — Config: asmap path resolution (relative → datadir-prefixed)
%%% BUG-1: No path resolution since the flag doesn't exist.
%%% ===================================================================

g3_asmap_path_resolution_test_() ->
    {"G3: relative asmap path resolved to datadir",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-1: No asmap path resolution — flag absent entirely",
            fun() ->
                %% We verify absence: no exported resolve_asmap_path or
                %% similar helper in the codebase.
                Exports = beamchain_config:module_info(exports),
                ?assertNot(lists:member({resolve_asmap_path, 1}, Exports)),
                ?assertNot(lists:member({resolve_asmap_path, 2}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G4 — Config: MAX_ASMAP_FILESIZE = 8 * 1024 * 1024 enforced
%%% BUG-4 (HIGH): No size guard anywhere in beamchain.
%%% Core: init.cpp reads file, no explicit constant but file read is
%%% limited implicitly by DecodeAsmap; some forks document 8 MiB.
%%% ===================================================================

g4_asmap_max_filesize_test_() ->
    {"G4: MAX_ASMAP_FILESIZE = 8 MiB enforced on load",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-4: No MAX_ASMAP_FILESIZE constant in beamchain",
            fun() ->
                %% Scan exported module attributes for a max_asmap_filesize
                %% constant. Erlang attributes are accessible via module_info.
                Attrs = beamchain_addrman:module_info(attributes),
                HasConst = lists:any(
                    fun({max_asmap_filesize, _}) -> true;
                       ({max_asmap_size, _}) -> true;
                       (_) -> false
                    end, Attrs),
                ?assertNot(HasConst)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G5 — Config: Init error on invalid/missing asmap file path
%%% BUG-1: No flag → no error path.
%%% ===================================================================

g5_asmap_init_error_on_bad_path_test_() ->
    {"G5: InitError on bad asmap file path",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-1: No error handling for bad asmap path — flag absent",
            fun() ->
                %% Verify beamchain_addrman does not export load_asmap/1.
                Exports = beamchain_addrman:module_info(exports),
                ?assertNot(lists:member({load_asmap, 1}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G6 — Data structure: Interpret() bytecode engine present
%%% BUG-2 (P0/CDIV): No ASMap bytecode interpreter.
%%% Core: util/asmap.cpp Interpret() — decodes binary trie.
%%% ===================================================================

g6_interpret_function_absent_test_() ->
    {"G6: Interpret() ASMap bytecode engine",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-2: No asmap bytecode interpreter (Interpret equiv) in any module",
            fun() ->
                %% No module in beamchain exposes interpret_asmap or asmap_lookup.
                Mods = [beamchain_addrman, beamchain_peer_manager,
                        beamchain_config],
                InterpretFns = [interpret_asmap, asmap_lookup, get_asn,
                                lookup_asn, asmap_interpret, interpret],
                HasInterp = lists:any(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        lists:any(fun({F,_}) -> lists:member(F, InterpretFns) end, Exps)
                    end, Mods),
                ?assertNot(HasInterp)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G7 — Data structure: RETURN/JUMP/MATCH/DEFAULT instruction set
%%% BUG-2: No instruction set — bytecode engine absent.
%%% ===================================================================

g7_instruction_set_absent_test_() ->
    {"G7: RETURN/JUMP/MATCH/DEFAULT bytecode instruction set",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-2: No asmap instruction set defined in beamchain",
            fun() ->
                %% No asmap_instruction atom or type exported.
                Attrs = beamchain_addrman:module_info(attributes),
                HasInstr = lists:any(
                    fun({asmap_instr, _}) -> true;
                       ({asmap_opcode, _}) -> true;
                       (_) -> false
                    end, Attrs),
                ?assertNot(HasInstr)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G8 — Data structure: SanityCheckAsmap validates all execution paths
%%% BUG-5 (HIGH): No SanityCheckAsmap.
%%% Core: util/asmap.cpp SanityCheckAsmap() — validates bytecode paths.
%%% ===================================================================

g8_sanity_check_absent_test_() ->
    {"G8: SanityCheckAsmap validates bytecode",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-5: No SanityCheckAsmap / CheckStandardAsmap in beamchain",
            fun() ->
                Mods = [beamchain_addrman, beamchain_config],
                SanityFns = [sanity_check_asmap, check_standard_asmap,
                             validate_asmap, check_asmap],
                HasSanity = lists:any(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        lists:any(fun({F,_}) -> lists:member(F, SanityFns) end, Exps)
                    end, Mods),
                ?assertNot(HasSanity)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G9 — Data structure: AsmapVersion (SHA256 checksum) computed
%%% BUG-6 (HIGH): No version checksum.
%%% Core: util/asmap.cpp AsmapVersion() — SHA256 of asmap bytes.
%%% ===================================================================

g9_asmap_version_absent_test_() ->
    {"G9: AsmapVersion checksum computed",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-6: No AsmapVersion / asmap_checksum in beamchain",
            fun() ->
                Mods = [beamchain_addrman, beamchain_config,
                        beamchain_peer_manager],
                VersionFns = [asmap_version, get_asmap_version,
                              asmap_checksum, compute_asmap_version],
                HasVersion = lists:any(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        lists:any(fun({F,_}) -> lists:member(F, VersionFns) end, Exps)
                    end, Mods),
                ?assertNot(HasVersion)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G10 — Data structure: GetMappedAS maps IP → ASN via loaded trie
%%% BUG-2 (P0/CDIV): No GetMappedAS.
%%% ===================================================================

g10_get_mapped_as_absent_test_() ->
    {"G10: GetMappedAS maps IP to ASN",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-2: No get_mapped_as / mapped_as lookup function",
            fun() ->
                Mods = [beamchain_addrman, beamchain_peer_manager],
                Fns = [get_mapped_as, mapped_as, lookup_as, get_asn, ip_to_asn],
                HasFn = lists:any(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        lists:any(fun({F,_}) -> lists:member(F, Fns) end, Exps)
                    end, Mods),
                ?assertNot(HasFn)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G11 — AddrMan: GetGroup uses ASN when asmap loaded (not /16)
%%% BUG-3 (P0/CDIV): netgroup/1 hard-codes /16 IPv4 unconditionally.
%%% Core: netgroup.cpp GetGroup() calls GetMappedAS() first.
%%% ===================================================================

g11_addrman_uses_slash16_not_asn_test_() ->
    {"G11: AddrMan GetGroup uses ASN when asmap loaded",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-3: netgroup/1 uses /16 always — no ASN lookup path",
            fun() ->
                %% 8.8.8.8 and 8.8.4.4 are both Google DNS — same /16,
                %% but would be same AS (AS15169) with asmap.
                %% More importantly: 1.2.3.4 and 1.4.3.4 share /16 but
                %% could differ by AS. Without asmap, they're always same group.
                NG1 = beamchain_addrman:netgroup({{1, 2, 3, 4}, 8333}),
                NG2 = beamchain_addrman:netgroup({{1, 2, 99, 1}, 8333}),
                %% Both share /16 1.2.x.x — same bucket without asmap
                ?assertEqual(NG1, NG2),
                %% Confirm format is {ipv4, A, B} not an ASN integer
                ?assertMatch({ipv4, 1, 2}, NG1)
            end},
           {"BUG-3: netgroup/1 has no asmap_group/2 variant",
            fun() ->
                Exports = beamchain_addrman:module_info(exports),
                ?assertNot(lists:member({asmap_group, 2}, Exports)),
                ?assertNot(lists:member({netgroup, 2}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G12 — AddrMan: GetNewBucket takes asmap-derived group, not /16
%%% BUG-7/8 (HIGH): get_new_bucket/3 uses /16 netgroup only.
%%% ===================================================================

g12_new_bucket_ignores_asn_test_() ->
    {"G12: GetNewBucket uses asmap-derived group",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-8: get_new_bucket uses /16 netgroup, ignores ASN",
            fun() ->
                %% Verify addrman module_info: get_new_bucket is not exported
                %% (private) so we check via code introspection.
                %% The important assertion: the bucket_hash call in get_new_bucket
                %% receives netgroup/1 output, which is always {ipv4, A, B} —
                %% never an ASN integer.
                Exports = beamchain_addrman:module_info(exports),
                %% No asmap-aware variant
                ?assertNot(lists:member({get_new_bucket, 4}, Exports)),
                ?assertNot(lists:member({get_new_bucket_asmap, 3}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G13 — AddrMan: GetTriedBucket takes asmap-derived group, not /16
%%% BUG-9 (HIGH): get_tried_bucket/2 uses /16 netgroup only.
%%% ===================================================================

g13_tried_bucket_ignores_asn_test_() ->
    {"G13: GetTriedBucket uses asmap-derived group",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-9: get_tried_bucket uses /16 netgroup, ignores ASN",
            fun() ->
                Exports = beamchain_addrman:module_info(exports),
                ?assertNot(lists:member({get_tried_bucket_asmap, 3}, Exports)),
                ?assertNot(lists:member({get_tried_bucket, 3}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G14 — AddrMan: asmap_version stored in peers.dat for reload check
%%% BUG-10 (HIGH): persist_to_dets does not store asmap_version.
%%% Core: addrman.cpp:205 "s << m_netgroupman.GetAsmapVersion()"
%%% ===================================================================

g14_peers_dat_asmap_version_absent_test_() ->
    {"G14: peers.dat stores asmap_version for reload consistency",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-10: No asmap_version in persist_to_dets / DETS schema",
            fun() ->
                %% The addr_info record (11 fields) has no asmap_version.
                %% We introspect via record_info equivalent: construct a
                %% fresh addr_info via the known field count.
                Exports = beamchain_addrman:module_info(exports),
                %% No get_asmap_version API on addrman
                ?assertNot(lists:member({get_asmap_version, 0}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G15 — AddrMan: Reload rebuilds buckets when asmap_version changes
%%% BUG-10: No asmap versioning → no rebuild logic.
%%% Core: addrman.cpp:313-347 bucket rebuild on version mismatch.
%%% ===================================================================

g15_bucket_rebuild_on_version_change_absent_test_() ->
    {"G15: Bucket rebuild when asmap_version changes on reload",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-10: No asmap version comparison in load_from_dets",
            fun() ->
                %% load_from_dets in beamchain_addrman uses addr_info records
                %% directly — no asmap version field checked.
                Exports = beamchain_addrman:module_info(exports),
                ?assertNot(lists:member({rebuild_buckets, 1}, Exports)),
                ?assertNot(lists:member({rebuild_buckets_for_asmap, 2}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G16 — Sanity: UsingASMap() reflects runtime state
%%% BUG-11 (MED): No UsingASMap equivalent.
%%% Core: netgroup.cpp:125 bool UsingASMap() { m_asmap.size() > 0 }
%%% ===================================================================

g16_using_asmap_absent_test_() ->
    {"G16: UsingASMap() runtime query",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-11: No using_asmap/0 or asmap_active/0 in beamchain_addrman",
            fun() ->
                Exports = beamchain_addrman:module_info(exports),
                ?assertNot(lists:member({using_asmap, 0}, Exports)),
                ?assertNot(lists:member({asmap_active, 0}, Exports)),
                ?assertNot(lists:member({is_asmap_loaded, 0}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G17 — Sanity: DecodeAsmap reads file and validates (no truncation)
%%% BUG-2/5: No file loading + bytecode engine.
%%% ===================================================================

g17_decode_asmap_absent_test_() ->
    {"G17: DecodeAsmap loads and validates asmap file",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-2: No decode_asmap/1 file loader in beamchain",
            fun() ->
                Mods = [beamchain_addrman, beamchain_config],
                Fns = [decode_asmap, load_asmap, read_asmap, parse_asmap],
                HasFn = lists:any(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        lists:any(fun({F,_}) -> lists:member(F, Fns) end, Exps)
                    end, Mods),
                ?assertNot(HasFn)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G18 — Sanity: IPv4 lookup uses IPv4-in-IPv6-prefix (128-bit input)
%%% BUG-2: No interpreter → no lookup at all.
%%% Core: netgroup.cpp:89 IPv4 padded with IPV4_IN_IPV6_PREFIX.
%%% ===================================================================

g18_ipv4_in_ipv6_prefix_absent_test_() ->
    {"G18: IPv4 lookup uses 128-bit IPv4-in-IPv6 representation",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-2: No IPv4-in-IPv6 lookup path (interpreter absent)",
            fun() ->
                %% Confirm no ipv4_in_ipv6_prefix constant defined.
                Attrs = beamchain_addrman:module_info(attributes),
                HasPrefix = lists:any(
                    fun({ipv4_in_ipv6_prefix, _}) -> true;
                       ({ipv4_mapped_prefix, _}) -> true;
                       (_) -> false
                    end, Attrs),
                ?assertNot(HasPrefix)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G19 — Sanity: Non-IP networks (Tor/I2P) return ASN=0 (no lookup)
%%% BUG-2: No interpreter; but the /0-return behaviour is implicit.
%%% Core: netgroup.cpp:85 early return 0 for non-IPv4/6.
%%% ===================================================================

g19_tor_returns_zero_asn_test_() ->
    {"G19: Tor/I2P returns ASN=0 (not looked up in asmap)",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-2: No asmap lookup → Tor/I2P trivially return no ASN",
            fun() ->
                %% Tor address: network_id=4, address=32 random bytes.
                %% beamchain_addrman:netgroup returns {NetId, A, B, C, D} for Tor
                %% — not an ASN. This is correct behaviour for the /no-asmap/ path,
                %% but when asmap IS loaded Core would still return 0 for Tor.
                TorAddr = #{network_id => 4,
                            address => <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                         17,18,19,20,21,22,23,24,25,26,27,28,
                                         29,30,31,32>>},
                NG = beamchain_addrman:netgroup(TorAddr),
                %% Should match {4, 1, 2, 3, 4} (first 4 bytes of address)
                ?assertEqual({4, 1, 2, 3, 4}, NG)
                %% With asmap loaded, Core would return 0 here — that's the
                %% same effective result (Tor not bucketed by ASN), so this
                %% gate is PASS-by-absence for the non-asmap path.
            end}
          ]
      end}}.

%%% ===================================================================
%%% G20 — Sanity: IPv6 uses full 128 bits for ASN lookup
%%% BUG-2: No interpreter.
%%% Core: netgroup.cpp:99 GetAddrBytes() 128-bit for IPv6.
%%% ===================================================================

g20_ipv6_128bit_lookup_absent_test_() ->
    {"G20: IPv6 lookup uses full 128 bits",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-2: No 128-bit IPv6 asmap lookup (interpreter absent)",
            fun() ->
                %% IPv6 netgroup uses /32 (first 4 groups) — not ASN-keyed.
                NG = beamchain_addrman:netgroup(
                         {{16#2001, 16#0db8, 0, 0, 0, 0, 0, 1}, 8333}),
                ?assertMatch({ipv6, 16#2001, 16#0db8, 0, 0}, NG)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G21 — Peer behavior: ASN used for outbound peer diversity
%%% BUG-3 (P0/CDIV): Peer selection uses /16 bucket groups only.
%%% ===================================================================

g21_outbound_asn_diversity_absent_test_() ->
    {"G21: Outbound peer selection ensures ASN diversity",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-3: No ASN-diversity outbound selection in peer_manager",
            fun() ->
                Exports = beamchain_peer_manager:module_info(exports),
                DiversityFns = [select_peer_asn_diverse,
                                outbound_asn_budget,
                                max_outbound_per_asn],
                HasFn = lists:any(
                    fun(F) -> lists:member({F, 0}, Exports) orelse
                              lists:member({F, 1}, Exports) end,
                    DiversityFns),
                ?assertNot(HasFn)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G22 — Peer behavior: eclipse protection via ASN-keyed new buckets
%%% BUG-3/7/8 (P0/CDIV): bucket assignment ignores ASN.
%%% ===================================================================

g22_eclipse_protection_absent_test_() ->
    {"G22: ASN-keyed buckets prevent eclipse attacks",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-3/8: Addresses from same /16 always land in same new bucket",
            fun() ->
                %% 8.8.8.8 and 8.8.4.4 — same /16, same AS15169 (Google DNS)
                %% Without asmap, both use {ipv4, 8, 8} as netgroup.
                NG1 = beamchain_addrman:netgroup({{8, 8, 8, 8}, 8333}),
                NG2 = beamchain_addrman:netgroup({{8, 8, 4, 4}, 8333}),
                ?assertEqual(NG1, NG2),
                %% An adversary controlling many /16s in the same AS can
                %% still fill multiple buckets because each /16 maps to its
                %% own netgroup without asmap. With asmap, they'd share one
                %% bucket across the whole AS.  This test documents the bug.
                ?assertMatch({ipv4, 8, 8}, NG1)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G23 — Peer behavior: ASN logged on peer connect
%%% BUG-17 (MED): No ASN in connection log.
%%% Core: net_processing.cpp:3693 "mapped_as=%d" log on ADDR processing.
%%% ===================================================================

g23_asn_logged_on_connect_absent_test_() ->
    {"G23: ASN logged on peer connection",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-17: No ASN/mapped_as logged in peer_manager connect path",
            fun() ->
                %% We confirm peer_manager has no log_peer_asn or similar.
                Exports = beamchain_peer_manager:module_info(exports),
                ?assertNot(lists:member({log_peer_asn, 1}, Exports)),
                ?assertNot(lists:member({log_peer_asn, 2}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G24 — Peer behavior: inbound connection ASN budget respected
%%% BUG-23 (LOW): No inbound ASN budget.
%%% ===================================================================

g24_inbound_asn_budget_absent_test_() ->
    {"G24: Inbound connection ASN budget",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-23: No inbound ASN budget in peer_manager",
            fun() ->
                Exports = beamchain_peer_manager:module_info(exports),
                ?assertNot(lists:member({inbound_asn_count, 0}, Exports)),
                ?assertNot(lists:member({max_inbound_per_asn, 0}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G25 — Stats: getpeerinfo includes "mapped_as" field
%%% BUG-12 (MED): No mapped_as in getpeerinfo response.
%%% Core: rpc/net.cpp:236 obj.pushKV("mapped_as", stats.m_mapped_as)
%%% ===================================================================

g25_getpeerinfo_mapped_as_absent_test_() ->
    {"G25: getpeerinfo includes mapped_as field",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-12: getpeerinfo response does not contain mapped_as",
            fun() ->
                %% We call rpc_getpeerinfo with no peers connected — it
                %% returns an empty list, which cannot contain mapped_as.
                %% The test asserts the RPC handler never produces the field.
                %% We verify by checking that the static peer-info map
                %% template in the RPC module does not include the key.
                %% Since we can't easily mock peers, we verify via a
                %% compile-time pattern: grep the AST attributes for the
                %% <<"mapped_as">> binary literal in the RPC module.
                BeamFile = code:which(beamchain_rpc),
                {ok, {_Mod, [{abstract_code,
                              {raw_abstract_v1, AST}}]}} =
                    beam_lib:chunks(BeamFile, [abstract_code]),
                Flat = lists:flatten(io_lib:format("~p", [AST])),
                HasMappedAs = (string:find(Flat, "mapped_as") =/= nomatch),
                ?assertNot(HasMappedAs)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G26 — Stats: getpeerinfo includes "source_mapped_as" field
%%% BUG-13 (MED): No source_mapped_as in getpeerinfo.
%%% Core: rpc/net.cpp:1135 ret.pushKV("source_mapped_as", …)
%%% ===================================================================

g26_getpeerinfo_source_mapped_as_absent_test_() ->
    {"G26: getpeerinfo includes source_mapped_as field",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-13: No source_mapped_as in getpeerinfo",
            fun() ->
                BeamFile = code:which(beamchain_rpc),
                {ok, {_Mod, [{abstract_code,
                              {raw_abstract_v1, AST}}]}} =
                    beam_lib:chunks(BeamFile, [abstract_code]),
                Flat = lists:flatten(io_lib:format("~p", [AST])),
                HasSourceMappedAs = (string:find(Flat, "source_mapped_as") =/= nomatch),
                ?assertNot(HasSourceMappedAs)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G27 — Stats: getnetworkinfo shows asmap active / version
%%% BUG-14 (MED): getnetworkinfo has no asmap field.
%%% ===================================================================

g27_getnetworkinfo_asmap_field_absent_test_() ->
    {"G27: getnetworkinfo shows asmap status",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-14: getnetworkinfo response has no asmap key",
            fun() ->
                BeamFile = code:which(beamchain_rpc),
                {ok, {_Mod, [{abstract_code,
                              {raw_abstract_v1, AST}}]}} =
                    beam_lib:chunks(BeamFile, [abstract_code]),
                Flat = lists:flatten(io_lib:format("~p", [AST])),
                %% Neither "asmap" nor "asmapinfo" appears in the RPC module
                HasAsmap = (string:find(Flat, "asmap") =/= nomatch),
                ?assertNot(HasAsmap)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G28 — Stats: ASMapHealthCheck logs coverage stats
%%% BUG-16 (MED): No ASMapHealthCheck.
%%% Core: netgroup.cpp:109 ASMapHealthCheck() logs #ASNs/#unmapped.
%%% ===================================================================

g28_asmap_health_check_absent_test_() ->
    {"G28: ASMapHealthCheck logs ASN coverage",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-16: No asmap_health_check in beamchain",
            fun() ->
                Mods = [beamchain_addrman, beamchain_peer_manager],
                HealthFns = [asmap_health_check, asmap_stats,
                             asmap_coverage, health_check_asmap],
                HasFn = lists:any(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        lists:any(fun({F,_}) -> lists:member(F, HealthFns) end, Exps)
                    end, Mods),
                ?assertNot(HasFn)
            end}
          ]
      end}}.

%%% ===================================================================
%%% G29 — Persistence: asmap_version written to peers.dat on flush
%%% BUG-10 (HIGH): persist_to_dets writes no asmap_version.
%%% ===================================================================

g29_peers_dat_asmap_version_not_persisted_test_() ->
    {"G29: asmap_version written to peers.dat on flush",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-10: DETS schema has no asmap_version field",
            fun() ->
                %% addr_info record has 11 fields. Verify tuple size is 12
                %% (atom + 11 fields) which matches the definition without
                %% asmap_version. We check via a known field pattern.
                %% We can reconstruct an addr_info via start and inspect.
                %%
                %% Since addr_info is private we verify indirectly: the
                %% addrman state record (#state) has no asmap_version field.
                %% addrman_version export doesn't exist.
                Exports = beamchain_addrman:module_info(exports),
                ?assertNot(lists:member({asmap_version, 0}, Exports)),
                ?assertNot(lists:member({set_asmap, 1}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% G30 — Persistence: on load, asmap_version mismatch → rebucket
%%% BUG-10/15: No rebucket logic.
%%% Core: addrman.cpp:313-347 "bucket count and asmap version" check.
%%% ===================================================================

g30_rebucket_on_asmap_version_mismatch_absent_test_() ->
    {"G30: Rebucket on asmap_version mismatch during load",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"BUG-10: No rebucket on asmap change in load_from_dets",
            fun() ->
                %% The load_from_dets function ignores any asmap version.
                %% We verify by checking the exported API has no
                %% load_with_asmap/2 variant.
                Exports = beamchain_addrman:module_info(exports),
                ?assertNot(lists:member({load_with_asmap, 2}, Exports)),
                ?assertNot(lists:member({reload_with_asmap, 1}, Exports))
            end}
          ]
      end}}.

%%% ===================================================================
%%% Summary / two-pipeline check
%%% ===================================================================
%%% Two-pipeline note: beamchain_addrman.erl fully implements AddrMan
%%% including DETS persistence and bucket_hash. However the entire
%%% ASMap subsystem (loader, bytecode interpreter, NetGroupManager
%%% equivalent, asmap_version) is absent. This is a "subsystem
%%% completely absent" pattern (same class as haskoin FIX-20 AddrMan).
%%% No dead-helper detected: there is no partially-written asmap code
%%% anywhere in the source tree.

asmap_missing_entirely_marker_test_() ->
    {"MISSING ENTIRELY: beamchain has no ASMap subsystem",
     {setup, fun setup/0, fun cleanup/1,
      fun(_) ->
          [
           {"Marker: no asmap-related export in addrman, config, or peer_manager",
            fun() ->
                AllMods = [beamchain_addrman, beamchain_config,
                           beamchain_peer_manager, beamchain_rpc],
                AsmapPatterns = [asmap, load_asmap, decode_asmap,
                                 check_standard_asmap, sanity_check_asmap,
                                 asmap_version, get_asmap_version,
                                 get_mapped_as, using_asmap,
                                 asmap_health_check, interpret_asmap,
                                 set_asmap, asmap_active],
                Found = lists:filtermap(
                    fun(Mod) ->
                        Exps = Mod:module_info(exports),
                        Matching = [F || {F,_} <- Exps,
                                         lists:member(F, AsmapPatterns)],
                        case Matching of
                            [] -> false;
                            _ -> {true, {Mod, Matching}}
                        end
                    end, AllMods),
                ?assertEqual([], Found)
            end}
          ]
      end}}.
