-module(beamchain_w141_zmq_rest_notify_tests).

%%% -------------------------------------------------------------------
%%% W141 — ZMQ + REST + Notification scripts audit (DISCOVERY-ONLY).
%%%
%%% Cross-references beamchain's external-observer surface (ZMQ pub
%%% notifier, REST HTTP server, external-command notify hooks) against
%%% Bitcoin Core's `zmq/zmqnotificationinterface.cpp`,
%%% `zmq/zmqpublishnotifier.cpp`, `rest.cpp`, `init.cpp`,
%%% `common/system.cpp`. These tests are NOT meant to all pass as
%%% PASS-meaning-correct: gates marked PRESENT assert Core-parity
%%% invariants (and DO pass); gates marked PARTIAL or MISSING assert
%%% the *current divergent behavior* using the "audit-flip" convention
%%% — when a later FIX wave brings the implementation into parity,
%%% these tests will FAIL and force an update. Same convention as
%%% W94/95/120/121/125/127/130/131/132/133/135/137.
%%%
%%% NO PRODUCTION CODE CHANGES IN THIS COMMIT. This is a discovery
%%% wave; the production code stays exactly as-is.
%%%
%%% Reference Core source:
%%%   src/zmq/zmqnotificationinterface.cpp — kernel-notification
%%%     fan-out (UpdatedBlockTip / BlockConnected / BlockDisconnected /
%%%     TransactionAddedToMempool / TransactionRemovedFromMempool).
%%%   src/zmq/zmqpublishnotifier.cpp — per-topic notifier subclasses,
%%%     multipart [topic, body, LE32(nSequence)] wire format,
%%%     SendSequenceMsg for the sequence topic.
%%%   src/zmq/zmqabstractnotifier.h — DEFAULT_ZMQ_SNDHWM = 1000.
%%%   src/rest.cpp — REST URL routes, MAX_GETUTXOS_OUTPOINTS = 15,
%%%     MAX_REST_HEADERS_RESULTS = 2000.
%%%   src/init.cpp — DEFAULT_REST_ENABLE = false, -blocknotify wiring
%%%     at lines 2009-2018, -shutdownnotify at 255-265,
%%%     -startupnotify at 737-745.
%%%   src/common/system.cpp — runCommand(strCommand) →
%%%     ::system(c_str()) at lines 50-61, ShellEscape() at 41-46.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

%%% ===================================================================
%%% Test fixtures
%%% ===================================================================

sample_block_header() ->
    #block_header{
        version = 1,
        prev_hash = <<0:256>>,
        merkle_root = <<1:256>>,
        timestamp = 1234567890,
        bits = 16#1d00ffff,
        nonce = 0
    }.

sample_coinbase_tx() ->
    #transaction{
        version = 1,
        inputs = [
            #tx_in{
                prev_out = #outpoint{hash = <<0:256>>, index = 16#ffffffff},
                script_sig = <<4, 1, 2, 3, 4>>,
                sequence = 16#ffffffff,
                witness = []
            }
        ],
        outputs = [
            #tx_out{
                value = 5000000000,
                script_pubkey = <<118, 169, 20, 0:160, 136, 172>>
            }
        ],
        locktime = 0
    }.

sample_block() ->
    #block{header = sample_block_header(),
           transactions = [sample_coinbase_tx()]}.

%%% ===================================================================
%%% Subsystem 1: ZMQ (G01-G10)
%%% ===================================================================

%%% G01 PRESENT: five ZMQ topic name binaries match Core's MSG_*
%%% constants in zmqpublishnotifier.cpp:33-37.
gate01_zmq_topic_names_match_core_test() ->
    %% Force-load the module so function_exported sees it under EUnit.
    {module, beamchain_zmq} = code:ensure_loaded(beamchain_zmq),
    ?assert(erlang:function_exported(beamchain_zmq, notify_block, 2)),
    ?assert(erlang:function_exported(beamchain_zmq, notify_transaction, 3)),
    ?assert(erlang:function_exported(beamchain_zmq, is_enabled, 0)),
    ?assert(erlang:function_exported(beamchain_zmq, get_endpoints, 0)),
    %% Source-level confirm: the five topic name binaries match Core's
    %% MSG_* constants ("hashblock" / "hashtx" / "rawblock" / "rawtx"
    %% / "sequence") from zmqpublishnotifier.cpp:33-37.
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    lists:foreach(fun(Name) ->
        ?assert(binary:match(Src,
            <<"<<\"", Name/binary, "\">>">>) =/= nomatch)
    end, [<<"hashblock">>, <<"hashtx">>, <<"rawblock">>,
          <<"rawtx">>, <<"sequence">>]),
    %% Sanity: with no zmq config in the test sandbox, is_enabled() is false.
    ?assertEqual(false, beamchain_zmq:is_enabled()),
    ?assertEqual(#{}, beamchain_zmq:get_endpoints()).

%%% G02 PRESENT: ZMQ multipart shape [topic, body, sequence_le32]
%%% matches Core's zmq_send_multipart(...command, data, msgseq, 4...)
%%% in zmqpublishnotifier.cpp:200.  Verified by inspection.
gate02_multipart_shape_documented_test() ->
    %% Module source carries the canonical comment line + the
    %% chumak:send_multipart call site at line ~340.
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    ?assert(binary:match(Src,
        <<"ZMQ multipart [topic, body, sequence_le32]">>) =/= nomatch),
    ?assert(binary:match(Src,
        <<"chumak:send_multipart(Socket, [Topic, Body, SeqLE])">>)
        =/= nomatch).

%%% G03 PRESENT: per-topic 32-bit wrapping sequence counter matches
%%% Core's nSequence++ + WriteLE32 at line 199.
gate03_zmq_sequence_counter_32bit_wrap_test() ->
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    %% Confirm the wrap mask exists (32-bit unsigned).
    ?assert(binary:match(Src, <<"band 16#ffffffff">>) =/= nomatch),
    %% Confirm the LE32 binary form exists.
    ?assert(binary:match(Src, <<"SeqNum:32/little">>) =/= nomatch).

%%% G04 PRESENT: sequence body for block connect ('C') / disconnect
%%% ('D') = <hash:32><label:1> (no LE64 trailer), per Core
%%% SendSequenceMsg with optional std::optional<uint64_t> sequence={}.
gate04_sequence_body_block_no_trailer_test() ->
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    %% Block connect/disconnect labels match Core 'C' / 'D'.
    ?assert(binary:match(Src, <<"SEQ_LABEL_CONNECT, $C">>) =/= nomatch),
    ?assert(binary:match(Src, <<"SEQ_LABEL_DISCONNECT, $D">>) =/= nomatch),
    %% Body construction at line ~254 has just <hash, label:8>
    %% (no LE64 trailer for block events).
    ?assert(binary:match(Src,
        <<"SeqBody = <<HashDisplay/binary, Label:8>>">>) =/= nomatch).

%%% G05 PRESENT: sequence body for mempool add ('A') / remove ('R') =
%%% <hash:32><label:1><mempool_seq:LE64>, per Core SendSequenceMsg
%%% with sequence set.
gate05_sequence_body_mempool_le64_test() ->
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    ?assert(binary:match(Src, <<"SEQ_LABEL_MEMPOOL_ADD, $A">>) =/= nomatch),
    ?assert(binary:match(Src, <<"SEQ_LABEL_MEMPOOL_REM, $R">>) =/= nomatch),
    %% Body construction at line ~324 includes MempoolSeq:64/little.
    ?assert(binary:match(Src, <<"MempoolSeq:64/little">>) =/= nomatch).

%%% G06 PARTIAL/BUG-1: hashtx/rawtx NOT republished on disconnect.
%%% Audit-flip: pin the *current* behaviour (disconnect → State4
%%% short-circuit) so a future fix wave that adds the disconnect tx
%%% fan-out will flip this assertion.
gate06_no_tx_publish_on_disconnect_test() ->
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    %% Audit-flip: confirm the short-circuit currently lives at line
    %% ~265 — "disconnect -> State4" without per-tx fold.
    %% Core re-publishes NotifyTransaction for every tx on disconnect
    %% (zmqnotificationinterface.cpp:200-205).
    ?assert(binary:match(Src, <<"disconnect ->\n            State4">>)
            =/= nomatch).

%%% G07 PARTIAL/BUG-2: hashblock/rawblock fire from per-connect path,
%%% NOT from UpdatedBlockTip with IBD/fork-only gate.  Audit-flip:
%%% pin the *current* call-site at chainstate connect_block_inner
%%% — Core would fire only when (!fInitialDownload &&
%%% pindexNew != pindexFork).
gate07_block_notify_fires_during_ibd_test() ->
    {ok, Cs} = file:read_file("src/beamchain_chainstate.erl"),
    %% Confirm the unconditional fire at the per-block-connect site.
    ?assert(binary:match(Cs,
        <<"beamchain_zmq:notify_block(Block, connect)">>) =/= nomatch),
    %% Confirm the absence of an IBD gate around the notify call.
    %% Core's gate: if (fInitialDownload || pindexNew == pindexFork) return;
    %% Search the 50 lines preceding the notify_block call for any
    %% IBD-related guard. Since file:read_file returns the whole
    %% body, we look for the textual pattern "is_synced" anywhere
    %% in the same vicinity. We CONFIRM the gate is currently MISSING
    %% by asserting the notify call site is NOT immediately preceded
    %% by an `is_synced()` clause in the source.
    NotifyOffset = case binary:match(Cs,
            <<"beamchain_zmq:notify_block(Block, connect)">>) of
        {O, _} -> O;
        nomatch -> -1
    end,
    ?assert(NotifyOffset > 0),
    %% Extract the 400 bytes preceding the notify call site.
    PrefixStart = max(0, NotifyOffset - 400),
    Prefix = binary:part(Cs, PrefixStart, NotifyOffset - PrefixStart),
    %% Currently the call is preceded by the BIP-157 filter index
    %% comment block, not by an IBD gate. Confirm.
    ?assertEqual(nomatch,
        binary:match(Prefix, <<"not beamchain_chainstate:is_synced">>)).

%%% G08 MISSING/BUG-14: no per-topic SNDHWM knob.
gate08_no_sndhwm_knob_test() ->
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    %% Audit-flip: source has no mention of sndhwm / high_water_mark
    %% / outbound_message_high_water_mark anywhere.
    ?assertEqual(nomatch, binary:match(Src, <<"sndhwm">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"high_water_mark">>)),
    ?assertEqual(nomatch,
        binary:match(Src, <<"outbound_message_high_water_mark">>)).

%%% G09 MISSING/BUG-15: no socket reuse for same-address topics.
gate09_no_socket_reuse_for_same_address_test() ->
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    %% setup_sockets/2 creates a fresh chumak socket per topic
    %% (chumak:socket(pub) followed by chumak:bind/4) with no
    %% address-keyed memoization. Core uses a multimap keyed by
    %% address. Audit-flip: pin the current per-topic-create
    %% pattern.
    ?assert(binary:match(Src, <<"chumak:socket(pub)">>) =/= nomatch),
    %% Confirm the absence of a mapPublishNotifiers-equivalent
    %% address->socket cache.
    ?assertEqual(nomatch, binary:match(Src, <<"mapPublishNotifiers">>)),
    ?assertEqual(nomatch, binary:match(Src, <<"AddressSocketCache">>)).

%%% G10 PARTIAL/BUG-3+BUG-4: list_to_atom + chumak:stop is a no-op.
gate10_atom_table_dos_and_stop_leak_test() ->
    {ok, Src} = file:read_file("src/beamchain_zmq.erl"),
    %% BUG-3: list_to_atom on operator-controlled protocol string.
    ?assert(binary:match(Src, <<"Protocol = list_to_atom(ProtoStr)">>)
            =/= nomatch),
    %% BUG-4: chumak:stop is called on each socket on terminate AND
    %% on each bind-failure cleanup AND on each socket-create error.
    %% chumak:stop/1 is the application stop callback (returns ok
    %% for any arg); these calls are no-ops, sockets leak.
    {ok, ChumakSrc} =
        file:read_file("_build/default/lib/chumak/src/chumak.erl"),
    ?assert(binary:match(ChumakSrc, <<"stop(_State) ->\n    ok.">>)
            =/= nomatch),
    %% Confirm beamchain calls chumak:stop on the bind/socket cleanup
    %% paths.
    StopCalls = [
        <<"catch chumak:stop(Sock)">>,
        <<"chumak:stop(Socket)">>
    ],
    lists:foreach(fun(C) ->
        ?assert(binary:match(Src, C) =/= nomatch)
    end, StopCalls).

%%% ===================================================================
%%% Subsystem 2: REST (G11-G22, G28, G29)
%%% ===================================================================

%%% G11 PRESENT: -rest=0 default (DEFAULT_REST_ENABLE = false in
%%% bitcoin-core/src/init.cpp:153).
gate11_rest_default_off_test() ->
    %% Ensure no env-var leak across tests.
    os:unsetenv("BEAMCHAIN_REST"),
    %% The config gen_server may or may not be running; use the
    %% ETS table fallback path.
    case ets:info(beamchain_config_ets) of
        undefined ->
            ets:new(beamchain_config_ets,
                    [named_table, set, public,
                     {read_concurrency, true}]);
        _ -> ok
    end,
    ets:delete(beamchain_config_ets, rest),
    ?assertEqual(false, beamchain_config:rest_enabled()).

%%% G12 PRESENT: MAX_GETUTXOS_OUTPOINTS = 15, MAX_REST_HEADERS_RESULTS
%%% = 2000.
gate12_rest_max_limits_test() ->
    %% Use the test exports from beamchain_rest to verify the
    %% header-count parser enforces the 2000 ceiling.
    ?assertMatch({error, _},
        beamchain_rest:parse_filterheaders_count(<<"2001">>)),
    ?assertEqual({ok, 2000},
        beamchain_rest:parse_filterheaders_count(<<"2000">>)),
    %% Source-level audit: MAX_GETUTXOS_OUTPOINTS = 15.
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    ?assert(binary:match(Src, <<"MAX_GETUTXOS_OUTPOINTS, 15">>)
            =/= nomatch),
    ?assert(binary:match(Src, <<"MAX_REST_HEADERS_RESULTS, 2000">>)
            =/= nomatch).

%%% G13 PRESENT: /rest/block/<h>.<f> route + /rest/block/notxdetails
%%% sub-route.
gate13_rest_block_routes_present_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    ?assert(binary:match(Src,
        <<"route_request([<<\"block\">>, HashWithFormat]">>)
        =/= nomatch),
    ?assert(binary:match(Src,
        <<"route_request([<<\"block\">>, <<\"notxdetails\">>,">>)
        =/= nomatch).

%%% G14 PRESENT: /rest/blockhashbyheight/<height>.<format> route.
gate14_rest_blockhashbyheight_route_present_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    ?assert(binary:match(Src,
        <<"route_request([<<\"blockhashbyheight\">>,">>) =/= nomatch).

%%% G15 PRESENT: BIP-157 /rest/blockfilter[headers] routes + wire
%%% encoding match Core byte-for-byte.
gate15_rest_blockfilter_routes_and_wire_test() ->
    %% Use the test exports to confirm wire encoding shape.
    Hash = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
             17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
             31, 32>>,
    %% Empty filter case: type || hash || varint(1) || 0x00.
    Wire = beamchain_rest:encode_blockfilter_wire(0, Hash, <<0>>),
    ?assertEqual(35, byte_size(Wire)),
    <<TypeByte:8, HashOut:32/binary, Tail/binary>> = Wire,
    ?assertEqual(0, TypeByte),
    ?assertEqual(Hash, HashOut),
    ?assertEqual(<<1, 0>>, Tail).

%%% G16 PARTIAL/BUG-5: /rest/mempool/contents.json ignores
%%% ?mempool_sequence=true query parameter.  Audit-flip.
gate16_no_mempool_sequence_query_param_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    %% Confirm beamchain only reads `verbose` from the query.
    ?assert(binary:match(Src,
        <<"Verbose = query_bool(Query, <<\"verbose\">>, true)">>)
        =/= nomatch),
    %% Audit-flip: confirm the absence of any mempool_sequence parse.
    ?assertEqual(nomatch, binary:match(Src, <<"mempool_sequence">>)).

%%% G17 PARTIAL/BUG-16: only GET accepted, HEAD rejected.
gate17_only_get_method_accepted_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    %% The init/2 Cowboy handler matches on <<"GET">> only.
    ?assert(binary:match(Src,
        <<"case cowboy_req:method(Req0) of\n        <<\"GET\">>">>)
        =/= nomatch),
    %% Audit-flip: confirm the absence of any HEAD branch.
    ?assertEqual(nomatch, binary:match(Src, <<"<<\"HEAD\">>">>)).

%%% G18 PARTIAL/BUG-17: wildcard CORS header on every reply.
gate18_cors_wildcard_present_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    %% Both reply_success and reply_error emit the wildcard.  Core
    %% emits no CORS header on the REST surface.
    Pattern = <<"access-control-allow-origin">>,
    ?assert(binary:match(Src, Pattern) =/= nomatch),
    %% Count occurrences: should appear at least twice (success +
    %% error paths).
    Matches = binary:matches(Src, Pattern),
    ?assert(length(Matches) >= 2).

%%% G19 PARTIAL/BUG-23: getutxos binary chaintipHash byte-reversed
%%% (display order) where Core sends internal order.
gate19_getutxos_binary_chaintip_byte_reversed_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    %% encode_utxos_binary at line ~1099 calls reverse_bytes on the
    %% chain hash, which yields display order.
    ?assert(binary:match(Src,
        <<"HashBin = beamchain_serialize:reverse_bytes(ChainHash)">>)
        =/= nomatch).

%%% G20 MISSING/BUG-6: no /rest/deploymentinfo route.
gate20_no_deploymentinfo_route_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    ?assertEqual(nomatch, binary:match(Src, <<"deploymentinfo">>)),
    %% Routing: parse_path on a /rest/deploymentinfo path resolves
    %% to a singleton list, and the catch-all returns 404 ("Endpoint
    %% not found").
    Result = beamchain_rest:parse_path(
        <<"/rest/deploymentinfo/abcd.json">>),
    %% The route would be [<<"deploymentinfo">>, <<"abcd.json">>],
    %% which doesn't match any case in route_request and falls
    %% through to the 404 catch-all.
    ?assertMatch([<<"deploymentinfo">>, <<"abcd.json">>], Result).

%%% G21 MISSING/BUG-7: no /rest/spenttxouts route.
gate21_no_spenttxouts_route_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    ?assertEqual(nomatch, binary:match(Src, <<"spenttxouts">>)),
    %% Path parse: /rest/spenttxouts/<txid>.json yields a list that
    %% falls through to the 404 catch-all.
    Result = beamchain_rest:parse_path(
        <<"/rest/spenttxouts/abcd.json">>),
    ?assertMatch([<<"spenttxouts">>, <<"abcd.json">>], Result).

%%% G22 MISSING/BUG-8: no /rest/blockpart route.
gate22_no_blockpart_route_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    ?assertEqual(nomatch, binary:match(Src, <<"blockpart">>)),
    %% Path parse: /rest/blockpart/<hash>.json yields a list that
    %% falls through to the 404 catch-all.
    Result = beamchain_rest:parse_path(
        <<"/rest/blockpart/abcd.json">>),
    ?assertMatch([<<"blockpart">>, <<"abcd.json">>], Result).

%%% ===================================================================
%%% Subsystem 3: Notify-scripts (G23-G27)
%%% ===================================================================

%%% G23 PRESENT (null gate): beamchain CLI does NOT advertise any of
%%% the five external-command notify options (W124 G28 cross-confirmed).
gate23_cli_no_notify_options_advertised_test() ->
    {ok, Cli} = file:read_file("src/beamchain_cli.erl"),
    ?assertEqual(nomatch, binary:match(Cli, <<"blocknotify">>)),
    ?assertEqual(nomatch, binary:match(Cli, <<"walletnotify">>)),
    ?assertEqual(nomatch, binary:match(Cli, <<"alertnotify">>)),
    ?assertEqual(nomatch, binary:match(Cli, <<"startupnotify">>)),
    ?assertEqual(nomatch, binary:match(Cli, <<"shutdownnotify">>)).

%%% G24 MISSING/BUG-9: -blocknotify external-command hook not wired.
gate24_no_blocknotify_hook_test() ->
    %% No beamchain source references blocknotify at all.
    {ok, Cfg} = file:read_file("src/beamchain_config.erl"),
    ?assertEqual(nomatch, binary:match(Cfg, <<"blocknotify">>)),
    {ok, Cs} = file:read_file("src/beamchain_chainstate.erl"),
    ?assertEqual(nomatch, binary:match(Cs, <<"blocknotify">>)).

%%% G25 MISSING/BUG-10: -walletnotify external-command hook not wired.
gate25_no_walletnotify_hook_test() ->
    {ok, Cfg} = file:read_file("src/beamchain_config.erl"),
    ?assertEqual(nomatch, binary:match(Cfg, <<"walletnotify">>)),
    {ok, Wlt} = file:read_file("src/beamchain_wallet.erl"),
    ?assertEqual(nomatch, binary:match(Wlt, <<"walletnotify">>)).

%%% G26 MISSING/BUG-11: -alertnotify external-command hook not wired.
gate26_no_alertnotify_hook_test() ->
    {ok, Cfg} = file:read_file("src/beamchain_config.erl"),
    ?assertEqual(nomatch, binary:match(Cfg, <<"alertnotify">>)),
    {ok, App} = file:read_file("src/beamchain_app.erl"),
    ?assertEqual(nomatch, binary:match(App, <<"alertnotify">>)).

%%% G27 MISSING/BUG-12: -startupnotify / -shutdownnotify external-
%%% command hook not wired.
gate27_no_startup_shutdown_notify_hooks_test() ->
    {ok, App} = file:read_file("src/beamchain_app.erl"),
    ?assertEqual(nomatch, binary:match(App, <<"startupnotify">>)),
    ?assertEqual(nomatch, binary:match(App, <<"shutdownnotify">>)),
    {ok, Cli} = file:read_file("src/beamchain_cli.erl"),
    ?assertEqual(nomatch, binary:match(Cli, <<"startupnotify">>)),
    ?assertEqual(nomatch, binary:match(Cli, <<"shutdownnotify">>)).

%%% ===================================================================
%%% Cross-cutting (G28-G30)
%%% ===================================================================

%%% G28 PARTIAL/BUG-20: /rest/chaininfo.json missing `warnings` array
%%% (and pruneheight / automatic_pruning / prune_target_size).
gate28_chaininfo_missing_warnings_field_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    %% rest_chaininfo emits the 13 keys catalogued in the audit.
    %% Confirm `warnings` is NOT one of them.
    %% (Source-search for the actual JSON-key literal.)
    ?assertEqual(nomatch,
        binary:match(Src, <<"<<\"warnings\">>">>)),
    %% Confirm the other Core fields beamchain DOES emit are present.
    ?assert(binary:match(Src, <<"<<\"verificationprogress\">>">>)
            =/= nomatch),
    ?assert(binary:match(Src, <<"<<\"initialblockdownload\">>">>)
            =/= nomatch).

%%% G29 PARTIAL/BUG-21+BUG-22: chaininfo / mempool/info / mempool/
%%% contents return HTTP 400 + custom body where Core returns 404 +
%%% "output format not found (available: json)".
gate29_non_json_format_returns_400_not_404_test() ->
    {ok, Src} = file:read_file("src/beamchain_rest.erl"),
    %% Confirm the divergent 400 + custom-text shape lives at the
    %% rest_chaininfo / rest_mempool_info / rest_mempool_contents
    %% catch-alls.
    ?assert(binary:match(Src,
        <<"<<\"Only JSON format supported for chaininfo\">>">>)
        =/= nomatch),
    ?assert(binary:match(Src,
        <<"<<\"Only JSON format supported for mempool/info\">>">>)
        =/= nomatch),
    ?assert(binary:match(Src,
        <<"<<\"Only JSON format supported for mempool/contents\">>">>)
        =/= nomatch),
    %% Confirm HTTP_BAD_REQUEST (400) is used, not HTTP_NOT_FOUND (404).
    %% (The macro expansion is HTTP_BAD_REQUEST in the source.)
    %% Source search: the relevant error tuples use ?HTTP_BAD_REQUEST.
    ?assert(binary:match(Src,
        <<"?HTTP_BAD_REQUEST, <<\"Only JSON format supported for chaininfo\">>">>)
        =/= nomatch).

%%% G30 PARTIAL/BUG-13: sequence topic mempool seq counter source
%%% diverges from Core (beamchain uses mempool gen_server's zmq_seq,
%%% Core uses m_sequence_number).
gate30_mempool_seq_source_diverges_test() ->
    {ok, Mp} = file:read_file("src/beamchain_mempool.erl"),
    %% Confirm beamchain uses zmq_seq from the mempool gen_server's
    %% state record (NOT the same as Core's CTxMemPool::
    %% m_sequence_number, which increments on every mempool
    %% mutation including block-confirmed removals).
    ?assert(binary:match(Mp, <<"zmq_seq = ZmqSeq">>) =/= nomatch),
    ?assert(binary:match(Mp,
        <<"beamchain_zmq:notify_transaction(Tx, mempool_add, ZmqSeq)">>)
        =/= nomatch),
    %% Confirm `m_sequence_number` is not used anywhere (since
    %% beamchain has its own zmq_seq counter, this is the
    %% audit-flip).
    ?assertEqual(nomatch, binary:match(Mp, <<"m_sequence_number">>)).

%%% ===================================================================
%%% Helper / sanity tests
%%% ===================================================================

%%% Sanity: beamchain_zmq:parse_endpoint accepts the canonical
%%% "tcp://*:28332" form (mirrors Core's accepted address strings).
parse_endpoint_sanity_test_() ->
    [
     ?_assertEqual({ok, tcp, "*", 28332},
                   beamchain_zmq:parse_endpoint_test("tcp://*:28332")),
     ?_assertEqual({ok, tcp, "127.0.0.1", 28333},
                   beamchain_zmq:parse_endpoint_test("tcp://127.0.0.1:28333")),
     ?_assertEqual({error, missing_port},
                   beamchain_zmq:parse_endpoint_test("tcp://localhost")),
     ?_assertEqual({error, missing_protocol},
                   beamchain_zmq:parse_endpoint_test("localhost:8332"))
    ].

%%% Sanity: REST parse_path / parse_format primitives remain stable.
rest_parse_primitives_sanity_test_() ->
    [
     ?_assertEqual(json, beamchain_rest:parse_format(<<".json">>)),
     ?_assertEqual(bin, beamchain_rest:parse_format(<<".bin">>)),
     ?_assertEqual(hex, beamchain_rest:parse_format(<<".hex">>)),
     ?_assertEqual(undefined, beamchain_rest:parse_format(<<".xml">>)),
     ?_assertEqual([<<"block">>, <<"abcd1234.json">>],
                   beamchain_rest:parse_path(
                       <<"/rest/block/abcd1234.json">>))
    ].

%%% Sanity: ZMQ no-op when disabled (the "default safe" case).
zmq_no_op_when_disabled_test() ->
    Block = sample_block(),
    Tx = sample_coinbase_tx(),
    ?assertEqual(ok, beamchain_zmq:notify_block(Block, connect)),
    ?assertEqual(ok, beamchain_zmq:notify_block(Block, disconnect)),
    ?assertEqual(ok, beamchain_zmq:notify_transaction(Tx, mempool_add, 0)),
    ?assertEqual(ok,
        beamchain_zmq:notify_transaction(Tx, mempool_remove, 1)).
