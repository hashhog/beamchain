-module(beamchain_fix67_payjoin_cleanup_tests).

%% FIX-67 / W119 — BIP-78 PayJoin remaining gates (G18 / G19 / G20 / G30).
%%
%% Closes:
%%   G18  receiver TTL: response within client-acceptable wait window
%%   G19  receiver no-double-spend: same Original PSBT processed once
%%   G20  receiver UTXO anti-fingerprint (UIH-1 / UIH-2 heuristic)
%%   G30  receiver replay protection (once-only token in pj= URL)
%%
%% These were the last four open gates after FIX-66 (BIP-78 sender +
%% anti-snoop + 2 RPCs) closed 14 receiver/sender gates. After FIX-67
%% the W119 PayJoin wave is structurally complete (G1..G30 closed) for
%% the beamchain impl.
%%
%% Test matrix:
%%
%%   G18:
%%     - compute_request_budget_ms/0 returns a positive ms value
%%       (defaulted to ?REQUEST_BUDGET_MS via beamchain_config fallback)
%%     - build_payjoin_psbt_bounded/4 returns
%%       {error, request_budget_exceeded} when the budget is exceeded
%%       (we exercise a budget of 0 ms — guarantees timeout regardless
%%       of how fast the build path runs)
%%
%%   G19:
%%     - remember_seen_psbt/1 returns ok the first time
%%     - second call with the same bytes returns {error, already_seen}
%%     - different bytes do NOT collide
%%
%%   G20:
%%     - uih_score/4 prefers Value >= MaxOut, penalises Value < MinOut
%%     - pick_receiver_utxo_anti_fingerprint/3 picks the highest-scoring
%%       eligible UTXO when multiple are staged
%%     - script_recently_used/1 reflects remember_used_script/1
%%
%%   G30:
%%     - mint_invoice_token/1 returns a 32-char hex
%%     - consume_invoice_token/1 returns {ok, BoundAddr} the first call
%%     - consume_invoice_token/1 returns {error, not_found} the 2nd time
%%     - rpc_getpayjoinrequest result map carries `token` key (hex)
%%     - the URI's pj= URL embeds `&token=<hex>` (after the path)
%%
%%   Single-pipeline anchor (preserved): grep
%%   `lookup_privkeys_for_inputs(` in beamchain_rpc.erl — count remains
%%   >= 4 (definition + sendtoaddress + bumpfee + marker comments). The
%%   FIX-67 changes do not introduce a second wallet-signing pipeline.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").
-include("beamchain_protocol.hrl").
-include("beamchain_psbt.hrl").

%%% ===================================================================
%%% Source-path helpers (shared with W118 / FIX-61 / FIX-63 / FIX-65 /
%%% FIX-66 tests)
%%% ===================================================================

beamchain_src_dir() ->
    Beam = code:which(beamchain_payjoin_server),
    case Beam of
        non_existing -> "src";
        _ ->
            Ebin = filename:dirname(Beam),
            Lib  = filename:dirname(Ebin),
            Src  = filename:join([Lib, "src"]),
            case filelib:is_dir(Src) of
                true -> Src;
                false -> "src"
            end
    end.

beamchain_rpc_path() ->
    filename:join(beamchain_src_dir(), "beamchain_rpc.erl").

%%% ===================================================================
%%% Wallet fixture (mirrors FIX-65)
%%% ===================================================================

start_default_wallet() ->
    case whereis(beamchain_wallet) of
        undefined ->
            {ok, Pid} = beamchain_wallet:start_link(),
            Pid;
        Pid -> Pid
    end.

stop_default_wallet() ->
    case whereis(beamchain_wallet) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

ensure_seeded_wallet() ->
    _ = stop_default_wallet(),
    Pid = start_default_wallet(),
    Seed = crypto:strong_rand_bytes(32),
    {ok, _} = gen_server:call(Pid, {create, Seed, undefined}),
    %% Wipe any leftover payjoin state between tests.
    beamchain_payjoin_state:clear_all(),
    Pid.

%%% ===================================================================
%%% G18 — Receiver TTL / request budget
%%% ===================================================================

g18_compute_request_budget_ms_default_test() ->
    %% No beamchain_config:payjoin_budget_ms/0 today — fallback should
    %% return a positive integer milliseconds value.
    Budget = beamchain_payjoin_server:compute_request_budget_ms(),
    ?assert(is_integer(Budget)),
    ?assert(Budget > 0),
    %% Reasonable upper bound — BIP-78 §"Reception" suggests sender
    %% timeout ~30s; we should not exceed that.
    ?assert(Budget =< 60000).

g18_bounded_build_times_out_test_() ->
    {setup,
     fun() -> ensure_seeded_wallet() end,
     fun(_) -> stop_default_wallet() end,
     fun(_Pid) ->
       [?_test(begin
          %% Construct a minimal #psbt{} that the build path could
          %% theoretically process. We don't care about success/failure
          %% of the underlying build — we only care that a 0ms budget
          %% surfaces the timeout error.
          Tx = #transaction{
              version = 2,
              inputs  = [#tx_in{
                  prev_out = #outpoint{hash = <<1:256>>, index = 0},
                  script_sig = <<>>,
                  sequence = 16#fffffffd,
                  witness = []
              }],
              outputs = [
                  #tx_out{value = 100000, script_pubkey = <<0:160>>},
                  #tx_out{value = 49000,  script_pubkey = <<0:160>>}
              ],
              locktime = 0
          },
          Psbt = #psbt{
              unsigned_tx = Tx,
              inputs  = [#{}],
              outputs = [#{}, #{}]
          },
          Params = #{version => 1,
                     additional_fee_output_index => undefined,
                     max_additional_fee_contribution => 0,
                     disable_output_substitution => false,
                     min_fee_rate => 0},
          Pid = whereis(beamchain_wallet),
          %% Budget=0ms → expect timeout regardless of how fast build
          %% would have completed. The build is spawned, the receive
          %% times out immediately, we surface request_budget_exceeded.
          R = beamchain_payjoin_server:build_payjoin_psbt_bounded(
                Psbt, Params, Pid, 0),
          ?assertEqual({error, request_budget_exceeded}, R)
        end)]
     end}.

%%% ===================================================================
%%% G19 — Original PSBT no-double-process (dedup)
%%% ===================================================================

g19_remember_seen_psbt_test_() ->
    {setup,
     fun() -> beamchain_payjoin_state:clear_all() end,
     fun(_) -> ok end,
     fun(_) ->
       [?_test(begin
          PsbtA = <<"alpha psbt bytes — sample 1">>,
          PsbtB = <<"beta psbt bytes — sample 2">>,
          %% First sighting → ok.
          ?assertEqual(ok,
              beamchain_payjoin_state:remember_seen_psbt(PsbtA)),
          %% Second sighting of A → already_seen.
          ?assertEqual({error, already_seen},
              beamchain_payjoin_state:remember_seen_psbt(PsbtA)),
          %% B is a different PSBT → ok (no collision).
          ?assertEqual(ok,
              beamchain_payjoin_state:remember_seen_psbt(PsbtB)),
          %% Soft check matches.
          ?assert(beamchain_payjoin_state:seen_psbt(PsbtA)),
          ?assert(beamchain_payjoin_state:seen_psbt(PsbtB)),
          ?assertNot(beamchain_payjoin_state:seen_psbt(
                       <<"unseen bytes">>))
        end)]
     end}.

g19_seen_size_grows_test_() ->
    {setup,
     fun() -> beamchain_payjoin_state:clear_all() end,
     fun(_) -> ok end,
     fun(_) ->
       [?_test(begin
          Before = beamchain_payjoin_state:seen_size(),
          beamchain_payjoin_state:remember_seen_psbt(<<"x">>),
          beamchain_payjoin_state:remember_seen_psbt(<<"y">>),
          After = beamchain_payjoin_state:seen_size(),
          ?assertEqual(Before + 2, After)
        end)]
     end}.

%%% ===================================================================
%%% G20 — UIH-1 / UIH-2 anti-fingerprint
%%% ===================================================================

g20_uih_score_prefers_ge_max_out_test() ->
    %% Outputs [100000, 49000]. MinOut=49000, MaxOut=100000.
    %% Candidate value 150000 ≥ MaxOut → score 0 (best).
    ?assertEqual(0,
                 beamchain_payjoin_server:uih_score(
                   150000, [100000, 49000], [], false)),
    %% Candidate value 75000 is between min and max → score 2.
    ?assertEqual(2,
                 beamchain_payjoin_server:uih_score(
                   75000, [100000, 49000], [], false)),
    %% Candidate value 10000 < MinOut → score 10 (worst).
    ?assertEqual(10,
                 beamchain_payjoin_server:uih_score(
                   10000, [100000, 49000], [], false)).

g20_uih_score_recency_penalty_test() ->
    %% Same candidate, but recently_used=true adds 5.
    ?assertEqual(0 + 5,
                 beamchain_payjoin_server:uih_score(
                   150000, [100000, 49000], [], true)),
    ?assertEqual(10 + 5,
                 beamchain_payjoin_server:uih_score(
                   10000, [100000, 49000], [], true)).

g20_pick_anti_fingerprint_prefers_large_utxo_test_() ->
    {setup,
     fun() -> ensure_seeded_wallet() end,
     fun(_) -> stop_default_wallet() end,
     fun(_Pid) ->
       [?_test(begin
          %% Stage TWO wallet UTXOs with different values + scripts.
          %% The "small" one collides with UIH-1 (Value < MinOut).
          %% The "large" one beats UIH-2 (Value ≥ MaxOut).
          %% Expected pick: the LARGE one.
          {ok, AddrSmall} = beamchain_wallet:get_new_address(p2wpkh),
          {ok, ScrSmall}  = beamchain_address:address_to_script(
                              AddrSmall, mainnet),
          {ok, AddrLarge} = beamchain_wallet:get_new_address(p2wpkh),
          {ok, ScrLarge}  = beamchain_address:address_to_script(
                              AddrLarge, mainnet),
          %% Stage:
          %%   SMALL utxo: 10_000 sat (< MinOut=49_000 → UIH-1 hit)
          %%   LARGE utxo: 200_000 sat (≥ MaxOut=100_000 → UIH-2 clear)
          ok = beamchain_wallet:add_wallet_utxo(
                 <<7:256>>, 0, 10000, ScrSmall, 1),
          ok = beamchain_wallet:add_wallet_utxo(
                 <<8:256>>, 0, 200000, ScrLarge, 1),
          %% Original tx outputs: [100_000, 49_000] (receiver + change).
          OldTx = #transaction{
              version = 2,
              inputs  = [#tx_in{
                  prev_out = #outpoint{hash = <<2:256>>, index = 0},
                  script_sig = <<>>,
                  sequence = 16#fffffffd,
                  witness = []
              }],
              outputs = [
                  #tx_out{value = 100000, script_pubkey = <<0:160>>},
                  #tx_out{value = 49000,  script_pubkey = <<0:160>>}
              ],
              locktime = 0
          },
          {ok, {_T, _V, Utxo}} =
              beamchain_payjoin_server:pick_receiver_utxo_anti_fingerprint(
                whereis(beamchain_wallet), mainnet, OldTx),
          %% The picker MUST select the LARGE utxo.
          ?assertEqual(200000, Utxo#utxo.value),
          ?assertEqual(ScrLarge, Utxo#utxo.script_pubkey)
        end)]
     end}.

g20_pick_anti_fingerprint_empty_wallet_test_() ->
    {setup,
     fun() -> ensure_seeded_wallet() end,
     fun(_) -> stop_default_wallet() end,
     fun(_Pid) ->
       [?_test(begin
          %% No UTXOs staged → no_eligible_utxo.
          OldTx = #transaction{
              version = 2,
              inputs  = [#tx_in{
                  prev_out = #outpoint{hash = <<2:256>>, index = 0},
                  script_sig = <<>>,
                  sequence = 16#fffffffd,
                  witness = []
              }],
              outputs = [#tx_out{value = 100000, script_pubkey = <<0:160>>}],
              locktime = 0
          },
          ?assertEqual({error, no_eligible_utxo},
              beamchain_payjoin_server:pick_receiver_utxo_anti_fingerprint(
                whereis(beamchain_wallet), mainnet, OldTx))
        end)]
     end}.

g20_remembered_script_test_() ->
    {setup,
     fun() -> beamchain_payjoin_state:clear_all() end,
     fun(_) -> ok end,
     fun(_) ->
       [?_test(begin
          Scr = <<16#00, 20, 9,9,9,9,9,9,9,9,9,9,
                   9,9,9,9,9,9,9,9,9,9>>,
          ?assertNot(beamchain_payjoin_state:script_recently_used(Scr)),
          beamchain_payjoin_state:remember_used_script(Scr),
          ?assert(beamchain_payjoin_state:script_recently_used(Scr))
        end)]
     end}.

%%% ===================================================================
%%% G30 — Invoice token (one-shot replay protection)
%%% ===================================================================

g30_mint_and_consume_token_test_() ->
    {setup,
     fun() -> beamchain_payjoin_state:clear_all() end,
     fun(_) -> ok end,
     fun(_) ->
       [?_test(begin
          Addr = <<"bc1qexample">>,
          Hex = beamchain_payjoin_state:mint_invoice_token(Addr),
          %% 16 bytes → 32 hex chars.
          ?assertEqual(32, byte_size(Hex)),
          %% Soft check: present.
          ?assert(beamchain_payjoin_state:token_exists(Hex)),
          %% First consume: ok with bound addr.
          ?assertEqual({ok, Addr},
              beamchain_payjoin_state:consume_invoice_token(Hex)),
          %% Soft check after consume: absent.
          ?assertNot(beamchain_payjoin_state:token_exists(Hex)),
          %% Second consume: not_found (one-shot).
          ?assertEqual({error, not_found},
              beamchain_payjoin_state:consume_invoice_token(Hex))
        end)]
     end}.

g30_consume_invalid_hex_test() ->
    %% Garbage in token slot → bad_hex / bad_hex_length.
    R1 = beamchain_payjoin_state:consume_invoice_token(<<"notahextoken">>),
    ?assertMatch({error, _}, R1),
    R2 = beamchain_payjoin_state:consume_invoice_token(<<"abc">>),
    ?assertMatch({error, _}, R2).

g30_token_uppercase_hex_accepted_test_() ->
    {setup,
     fun() -> beamchain_payjoin_state:clear_all() end,
     fun(_) -> ok end,
     fun(_) ->
       [?_test(begin
          Addr = <<"bc1qexample">>,
          HexLower = beamchain_payjoin_state:mint_invoice_token(Addr),
          %% Force to upper case — a hex decoder MUST accept both per
          %% RFC 4648 §8 ("hex" alphabet is case-insensitive).
          HexUpper = list_to_binary(
                       string:to_upper(binary_to_list(HexLower))),
          ?assertEqual({ok, Addr},
              beamchain_payjoin_state:consume_invoice_token(HexUpper))
        end)]
     end}.

g30_rpc_getpayjoinrequest_emits_token_test_() ->
    {setup,
     fun() ->
        beamchain_payjoin_state:clear_all(),
        ensure_seeded_wallet()
     end,
     fun(_) -> stop_default_wallet() end,
     fun(_Pid) ->
       [?_test(begin
          Result = beamchain_rpc:rpc_getpayjoinrequest(
                     [<<"0.0001">>], <<>>),
          %% Result shape:
          %%   {ok, #{<<"uri">> := Uri, <<"token">> := Hex, ...}}
          {ok, Map} = Result,
          ?assert(is_map(Map)),
          ?assert(maps:is_key(<<"uri">>, Map)),
          ?assert(maps:is_key(<<"token">>, Map)),
          Token = maps:get(<<"token">>, Map),
          ?assert(is_binary(Token)),
          ?assertEqual(32, byte_size(Token)),
          %% Uri MUST embed the token bytes somewhere in its body. The
          %% raw `token=<hex>` substring is percent-encoded by the
          %% BIP-21 builder (token=<hex> appears inside the pj= value),
          %% so we look for the bare token bytes — which survive
          %% percent-encoding because hex chars are all unreserved.
          Uri = maps:get(<<"uri">>, Map),
          ?assertNotEqual(nomatch,
              binary:match(Uri, Token)),
          %% Endpoint (the pj= target) carries the token UNENCODED;
          %% it's the URL the receiver hosts at, not a query value
          %% being embedded in another query.
          Endpoint = maps:get(<<"endpoint">>, Map),
          ?assertNotEqual(nomatch,
              binary:match(Endpoint, <<"token=", Token/binary>>)),
          %% Token MUST be present in state (the RPC consumes-once on
          %% receiver POST, not on issuance).
          ?assert(beamchain_payjoin_state:token_exists(Token))
        end)]
     end}.

%%% ===================================================================
%%% Single-pipeline anchor — preserved through FIX-67
%%% ===================================================================
%%
%% FIX-66 established the floor of >= 4 mentions of
%% `lookup_privkeys_for_inputs` in src/beamchain_rpc.erl. FIX-67 only
%% touches receiver-side server state + RPC URI minting; it does NOT
%% introduce a second wallet-signing pipeline. We assert the count
%% stays >= 4 AND that the new state module does NOT call any
%% wallet-signing primitive.

single_pipeline_anchor_preserved_test_() ->
    {"FIX-67 single-pipeline anchor: lookup_privkeys_for_inputs "
     "count stays ≥ 4 and the new state module has no signing path",
     [
      ?_test(begin
         {ok, RpcSrc} = file:read_file(beamchain_rpc_path()),
         Matches = binary:matches(RpcSrc,
                                  <<"lookup_privkeys_for_inputs">>),
         ?assert(length(Matches) >= 4)
       end),
      ?_test(begin
         SrcPath = filename:join(beamchain_src_dir(),
                                 "beamchain_payjoin_state.erl"),
         {ok, Src} = file:read_file(SrcPath),
         %% State module is pure ETS + hex helpers — must not touch
         %% any signing primitive.
         ?assertEqual(nomatch,
             binary:match(Src, <<"beamchain_crypto:ecdsa_sign(">>)),
         ?assertEqual(nomatch,
             binary:match(Src, <<"beamchain_crypto:schnorr_sign(">>)),
         ?assertEqual(nomatch,
             binary:match(Src, <<"get_private_key(">>)),
         ?assertEqual(nomatch,
             binary:match(Src, <<"lookup_privkeys_for_inputs(">>))
       end),
      ?_test(begin
         %% Receiver path STILL routes signing through
         %% rpc_walletprocesspsbt (the single canonical path).
         SrcPath = filename:join(beamchain_src_dir(),
                                 "beamchain_payjoin_server.erl"),
         {ok, RecvSrc} = file:read_file(SrcPath),
         ?assertNotEqual(nomatch,
             binary:match(RecvSrc,
                          <<"beamchain_rpc:rpc_walletprocesspsbt(">>))
       end)
     ]}.
