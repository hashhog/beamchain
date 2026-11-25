-module(beamchain_neon_headers_tx_count_tests).

%% Finding 20 of the Gemini (Neon) audit of beamchain against Bitcoin
%% Core v31.1 (item verify-neon-beamchain-findings). ProcessMessage("headers")
%% (net_processing.cpp) reads each header's tx count with ReadCompactSize and
%% ignores the value. A non-canonical or oversized CompactSize throws, and
%% the whole message is dropped. beamchain's decoder bound the error as the
%% rest of the payload: on the last header the error atom became the "rest"
%% and the headers were accepted.

-include_lib("eunit/include/eunit.hrl").
-include("beamchain.hrl").

%%% ===================================================================
%%% F20: headers decoder
%%% ===================================================================

hdr(N) ->
    beamchain_serialize:encode_block_header(
      #block_header{version = 4, prev_hash = <<N:256>>, merkle_root = <<0:256>>,
                    timestamp = 1700000000 + N, bits = 16#207fffff, nonce = N}).

f20_last_header_non_canonical_tx_count_is_malformed_test() ->
    Bin = <<1, (hdr(1))/binary, 16#fd, 0, 0>>,
    ?assertEqual({error, {malformed, headers}},
                 beamchain_p2p_msg:decode_payload(headers, Bin)).

f20_last_header_oversized_tx_count_is_malformed_test() ->
    Bin = <<2, (hdr(1))/binary, 0, (hdr(2))/binary, 16#fe, 16#ff, 16#ff, 16#ff, 16#ff>>,
    ?assertEqual({error, {malformed, headers}},
                 beamchain_p2p_msg:decode_payload(headers, Bin)).

%% Control (and the half of the claim that is NOT a divergence): Core
%% ignores the tx-count VALUE, so a canonical non-zero count decodes.
f20_control_nonzero_tx_count_is_ignored_test() ->
    Bin = <<2, (hdr(1))/binary, 1, (hdr(2))/binary, 0>>,
    ?assertMatch({ok, #{headers := [_, _]}},
                 beamchain_p2p_msg:decode_payload(headers, Bin)).

%% Control: a non-canonical count on a header that is not the last was
%% already refused (the next header decode failed).
f20_control_inner_non_canonical_tx_count_is_malformed_test() ->
    Bin = <<2, (hdr(1))/binary, 16#fd, 0, 0, (hdr(2))/binary, 0>>,
    ?assertEqual({error, {malformed, headers}},
                 beamchain_p2p_msg:decode_payload(headers, Bin)).
