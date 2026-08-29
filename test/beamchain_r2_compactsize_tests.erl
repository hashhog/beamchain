-module(beamchain_r2_compactsize_tests).

%%% -------------------------------------------------------------------
%%% submitblock: DECODE failure is separate from VALIDATION failure.
%%%
%%% R2 reason-token parity. Core's submitblock runs DecodeHexBlk FIRST
%%% (rpc/mining.cpp:1079) and answers a failure with
%%%
%%%     throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
%%%
%%% a JSON-RPC ERROR, never a BIP-22 result string. The underlying
%%% std::ios_base::failure text -- "non-canonical ReadCompactSize()",
%%% serialize.h:344/350/356 -- is swallowed by DecodeHexBlk, which returns a
%%% bare bool, so it never reaches the client.
%%%
%%% beamchain folded hex-decode and deserialize into the SAME try/catch as
%%% validate-and-connect, so every decode failure collapsed to {error, Reason}
%%% and then to bip22_result/1's "rejected" fallback.
%%%
%%% MEASURED on diff-test corpus
%%% _tierc-guards-2026-07-06/C1-noncanonical-compactsize, all 4 rows, via the
%%% real RPC against a live regtest node with Core as the oracle:
%%%
%%%     before:  bitcoin-core reject:block-decode-failed
%%%              beamchain    reject:rejected            <- token divergence
%%%     after:   both         reject:block-decode-failed
%%%
%%% Both REJECT either way and the tip is unchanged, so this was never a
%%% consensus split -- reason-token parity is what R2 measures.
%%%
%%% This module pins the SPLIT itself, at the unit the patch introduced, so
%%% the property survives without standing up the miner gen_server. The
%%% end-to-end RPC mapping (-22 "Block decode failed") is covered by the
%%% corpus run above, which drives the real handler.
%%% -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").

%% Corpus row cs-vin-count-fd, byte-for-byte: a valid h=111 regtest block
%% whose coinbase vin count "0x01" was rewritten as the non-canonical
%% two-byte "0xfd 0100". Core throws inside CTransaction deserialization,
%% BEFORE any contextual check -- which is why this corpus is decay-immune:
%% there is no timestamp or height for it to outgrow.
noncanonical_block_hex() ->
    <<"00000020b71ac1de569facf2723f92027fe4cc8c0bf5c0e69367a42cc03dda2e35d9b57e0767708111b80d2ae52345c7d445a29b5111807d05bdef7b42cf04ab05f9569fdab1f769ffff7f200000000001020000000001fd01000000000000000000000000000000000000000000000000000000000000000000ffffffff06016fc1001101ffffffff0200f2052a010000002200204ba0535e5837836b8f9eef690e8002a8d943ad03c8a799d80fa70d9d99cd1f4f0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000">>.

%% The corpus's own _valid_baseline.hex: same block, canonical encoding.
valid_block_hex() ->
    <<"00000020b71ac1de569facf2723f92027fe4cc8c0bf5c0e69367a42cc03dda2e35d9b57e0767708111b80d2ae52345c7d445a29b5111807d05bdef7b42cf04ab05f9569fdab1f769ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff06016fc1001101ffffffff0200f2052a010000002200204ba0535e5837836b8f9eef690e8002a8d943ad03c8a799d80fa70d9d99cd1f4f0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000">>.

%%% THE REGRESSION. At the parent commit the non-canonical CompactSize threw
%%% inside the combined try/catch and came back as a generic validation
%%% failure, which bip22_result/1 rendered as "rejected".
noncanonical_compactsize_is_a_DECODE_failure_test() ->
    ?assertEqual({error, decode_failed},
                 beamchain_miner:decode_block_hex(noncanonical_block_hex())).

%%% Same class, shorter path: hex that is not a block at all.
garbage_hex_is_a_decode_failure_test() ->
    ?assertEqual({error, decode_failed},
                 beamchain_miner:decode_block_hex(<<"deadbeef">>)).

%%% Odd-length input fails the hex step rather than the deserialize step.
%%% An over-narrow fix that only caught CompactSize would leave this one on
%%% the old path.
odd_length_hex_is_a_decode_failure_test() ->
    ?assertEqual({error, decode_failed},
                 beamchain_miner:decode_block_hex(<<"abc">>)).

%%% CONTROL, and the one that matters most: the corpus's canonical baseline
%%% block MUST still decode. Without it, all three assertions above are
%%% satisfied by a decoder that rejects everything -- which would turn a
%%% token-parity fix into a node that can no longer accept a submitted block.
canonical_baseline_block_still_decodes_test() ->
    ?assertMatch({ok, _}, beamchain_miner:decode_block_hex(valid_block_hex())).
