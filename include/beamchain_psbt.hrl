-ifndef(BEAMCHAIN_PSBT_HRL).
-define(BEAMCHAIN_PSBT_HRL, true).

%%% -------------------------------------------------------------------
%%% PSBT record — canonical definition
%%%
%%% BIP-174 Partially Signed Bitcoin Transactions.
%%%
%%% W118 TP-2 closure (FIX-63): pre-fix the same `-record(psbt, ...)` was
%%% defined in BOTH beamchain_psbt.erl:79 (7 fields: unsigned_tx, xpubs,
%%% version, global_unknown, inputs, outputs) and beamchain_wallet.erl:1245
%%% (4 fields: unsigned_tx, inputs, outputs) with the SAME RECORD NAME.
%%%
%%% Records are erased to tagged tuples at compile time. The two
%%% definitions produced incompatible tuple layouts:
%%%
%%%   {psbt, UnsignedTx, Inputs, Outputs}                       (wallet)
%%%   {psbt, UnsignedTx, XPubs, Version, GlobalUnknown,
%%%          Inputs, Outputs}                                   (psbt module)
%%%
%%% A value produced by `beamchain_psbt:create/1` then handed to
%%% `beamchain_wallet:add_witness_utxo/3` would silently read the wrong
%%% field — `Psbt#psbt.inputs` resolves to position 3 in the WALLET
%%% definition (which is `xpubs` in the psbt-module-produced tuple),
%%% returning a map() instead of a list of input maps. Concrete call
%%% sites that crossed the boundary:
%%%
%%%   rpc_walletcreatefundedpsbt → beamchain_psbt:create/1 →
%%%     beamchain_wallet:add_witness_utxo/3              (W113 path)
%%%   bumpfee_emit_psbt → beamchain_psbt:create/1 →
%%%     beamchain_wallet:add_witness_utxo/3              (FIX-61 path)
%%%
%%% FIX-63 unifies on the superset (psbt-module shape) and routes both
%%% modules through this header. The wallet had no use for the dropped
%%% `xpubs`/`version`/`global_unknown` fields (they default to empty), so
%%% the migration is field-additive.
%%%
%%% Reference: bitcoin-core/src/psbt.h::PartiallySignedTransaction.
%%% -------------------------------------------------------------------

-include("beamchain.hrl").

-record(psbt, {
    %% The unsigned transaction (inputs have empty scriptSigs, no witness).
    unsigned_tx        :: #transaction{},
    %% Global xpubs: #{xpub_binary => {fingerprint, path}}.
    xpubs          = #{} :: map(),
    %% Global version (default 0 — BIP-174 v0; v2 is BIP-370 / future).
    version        = 0   :: non_neg_integer(),
    %% Global unknown/proprietary key-value pairs.
    global_unknown = #{} :: map(),
    %% Per-input data: list of maps (one map per tx input, same order).
    inputs         = []  :: [map()],
    %% Per-output data: list of maps (one map per tx output, same order).
    outputs        = []  :: [map()]
}).

-endif.
