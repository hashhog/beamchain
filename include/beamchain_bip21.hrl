%%% beamchain_bip21.hrl — BIP-21 `bitcoin:` URI record.
%%%
%%% Lives in include/ so test/ and other consumers (e.g. a future
%%% beamchain_payjoin_client per W119 BUG-2) can include the type
%%% without having to re-declare or use element/2 positional access.

-ifndef(BEAMCHAIN_BIP21_HRL).
-define(BEAMCHAIN_BIP21_HRL, true).

-record(bip21_uri, {
    address   :: binary(),
    amount    :: undefined | non_neg_integer(),   %% satoshis
    label     :: undefined | binary(),
    message   :: undefined | binary(),
    lightning :: undefined | binary(),
    pj        :: undefined | binary(),
    pjos      :: undefined | 0 | 1,
    extras    :: [{binary(), binary()}]
}).

-endif.
