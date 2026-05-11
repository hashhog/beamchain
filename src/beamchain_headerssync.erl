-module(beamchain_headerssync).

%% Anti-DoS two-phase headers sync state machine.
%%
%% Mirrors Bitcoin Core src/headerssync.cpp (HeadersSyncState class).
%%
%% Phase 1 – PRESYNC: receive headers from a peer, validate PoW and
%% PermittedDifficultyTransition, accumulate chainwork.  Every
%% commitment_period heights store 1-bit salted commitments (SipHash-2-4 of
%% the block hash, LSB).  Track a memory bound (max_commitments) derived from
%% the 6-blocks/second MTP rule so we can abort oversized chains.  When
%% cumulative work reaches minimum_required_work, transition to REDOWNLOAD.
%%
%% Phase 2 – REDOWNLOAD: the peer re-sends from chain_start.  Verify the
%% stored commitments, accumulate work again.  Buffer headers in
%% m_redownloaded_headers until we have redownload_buffer_size headers of
%% verified commitments on top, then release them to the caller.  Once
%% m_redownload_chain_work >= minimum_required_work, release everything.
%%
%% State:
%%   presync  – collecting commitments
%%   redownload – verifying commitments, buffering headers
%%   final   – done; caller must discard state
%%
%% Core line references are noted on individual functions.

-include("beamchain.hrl").
-include("beamchain_protocol.hrl").

-export([new/5,
         process_next_headers/3,
         next_headers_request_locator/1,
         get_state/1,
         get_presync_height/1,
         get_presync_work/1,
         get_presync_time/1]).

%% Per-network parameters (mirrors HeadersSyncParams in kernel/chainparams.h).
%% These match the values in bitcoin-core/src/chainparams.cpp.
-define(COMMITMENT_PERIOD_MAINNET,  641).
-define(REDOWNLOAD_BUFFER_MAINNET,  15218).
-define(COMMITMENT_PERIOD_TESTNET4, 606).
-define(REDOWNLOAD_BUFFER_TESTNET4, 16092).
-define(COMMITMENT_PERIOD_SIGNET,   673).
-define(REDOWNLOAD_BUFFER_SIGNET,   14460).
-define(COMMITMENT_PERIOD_TESTNET,  620).
-define(REDOWNLOAD_BUFFER_TESTNET,  15724).
-define(COMMITMENT_PERIOD_REGTEST,  275).
-define(REDOWNLOAD_BUFFER_REGTEST,  7017).

%% 6 blocks per second (MTP rule), used for max_commitments bound.
%% Core: headerssync.cpp:36 "using 6 blocks/second"
-define(MAX_BLOCKS_PER_SECOND, 6).

%% MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60.  Core: chain.h:29
-define(MAX_FUTURE_BLOCK_TIME, 7200).

%% -----------------------------------------------------------------
%% Public record – treat as opaque outside this module.
%% -----------------------------------------------------------------

%% m_redownloaded_headers stores compressed headers (no prev_hash).
-record(compressed_hdr, {
    version    :: integer(),
    merkle_root :: binary(),
    timestamp  :: non_neg_integer(),
    bits       :: non_neg_integer(),
    nonce      :: non_neg_integer()
}).

-record(hss, {
    %% Peer identifier (for logging)
    peer_id            :: term(),
    %% Chain parameters map (from beamchain_chain_params)
    params             :: map(),
    %% Chain start block index: #{height, hash, chainwork, bits, mtp}
    chain_start        :: map(),
    %% Minimum cumulative work required before we accept headers.
    minimum_required_work :: non_neg_integer(),
    %% Per-network sync parameters
    commitment_period  :: pos_integer(),
    redownload_buffer_size :: pos_integer(),
    %% Secret random offset for commitment heights.
    %% Core: headerssync.cpp:22-23, headerssync.h:184-185
    commit_offset      :: non_neg_integer(),
    %% Salted SipHash key pair (k0, k1) for 1-bit commitments.
    %% Core: m_hasher (SaltedUint256Hasher backed by PresaltedSipHasher)
    hasher_k0          :: non_neg_integer(),
    hasher_k1          :: non_neg_integer(),
    %% Queue of 1-bit commitments built in PRESYNC, verified in REDOWNLOAD.
    %% Core: m_header_commitments (bitdeque<>)
    header_commitments :: queue:queue(0 | 1),
    %% Upper bound on commitment queue length.
    %% Core: m_max_commitments
    max_commitments    :: non_neg_integer(),
    %% Last header seen in PRESYNC (full header binary state).
    %% Core: m_last_header_received
    last_header        :: #block_header{} | undefined,
    %% Height of last_header.  Core: m_current_height
    current_height     :: integer(),
    %% Accumulated work in PRESYNC.  Core: m_current_chain_work
    current_chain_work :: non_neg_integer(),

    %% REDOWNLOAD phase state ----------------------------------------

    %% Buffered compressed headers awaiting enough verified commitments.
    %% Core: m_redownloaded_headers (deque<CompressedHeader>)
    redownloaded_headers :: queue:queue(#compressed_hdr{}),
    %% Height of the last entry in redownloaded_headers.
    %% Core: m_redownload_buffer_last_height
    redownload_buffer_last_height :: integer(),
    %% Hash of the last entry in redownloaded_headers.
    %% Core: m_redownload_buffer_last_hash
    redownload_buffer_last_hash :: binary(),
    %% Hash immediately before the first entry in redownloaded_headers.
    %% Needed to reconstruct the full header at pop time.
    %% Core: m_redownload_buffer_first_prev_hash
    redownload_buffer_first_prev_hash :: binary(),
    %% Accumulated chainwork on the redownloaded chain.
    %% Core: m_redownload_chain_work
    redownload_chain_work :: non_neg_integer(),
    %% Set once redownload_chain_work >= minimum_required_work.
    %% Core: m_process_all_remaining_headers
    process_all_remaining :: boolean(),

    %% Current phase.  Core: m_download_state
    download_state :: presync | redownload | final
}).

%% Internal result record for pop_ready/1.
-record(redownload_result, {headers :: [#block_header{}], hss :: #hss{}}).

%% -----------------------------------------------------------------
%% API
%% -----------------------------------------------------------------

%% @doc Create a new HeadersSyncState.
%%
%% PeerId     – any term used in log messages
%% Params     – chain params from beamchain_chain_params:params/1
%% ChainStart – #{height, hash, chainwork, bits, mtp_past}
%%              mtp_past is the MTP of chain_start (used for max_commitments)
%% MinWork    – minimum_required_work as integer
%%
%% Core: HeadersSyncState constructor, headerssync.cpp:17-46
-spec new(PeerId, Params, ChainStart, MinWork, Network) -> #hss{}
    when PeerId    :: term(),
         Params    :: map(),
         ChainStart :: map(),
         MinWork   :: non_neg_integer(),
         Network   :: mainnet | testnet4 | testnet | regtest | signet.
new(PeerId, Params, ChainStart, MinWork, Network) ->
    {CommitPeriod, RedownloadBuf} = sync_params(Network),
    %% Secret random offset in [0, CommitPeriod).
    %% Core: FastRandomContext().randrange(params.commitment_period)
    CommitOffset = rand:uniform(CommitPeriod) - 1,
    %% Salted SipHash-2-4 key: two random 64-bit words, matching
    %% SaltedUint256Hasher / PresaltedSipHasher in Core.
    HasherK0 = rand:uniform(1 bsl 64) - 1,
    HasherK1 = rand:uniform(1 bsl 64) - 1,
    %% max_commitments: 6 blocks/second * seconds_since_chain_start / period
    %% Core: headerssync.cpp:41-43
    MTPPast = maps:get(mtp_past, ChainStart, 0),
    NowSec  = erlang:system_time(second),
    MaxSecondsSinceStart = (NowSec - MTPPast) + ?MAX_FUTURE_BLOCK_TIME,
    MaxCommitments = (?MAX_BLOCKS_PER_SECOND * MaxSecondsSinceStart)
                     div CommitPeriod,
    StartHeight   = maps:get(height, ChainStart, 0),
    StartHash     = maps:get(hash, ChainStart, <<0:256>>),
    StartWork     = maps:get(chainwork, ChainStart, 0),
    logger:debug("headerssync: peer=~p init height=~B max_commitments=~B "
                 "min_work=~B",
                 [PeerId, StartHeight, MaxCommitments, MinWork]),
    #hss{
        peer_id            = PeerId,
        params             = Params,
        chain_start        = ChainStart,
        minimum_required_work = MinWork,
        commitment_period  = CommitPeriod,
        redownload_buffer_size = RedownloadBuf,
        commit_offset      = CommitOffset,
        hasher_k0          = HasherK0,
        hasher_k1          = HasherK1,
        header_commitments = queue:new(),
        max_commitments    = max(1, MaxCommitments),
        last_header        = undefined,
        current_height     = StartHeight,
        current_chain_work = StartWork,
        redownloaded_headers           = queue:new(),
        redownload_buffer_last_height  = StartHeight,
        redownload_buffer_last_hash    = StartHash,
        redownload_buffer_first_prev_hash = StartHash,
        redownload_chain_work          = 0,
        process_all_remaining          = false,
        download_state     = presync
    }.

%% @doc Process the next batch of headers.
%%
%% Returns {ok, ReadyHeaders, NewHss} where ReadyHeaders is a (possibly
%% empty) list of #block_header{} that the caller can accept into the block
%% index, and NewHss is the updated state.
%%
%% Returns {error, Reason, FinalHss} on protocol error; the caller MUST
%% discard FinalHss and disconnect the peer.
%%
%% request_more/1 can be used to test whether the caller should send another
%% GETHEADERS.
%%
%% Core: ProcessNextHeaders, headerssync.cpp:68-137
-spec process_next_headers([#block_header{}], boolean(), #hss{}) ->
    {ok, [#block_header{}], boolean(), #hss{}} |
    {error, term(), #hss{}}.
process_next_headers([], _FullMsg, Hss) ->
    %% Core line 73: Assume(!received_headers.empty())
    {ok, [], false, Hss};

process_next_headers(_Headers, _FullMsg, #hss{download_state = final} = Hss) ->
    %% Core line 77: if (m_download_state == State::FINAL) return ret;
    {ok, [], false, Hss};

process_next_headers(Headers, FullMsg,
                     #hss{download_state = presync} = Hss) ->
    %% Core lines 79-97: PRESYNC branch
    case validate_and_store_commitments(Headers, Hss) of
        {ok, Hss2} ->
            RequestMore = FullMsg orelse
                          Hss2#hss.download_state =:= redownload,
            case RequestMore of
                false ->
                    %% Core line 95: non-full presync msg → chain too short
                    logger:debug("headerssync: peer=~p presync aborted: "
                                 "incomplete headers at height=~B",
                                 [Hss2#hss.peer_id, Hss2#hss.current_height]);
                true -> ok
            end,
            Hss3 = maybe_finalize(RequestMore, Hss2),
            {ok, [], RequestMore, Hss3};
        {error, Reason, Hss2} ->
            {error, Reason, finalize(Hss2)}
    end;

process_next_headers(Headers, FullMsg,
                     #hss{download_state = redownload} = Hss) ->
    %% Core lines 98-133: REDOWNLOAD branch
    case store_redownloaded(Headers, Hss) of
        {ok, Hss2} ->
            Ready = pop_ready(Hss2),
            Hss3  = Ready#redownload_result.hss,
            ReadyHeaders = Ready#redownload_result.headers,
            %% AllDone: m_redownloaded_headers empty + m_process_all_remaining
            %% Core line 120: if (m_redownloaded_headers.empty() &&
            %%                    m_process_all_remaining_headers)
            AllDone = queue:is_empty(Hss3#hss.redownloaded_headers)
                      andalso Hss3#hss.process_all_remaining,
            {RequestMore, Hss4} =
                if AllDone ->
                    logger:debug("headerssync: peer=~p redownload complete "
                                 "at height=~B",
                                 [Hss3#hss.peer_id,
                                  Hss3#hss.redownload_buffer_last_height]),
                    {false, finalize(Hss3)};
                FullMsg ->
                    %% Core line 122-124: full message → request more
                    {true, Hss3};
                true ->
                    %% Core line 126-130: non-full message and not done →
                    %% peer is withholding the chain it claimed to have
                    logger:debug("headerssync: peer=~p redownload aborted: "
                                 "incomplete headers at height=~B",
                                 [Hss3#hss.peer_id,
                                  Hss3#hss.redownload_buffer_last_height]),
                    {false, finalize(Hss3)}
                end,
            {ok, ReadyHeaders, RequestMore, Hss4};
        {error, Reason, Hss2} ->
            {error, Reason, finalize(Hss2)}
    end.

%% @doc Build the next GETHEADERS locator for this sync session.
%%
%% Core: NextHeadersRequestLocator, headerssync.cpp:296-317
-spec next_headers_request_locator(#hss{}) -> [binary()].
next_headers_request_locator(#hss{download_state = final}) ->
    [];
next_headers_request_locator(#hss{download_state = presync,
                                   chain_start = CS,
                                   last_header = LastHdr,
                                   current_height = CurH} = Hss) ->
    %% Core line 304-307: PRESYNC locator = last_received_hash + chain_start
    LastHash = case LastHdr of
        undefined ->
            %% No header received yet — start from chain_start
            maps:get(hash, CS, <<0:256>>);
        _ ->
            beamchain_serialize:block_hash(LastHdr)
    end,
    StartLocator = chain_start_locator(CS),
    case lists:member(LastHash, StartLocator) of
        true  -> StartLocator;
        false -> [LastHash | StartLocator]
    end ++ extra_log(Hss, CurH);

next_headers_request_locator(#hss{download_state = redownload,
                                   chain_start = CS,
                                   redownload_buffer_last_hash = LastHash}) ->
    %% Core line 309-312: REDOWNLOAD locator = redownload_buffer_last_hash + chain_start
    StartLocator = chain_start_locator(CS),
    case lists:member(LastHash, StartLocator) of
        true  -> StartLocator;
        false -> [LastHash | StartLocator]
    end.

%% @doc Return current phase atom.
-spec get_state(#hss{}) -> presync | redownload | final.
get_state(#hss{download_state = S}) -> S.

%% @doc Height reached during PRESYNC.
-spec get_presync_height(#hss{}) -> integer().
get_presync_height(#hss{current_height = H}) -> H.

%% @doc Cumulative work seen in PRESYNC.
-spec get_presync_work(#hss{}) -> non_neg_integer().
get_presync_work(#hss{current_chain_work = W}) -> W.

%% @doc Timestamp of last header in PRESYNC.
-spec get_presync_time(#hss{}) -> non_neg_integer().
get_presync_time(#hss{last_header = undefined}) -> 0;
get_presync_time(#hss{last_header = H}) -> H#block_header.timestamp.

%% -----------------------------------------------------------------
%% Internal: PRESYNC
%% -----------------------------------------------------------------

%% ValidateAndStoreHeadersCommitments.
%% Core: headerssync.cpp:139-175
-spec validate_and_store_commitments([#block_header{}], #hss{}) ->
    {ok, #hss{}} | {error, term(), #hss{}}.
validate_and_store_commitments([], Hss) ->
    {ok, Hss};
validate_and_store_commitments(Headers, Hss) ->
    %% Core line 148: check first header connects to last_header_received
    FirstPrev = (hd(Headers))#block_header.prev_hash,
    ExpectedPrev = case Hss#hss.last_header of
        undefined -> maps:get(hash, Hss#hss.chain_start, <<0:256>>);
        LH        -> beamchain_serialize:block_hash(LH)
    end,
    case FirstPrev =:= ExpectedPrev of
        false ->
            logger:debug("headerssync: peer=~p presync non-continuous at "
                         "height=~B",
                         [Hss#hss.peer_id, Hss#hss.current_height]),
            {error, non_continuous, Hss};
        true ->
            presync_loop(Headers, Hss)
    end.

presync_loop([], Hss) ->
    %% After consuming all headers, check if we've met the work threshold.
    %% Core lines 165-173
    maybe_transition_to_redownload(Hss);
presync_loop([Hdr | Rest], Hss) ->
    case validate_single_header(Hdr, Hss) of
        {ok, Hss2} -> presync_loop(Rest, Hss2);
        {error, Reason, Hss2} -> {error, Reason, Hss2}
    end.

%% ValidateAndProcessSingleHeader.
%% Core: headerssync.cpp:177-213
-spec validate_single_header(#block_header{}, #hss{}) ->
    {ok, #hss{}} | {error, term(), #hss{}}.
validate_single_header(Header, #hss{current_height = Height,
                                     params = Params,
                                     last_header = LastHdr,
                                     header_commitments = Commits,
                                     max_commitments = MaxC,
                                     commit_offset = Offset,
                                     commitment_period = Period,
                                     hasher_k0 = K0,
                                     hasher_k1 = K1,
                                     current_chain_work = Work} = Hss) ->
    NextHeight = Height + 1,
    PrevBits = case LastHdr of
        undefined -> maps:get(bits, Hss#hss.chain_start, 16#1d00ffff);
        _         -> LastHdr#block_header.bits
    end,
    %% Core line 189-193: PermittedDifficultyTransition
    case beamchain_pow:permitted_difficulty_transition(
             Params, NextHeight, PrevBits, Header#block_header.bits) of
        false ->
            logger:debug("headerssync: peer=~p invalid difficulty "
                         "transition at height=~B (presync)",
                         [Hss#hss.peer_id, NextHeight]),
            {error, invalid_difficulty, Hss};
        true ->
            %% Core lines 195-205: store commitment if at period boundary
            Commits2 = case NextHeight rem Period =:= Offset of
                true ->
                    BlockHash = beamchain_serialize:block_hash(Header),
                    Bit = siphash_bit(K0, K1, BlockHash),
                    queue:in(Bit, Commits);
                false ->
                    Commits
            end,
            case queue:len(Commits2) > MaxC of
                true ->
                    %% Core lines 199-204: chain too long
                    logger:debug("headerssync: peer=~p exceeded max "
                                 "commitments at height=~B (presync)",
                                 [Hss#hss.peer_id, NextHeight]),
                    {error, too_many_commitments, Hss};
                false ->
                    %% Core lines 208-210: update work + state
                    BlockWork = beamchain_pow:compute_work(Header#block_header.bits),
                    Hss2 = Hss#hss{
                        header_commitments = Commits2,
                        current_chain_work = Work + BlockWork,
                        last_header        = Header,
                        current_height     = NextHeight
                    },
                    {ok, Hss2}
            end
    end.

%% Check work threshold and transition to REDOWNLOAD if met.
%% Core: headerssync.cpp:165-173
maybe_transition_to_redownload(#hss{current_chain_work = CW,
                                     minimum_required_work = MinWork,
                                     chain_start = CS,
                                     peer_id = PeerId,
                                     current_height = CurH} = Hss) ->
    case CW >= MinWork of
        false ->
            {ok, Hss};
        true ->
            StartHeight = maps:get(height, CS, 0),
            StartHash   = maps:get(hash, CS, <<0:256>>),
            StartWork   = maps:get(chainwork, CS, 0),
            logger:debug("headerssync: peer=~p reached sufficient work at "
                         "height=~B, redownloading from height=~B",
                         [PeerId, CurH, StartHeight]),
            Hss2 = Hss#hss{
                redownloaded_headers           = queue:new(),
                redownload_buffer_last_height  = StartHeight,
                redownload_buffer_first_prev_hash = StartHash,
                redownload_buffer_last_hash    = StartHash,
                redownload_chain_work          = StartWork,
                download_state                 = redownload
            },
            {ok, Hss2}
    end.

%% -----------------------------------------------------------------
%% Internal: REDOWNLOAD
%% -----------------------------------------------------------------

%% ValidateAndStoreRedownloadedHeader (single header).
%% Core: headerssync.cpp:215-278
-spec validate_and_store_redownloaded(#block_header{}, #hss{}) ->
    {ok, #hss{}} | {error, term(), #hss{}}.
validate_and_store_redownloaded(
        Header,
        #hss{redownload_buffer_last_height = BufH,
             redownload_buffer_last_hash   = BufHash,
             params                        = Params,
             redownloaded_headers          = Buf,
             chain_start                   = CS,
             commit_offset                 = Offset,
             commitment_period             = Period,
             header_commitments            = Commits,
             hasher_k0                     = K0,
             hasher_k1                     = K1,
             redownload_chain_work         = RW,
             minimum_required_work         = MinWork,
             process_all_remaining         = AllRemaining,
             peer_id                       = PeerId} = Hss) ->
    NextHeight = BufH + 1,
    %% Core line 224: check connection
    case Header#block_header.prev_hash =:= BufHash of
        false ->
            logger:debug("headerssync: peer=~p non-continuous at "
                         "height=~B (redownload)",
                         [PeerId, NextHeight]),
            {error, non_continuous, Hss};
        true ->
            %% Core lines 230-240: PermittedDifficultyTransition
            PrevBits = case queue:is_empty(Buf) of
                true  -> maps:get(bits, CS, 16#1d00ffff);
                false ->
                    {value, Last} = queue:peek_r(Buf),
                    Last#compressed_hdr.bits
            end,
            case beamchain_pow:permitted_difficulty_transition(
                     Params, NextHeight, PrevBits,
                     Header#block_header.bits) of
                false ->
                    logger:debug("headerssync: peer=~p invalid difficulty "
                                 "transition at height=~B (redownload)",
                                 [PeerId, NextHeight]),
                    {error, invalid_difficulty, Hss};
                true ->
                    %% Core lines 243-248: accumulate work + maybe set flag
                    BlockWork = beamchain_pow:compute_work(Header#block_header.bits),
                    NewRW = RW + BlockWork,
                    AllRemaining2 = AllRemaining orelse NewRW >= MinWork,
                    %% Core lines 256-269: verify commitment (unless past target)
                    BlockHash = beamchain_serialize:block_hash(Header),
                    case check_commitment(AllRemaining2, NextHeight, Period,
                                         Offset, K0, K1, BlockHash, Commits,
                                         PeerId) of
                        {ok, Commits2} ->
                            %% Core lines 272-275: store compressed header
                            CHdr = #compressed_hdr{
                                version     = Header#block_header.version,
                                merkle_root = Header#block_header.merkle_root,
                                timestamp   = Header#block_header.timestamp,
                                bits        = Header#block_header.bits,
                                nonce       = Header#block_header.nonce
                            },
                            Hss2 = Hss#hss{
                                redownloaded_headers          = queue:in(CHdr, Buf),
                                redownload_buffer_last_height = NextHeight,
                                redownload_buffer_last_hash   = BlockHash,
                                redownload_chain_work         = NewRW,
                                process_all_remaining         = AllRemaining2,
                                header_commitments            = Commits2
                            },
                            {ok, Hss2};
                        {error, Reason, Commits2} ->
                            Hss2 = Hss#hss{header_commitments = Commits2},
                            {error, Reason, Hss2}
                    end
            end
    end.

%% Core lines 256-269: check commitment at redownload boundary.
-spec check_commitment(boolean(), integer(), pos_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(), binary(),
                       queue:queue(0|1), term()) ->
    {ok, queue:queue(0|1)} | {error, term(), queue:queue(0|1)}.
check_commitment(true, _NextH, _Period, _Offset, _K0, _K1, _Hash,
                 Commits, _PeerId) ->
    %% Past minimum_required_work — skip commitment checks.
    %% Core line 256: !m_process_all_remaining_headers
    {ok, Commits};
check_commitment(false, NextH, Period, Offset, K0, K1, Hash,
                 Commits, PeerId) ->
    case NextH rem Period =:= Offset of
        false ->
            {ok, Commits};
        true ->
            %% Core line 257-260: commitment overrun
            case queue:is_empty(Commits) of
                true ->
                    logger:debug("headerssync: peer=~p commitment overrun "
                                 "at height=~B",
                                 [PeerId, NextH]),
                    {error, commitment_overrun, Commits};
                false ->
                    %% Core lines 263-268: commitment mismatch
                    Expected = queue:get(Commits),
                    Commits2 = queue:drop(Commits),
                    Actual   = siphash_bit(K0, K1, Hash),
                    case Actual =:= Expected of
                        true  -> {ok, Commits2};
                        false ->
                            logger:debug("headerssync: peer=~p commitment "
                                         "mismatch at height=~B",
                                         [PeerId, NextH]),
                            {error, commitment_mismatch, Commits2}
                    end
            end
    end.

%% Process a batch of headers in REDOWNLOAD phase.
-spec store_redownloaded([#block_header{}], #hss{}) ->
    {ok, #hss{}} | {error, term(), #hss{}}.
store_redownloaded([], Hss) ->
    {ok, Hss};
store_redownloaded([H | Rest], Hss) ->
    case validate_and_store_redownloaded(H, Hss) of
        {ok, Hss2}           -> store_redownloaded(Rest, Hss2);
        {error, Reason, Hss2} -> {error, Reason, Hss2}
    end.

%% -----------------------------------------------------------------
%% Internal: release buffer
%% -----------------------------------------------------------------

%% PopHeadersReadyForAcceptance.
%% Core: headerssync.cpp:280-294
-spec pop_ready(#hss{}) -> #redownload_result{}.
pop_ready(#hss{redownloaded_headers          = Buf,
               redownload_buffer_size        = BufSize,
               process_all_remaining         = AllRemaining,
               redownload_buffer_first_prev_hash = FirstPrev} = Hss) ->
    pop_ready_loop(Buf, BufSize, AllRemaining, FirstPrev, [], Hss).

pop_ready_loop(Buf, BufSize, AllRemaining, PrevHash, Acc, Hss) ->
    ShouldPop = (queue:len(Buf) > BufSize)
                orelse (not queue:is_empty(Buf) andalso AllRemaining),
    case ShouldPop of
        false ->
            #redownload_result{
                headers = lists:reverse(Acc),
                hss     = Hss#hss{
                    redownloaded_headers          = Buf,
                    redownload_buffer_first_prev_hash = PrevHash
                }
            };
        true ->
            {value, CHdr} = queue:peek(Buf),
            Buf2 = queue:drop(Buf),
            %% Reconstruct full header using PrevHash.
            %% Core: m_redownloaded_headers.front().GetFullHeader(first_prev_hash)
            FullHdr = #block_header{
                version     = CHdr#compressed_hdr.version,
                prev_hash   = PrevHash,
                merkle_root = CHdr#compressed_hdr.merkle_root,
                timestamp   = CHdr#compressed_hdr.timestamp,
                bits        = CHdr#compressed_hdr.bits,
                nonce       = CHdr#compressed_hdr.nonce
            },
            NewPrevHash = beamchain_serialize:block_hash(FullHdr),
            pop_ready_loop(Buf2, BufSize, AllRemaining, NewPrevHash,
                           [FullHdr | Acc], Hss)
    end.

%% -----------------------------------------------------------------
%% Internal: helpers
%% -----------------------------------------------------------------

%% Compute 1-bit commitment: SipHash-2-4(K0, K1, block_hash) & 1.
%% Core: m_hasher(current.GetHash()) & 1
-spec siphash_bit(non_neg_integer(), non_neg_integer(), binary()) -> 0 | 1.
siphash_bit(K0, K1, Hash32) ->
    H = beamchain_crypto:siphash_uint256(K0, K1, Hash32),
    H band 1.

%% Finalize the state (free memory, mark final).
%% Core: Finalize(), headerssync.cpp:51-63
-spec finalize(#hss{}) -> #hss{}.
finalize(Hss) ->
    Hss#hss{
        header_commitments            = queue:new(),
        redownloaded_headers          = queue:new(),
        redownload_buffer_last_hash   = <<0:256>>,
        redownload_buffer_first_prev_hash = <<0:256>>,
        process_all_remaining         = false,
        current_height                = 0,
        download_state                = final
    }.

-spec maybe_finalize(boolean(), #hss{}) -> #hss{}.
maybe_finalize(true, Hss) -> Hss;     %% keep state — more work needed
maybe_finalize(false, Hss) -> finalize(Hss).

%% Build a block-locator-style entry list for chain_start.
%% Mirrors Core's LocatorEntries(&m_chain_start) in the locator functions.
%% We use only the chain_start hash (no DB calls needed — we already have
%% the hash in the state).  Core builds a full exponential locator from the
%% chain_start CBlockIndex, but for the anti-DoS pipeline the important
%% property is that the locator contains the fork point so the peer knows
%% where to resume.
-spec chain_start_locator(map()) -> [binary()].
chain_start_locator(CS) ->
    Hash = maps:get(hash, CS, <<0:256>>),
    [Hash].

%% Suppress unused variable warning for logging helper.
extra_log(_Hss, _H) -> [].

%% Return {CommitmentPeriod, RedownloadBufferSize} for network.
-spec sync_params(atom()) -> {pos_integer(), pos_integer()}.
sync_params(mainnet)  -> {?COMMITMENT_PERIOD_MAINNET,  ?REDOWNLOAD_BUFFER_MAINNET};
sync_params(testnet4) -> {?COMMITMENT_PERIOD_TESTNET4, ?REDOWNLOAD_BUFFER_TESTNET4};
sync_params(signet)   -> {?COMMITMENT_PERIOD_SIGNET,   ?REDOWNLOAD_BUFFER_SIGNET};
sync_params(testnet)  -> {?COMMITMENT_PERIOD_TESTNET,  ?REDOWNLOAD_BUFFER_TESTNET};
sync_params(regtest)  -> {?COMMITMENT_PERIOD_REGTEST,  ?REDOWNLOAD_BUFFER_REGTEST};
sync_params(_)        -> {?COMMITMENT_PERIOD_MAINNET,  ?REDOWNLOAD_BUFFER_MAINNET}.
