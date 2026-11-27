use super::*;

pub(super) fn block_hash_vec(cache: &Cache, height: u32) -> Vec<u8> {
    cache
        .get_block_hash(height)
        .ok()
        .flatten()
        .map(|h| h.to_vec())
        .unwrap_or_default()
}

/// Retained snapshot row. `state_root` is blake3(tree_data): the compact cache
/// has no header money-tree root to check against.
pub(super) fn persisted_tree_state(
    height: u32,
    tree_data: Vec<u8>,
    block_hash: Vec<u8>,
) -> proto::TreeState {
    let state_root = blake3::hash(&tree_data).as_bytes().to_vec();
    proto::TreeState {
        height,
        tree_data,
        block_hash,
        state_root,
        is_checkpoint: true,
    }
}

pub(super) fn snapshot_miss_status(height: u32, tip: u32, lower: Option<u32>) -> Status {
    let detail = match lower {
        Some(snap) => format!("greatest snapshot <= {height} is {snap}"),
        None => format!("no snapshot at or below {height}"),
    };
    Status::failed_precondition(format!(
        "GetTreeState height {height} is not a retained snapshot (tip {tip}); {detail}"
    ))
}

/// blake3(height LE || tree_data || nullifier_index) — lockstep with mobile FFI.
pub(super) fn snapshot_integrity_hash(
    height: u32,
    tree_data: &[u8],
    nullifier_index: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(tree_data);
    hasher.update(nullifier_index);
    *hasher.finalize().as_bytes()
}

/// Maximum number of blocks allowed in a single range request.
/// Prevents DoS via unbounded range requests that would load
/// the entire cache into memory.
pub(super) const MAX_BLOCKS_PER_REQUEST: u32 = 10_000;
/// Max heights in a sparse GetCompactBlocksAtHeights request.
pub(super) const MAX_SPARSE_HEIGHTS: usize = 512;
/// Max serialized detection key size before parse (S24 / DoS).
/// Param2 (D=4096, moduli 40×3, n=1024) det-keys measure ~120 MiB on the wire.
pub(super) const MAX_DETECTION_KEY_BYTES: usize = 160 * 1024 * 1024;
/// Cap on sum of all detection_keys lengths in one request.
pub(super) const MAX_DETECTION_KEYS_TOTAL_BYTES: usize = 160 * 1024 * 1024;
/// Concurrent FHE worker slots (GetUnifOmrDigest / FetchPirBatch).
pub(super) const DEFAULT_FHE_PERMITS: usize = 2;
/// Max wait for the next DetectionKeyChunk. The FHE permit is not held
/// during this read; a slow client must not occupy a worker slot.
#[cfg(feature = "fhe-omr")]
pub(super) const DETECTION_KEY_CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Whole detection-key upload default deadline, including every chunk.
/// Overridden by `Config.upload_deadline_s` (300s default for ~120 MiB over Tor).
#[cfg(feature = "fhe-omr")]
pub(super) const UPLOAD_DEADLINE: Duration = Duration::from_secs(300);
/// Wait for an FHE worker before returning UNAVAILABLE.
#[cfg(feature = "fhe-omr")]
pub(super) const FHE_PERMIT_WAIT: Duration = Duration::from_secs(10);
/// Default in-flight detection-key upload budget.
pub(super) const DEFAULT_UPLOAD_BUDGET_MIB: usize = 512;
/// Default concurrent detection-key uploads from one IP.
pub(super) const DEFAULT_MAX_UPLOADS_PER_IP: usize = 2;
/// One IP must not hold both FHE permits via FetchPirBatch.
#[cfg(feature = "fhe-omr")]
pub(super) const MAX_PIR_INFLIGHT_PER_IP: usize = 1;
/// A client that stops reading ends the stream instead of pinning the task.
pub(super) const STREAM_SEND_TIMEOUT: Duration = Duration::from_secs(60);
/// Process-wide cap on block-range streams. Extra requests wait, then fail.
pub(super) const MAX_BLOCK_RANGE_STREAMS: usize = 200;
pub(super) const BLOCK_RANGE_WAIT: Duration = Duration::from_secs(10);
/// Process-wide cap on concurrent `SubscribeBlocks` streams.
pub(super) const MAX_SUBSCRIBE_STREAMS: usize = 512;
/// Max SealPIR stripe query ciphertexts (window ≤ stripes × BFV degree).
#[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
pub(super) const MAX_PIR_STRIPES: usize = 8;
/// Max bytes per SealPIR query ciphertext (rejects multi-MB garbage).
#[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
pub(super) const MAX_PIR_QUERY_CT_BYTES: usize = 4 * 1024 * 1024;
/// Max protobuf-encoded compact-block bytes materialized for one PIR window.
#[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
pub(super) const MAX_PIR_WINDOW_ENCODED_BYTES: usize = 64 * 1024 * 1024;
/// One `FetchPirBatch` per limb. Matches `MAX_PIR_LIMBS` (4096) so a peer can
/// pull every column of one compact block within the minute window.
pub(super) const PIR_RATE_LIMIT_PER_MIN: u32 = 4096;
/// Max opaque recipient OMR metadata on SendTransaction / RegisterOmrClue.
pub(super) const MAX_OMR_METADATA_ENC_BYTES: usize = 4096;
/// Extra OMR clue hints on SendTransaction. DarkFi allows 20 calls per
/// transaction; 64 leaves room for a few outputs per call and still stops
/// the quadratic hint rewrite.
pub(super) const MAX_EXTRA_OMR_CLUES: usize = 64;
/// Serialized UnifOMR clue public key (`n = 1024`: 4-byte header + 16 bytes × n).
pub(super) const CLUE_PUBLIC_KEY_WIRE_LEN: usize = 4 + 16 * 1024;
/// Upper bound on `CluePublicKeyRegistration.clue_public_key` before signature verify.
pub(super) const MAX_CLUE_PUBLIC_KEY_BYTES: usize = 65_536;
/// Upper bound on `CluePublicKeyRegistration.ownership_proof` before signature verify.
pub(super) const MAX_OWNERSHIP_PROOF_BYTES: usize = 4096;
/// Compact-block wire version reported by GetLightInfo.
/// Bump when the compact format or RPC contract changes.
/// 2.1.0: compact DAO calls and Money `func_code` (token mint, auth-token history).
/// 2.0.0: historical snapshots, padded ranges, detection-key pool,
/// ChainTip subscribe, compact output bodies. No 1.0.0 compatibility path.
pub(super) const LIGHTWALLET_PROTO_VERSION: &str = "2.1.0";

/// Default max raw tx bytes (overridden by Config.max_tx_bytes).
pub(super) const DEFAULT_MAX_TX_BYTES: usize = 2_000_000;
/// Minimum span for GetNoteCommitments, GetNullifiers, and GetCompactOutputBodies.
/// Matches the client pad rule: span is a power of two of at least this size.
pub(super) const MIN_PADDED_RANGE_SPAN: u32 = 1024;
/// A client pads against the tip it saw at the start of its sync cycle. A
/// bucket it cut short at that tip may end this many blocks below ours. Kept
/// well under one bucket so a raw cursor range is not mistaken for a cut bucket.
pub(super) const MAX_PADDED_TIP_LAG: u32 = 64;
/// SubscribeBlocks keeps one unsent ChainTip. Further tips are skipped, not dropped.
pub(super) const SUBSCRIBE_TIP_BUFFER: usize = 1;
/// Max characters in LookupZkas contract id (base58 + headroom).
pub(super) const MAX_CONTRACT_ID_CHARS: usize = 128;

/// How long a SendTransaction peer binding remains valid for RegisterOmrClue (S12).
pub(super) const SEND_PEER_BIND_TTL: Duration = Duration::from_secs(86_400);
/// Minimum interval between full-map GC scans of `recent_send_peers`.
pub(super) const SEND_PEER_GC_INTERVAL: Duration = Duration::from_secs(60);
/// Hard cap on `recent_send_peers` entries to prevent unbounded memory growth (M2).
pub(super) const MAX_SEND_PEER_ENTRIES: usize = 100_000;

/// Lock-free atomic metrics counters for periodic INFO summaries.
#[derive(Default)]
pub struct ServiceMetrics {
    pub(super) rpc_requests: AtomicU64,
    pub(super) rate_limited: AtomicU64,
    pub(super) active_streams: AtomicUsize,
}

/// Point-in-time snapshot of [`ServiceMetrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub rpc_requests: u64,
    pub rate_limited: u64,
    pub active_streams: usize,
}

impl ServiceMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(&self) {
        self.rpc_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            rpc_requests: self.rpc_requests.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
        }
    }

    pub(super) fn track_stream(self: &Arc<Self>) -> ActiveStreamGuard {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        ActiveStreamGuard {
            metrics: Arc::clone(self),
        }
    }
}

pub(super) struct ActiveStreamGuard {
    pub(super) metrics: Arc<ServiceMetrics>,
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.metrics.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) struct SendPeerTable {
    pub(super) entries: HashMap<[u8; 32], (IpAddr, Instant)>,
    pub(super) last_gc: Instant,
}

impl SendPeerTable {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_gc: Instant::now(),
        }
    }
}

/// Inclusive height span as `u64` so `end = u32::MAX` cannot wrap the cap.
#[allow(clippy::result_large_err)]
pub(super) fn height_span(start: u32, end: u32) -> Result<u64, Status> {
    if start > end {
        return Err(Status::invalid_argument(format!(
            "Invalid height range: start={start} > end={end}"
        )));
    }
    Ok((end as u64) - (start as u64) + 1)
}

/// `end == 0` means "through the cached tip". Any other end is clamped to the tip.
#[allow(clippy::result_large_err)]
pub(super) fn resolve_block_range(
    cache: &crate::cache::Cache,
    start: u32,
    end: u32,
) -> Result<(u32, u32), Status> {
    let tip = match cache.get_tip() {
        Ok(Some((tip, _))) => tip,
        Ok(None) => return Err(Status::unavailable("No blocks cached yet")),
        Err(e) => return Err(cache_status(e)),
    };
    let end = if end == 0 { tip } else { end.min(tip) };
    if start > end {
        return Err(Status::invalid_argument("block range start exceeds tip"));
    }
    reject_oversized_window(start, end)?;
    Ok((start, end))
}

/// Last height of `[start, end]` a digest may cover, and whether that is all of it.
///
/// Stops at the tip and strictly before the first height missing from the
/// cache, so clients advancing to `max(slot_heights)` never skip a hole.
/// `None` means no height is evaluable (hole or tip below `start`).
#[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
#[allow(clippy::result_large_err)]
pub(super) fn digest_evaluable_end(
    cache: &Cache,
    start: u32,
    end: u32,
) -> Result<(Option<u32>, bool), Status> {
    let tip = cache
        .get_tip()
        .map_err(cache_status)?
        .map(|(h, _)| h)
        .unwrap_or(0);
    let last = end.min(tip);
    if start > last {
        return Ok((None, false));
    }
    if let Some(hole) = cache
        .first_missing_hash(start, last)
        .map_err(cache_status)?
    {
        return Ok((hole.checked_sub(1).filter(|&p| p >= start), false));
    }
    Ok((Some(last), tip >= end))
}

/// Decoy clue key of the same wire length as a real UnifOMR public key.
///
/// Default builds cannot run BFV keygen. A 32-byte hash would still tell a
/// network observer that the address is unregistered.
#[cfg_attr(feature = "fhe-omr", allow(dead_code))]
pub(super) fn padded_decoy_clue_public_key(
    payment_pubkey: &[u8; 32],
    pepper: &[u8; 32],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_keyed(pepper);
    hasher.update(b"unifomr-clue-decoy-v1");
    hasher.update(payment_pubkey);
    let mut dummy = vec![0u8; CLUE_PUBLIC_KEY_WIRE_LEN];
    hasher.finalize_xof().fill(&mut dummy);
    dummy
}

/// Expand `[start, end]` into a padded bucket the server will accept.
///
/// Span is at least 1024 and a power of two, and at most 8192 (the largest
/// power of two that fits in the 10_000 block cap). The window ends at
/// `end.min(tip)` and grows backward. A tip below block 1023 has no full
/// bucket; the whole chain `0..=end` is returned instead.
pub fn pad_block_range(start: u32, end: u32, tip: u32) -> (u32, u32) {
    let end = end.min(tip);
    let start = start.min(end);
    let raw = (end as u64).saturating_sub(start as u64).saturating_add(1);
    let mut span = raw.max(MIN_PADDED_RANGE_SPAN as u64);
    if !span.is_power_of_two() {
        span = span.next_power_of_two();
    }
    // 16384 exceeds MAX_BLOCKS_PER_REQUEST (10_000).
    const MAX_BUCKET: u64 = 8192;
    if span > MAX_BUCKET {
        span = MAX_BUCKET;
    }
    let room = (tip as u64).saturating_add(1);
    while span > room && span > 1 {
        span >>= 1;
    }
    if span < MIN_PADDED_RANGE_SPAN as u64 {
        return (0, end);
    }
    let span_u = span as u32;
    if (end as u64).saturating_add(1) >= span {
        let padded_start = end.saturating_add(1).saturating_sub(span_u);
        return (padded_start, end);
    }
    (0, span_u.saturating_sub(1))
}

#[allow(clippy::result_large_err)]
pub(super) fn reject_oversized_window(start: u32, end: u32) -> Result<u64, Status> {
    let span = height_span(start, end)?;
    if span > MAX_BLOCKS_PER_REQUEST as u64 {
        return Err(Status::invalid_argument(format!(
            "Range too large: {span} blocks requested, max is {MAX_BLOCKS_PER_REQUEST}"
        )));
    }
    Ok(span)
}

/// Why `start..=end` is not a padded bucket, or `None` when it is valid.
///
/// Valid ranges are what the client `pad_block_range` emits. `end` is at or
/// before the tip and `span = end - start + 1` is at most `max_range`. Either
/// the span is a power of two of at least [`MIN_PADDED_RANGE_SPAN`], or the
/// bucket was cut short at the client's tip: `start` sits on a bucket
/// boundary and `end` is within [`MAX_PADDED_TIP_LAG`] of our tip. A short
/// unpadded cursor range is rejected.
pub(super) fn padded_range_rejection(
    start: u32,
    end: u32,
    tip: u32,
    max_range: u32,
) -> Option<String> {
    if start > end {
        return Some(format!("Invalid height range: start={start} > end={end}"));
    }
    if end > tip {
        return Some(format!("range end {end} is past tip {tip}"));
    }
    let span = (end as u64) - (start as u64) + 1;
    if span > max_range as u64 {
        return Some(format!(
            "Range too large: {span} blocks requested, max is {max_range}"
        ));
    }
    if span >= MIN_PADDED_RANGE_SPAN as u64 && span.is_power_of_two() {
        return None;
    }
    // Cut short at the tip: one bucket of size B >= span aligned to B, or two
    // buckets of size B aligned to B. Both put `start` on a multiple of
    // max(B_full / 2, MIN) where B_full is the full span rounded up.
    let full = span.max(MIN_PADDED_RANGE_SPAN as u64).next_power_of_two();
    let align = (full / 2).max(MIN_PADDED_RANGE_SPAN as u64);
    if !(start as u64).is_multiple_of(align) {
        return Some(format!(
            "range span {span} must be a power of two of at least {MIN_PADDED_RANGE_SPAN}, \
             or a bucket aligned to {align} that ends at the tip"
        ));
    }
    if (end as u64) + (MAX_PADDED_TIP_LAG as u64) < tip as u64 {
        return Some(format!(
            "range {start}..={end} is a partial bucket that does not end at the tip {tip}"
        ));
    }
    None
}

#[allow(clippy::result_large_err)]
pub(super) fn require_padded_block_range(
    cache: &Cache,
    start: u32,
    end: u32,
) -> Result<(u32, u32), Status> {
    let tip = match cache.get_tip() {
        Ok(Some((tip, _))) => tip,
        Ok(None) => return Err(Status::unavailable("No blocks cached yet")),
        Err(e) => return Err(cache_status(e)),
    };
    match padded_range_rejection(start, end, tip, MAX_BLOCKS_PER_REQUEST) {
        None => Ok((start, end)),
        Some(reason) => Err(Status::invalid_argument(reason)),
    }
}

pub(super) fn cache_status(e: impl std::fmt::Display) -> Status {
    tracing::error!(target: "lightwalletd::server", "cache error: {e}");
    Status::internal("cache error")
}

pub(super) fn backend_unavailable() -> Status {
    Status::unavailable("backend unavailable")
}

/// Outcome of `broadcast_tx` plus the mempool/chain confirm that follows a success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreBroadcastFollowup {
    /// `broadcast_tx` itself failed. The transaction was not accepted.
    BroadcastFailed,
    /// The node answered, and the tx is not in the mempool or on chain.
    NotConfirmed,
    /// The node answered, and the tx is in the mempool or on chain.
    Confirmed,
    /// Confirm lost the connection after `broadcast_tx` returned a hash.
    /// The transaction may already have propagated.
    ConfirmConnectionError,
}

/// Whether clue hints and encrypted metadata stored before broadcast should be deleted.
///
/// A connection error after a successful broadcast keeps the rows. The 24h TTL
/// reaps them. Broadcast failure and a negative confirm still drop them.
pub(super) fn drop_pre_broadcast_rows(followup: PreBroadcastFollowup) -> bool {
    matches!(
        followup,
        PreBroadcastFollowup::BroadcastFailed | PreBroadcastFollowup::NotConfirmed
    )
}

/// Stream compact blocks one sled read at a time; abort on holes, mixed forks,
/// or client disconnect (do not materialize the whole window).
pub(super) async fn send_stream<T: Send>(
    tx: &tokio::sync::mpsc::Sender<Result<T, Status>>,
    msg: Result<T, Status>,
) -> bool {
    matches!(
        tokio::time::timeout(STREAM_SEND_TIMEOUT, tx.send(msg)).await,
        Ok(Ok(()))
    )
}

pub(super) fn spawn_compact_range<T, F>(
    cache: Arc<Cache>,
    start: u32,
    end: u32,
    permit: tokio::sync::OwnedSemaphorePermit,
    stream_guard: ActiveStreamGuard,
    map: F,
) -> tokio_stream::wrappers::ReceiverStream<Result<T, Status>>
where
    T: Send + 'static,
    F: Fn(&CompactBlock) -> T + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        let _permit = permit;
        let _stream_guard = stream_guard;
        let mut prev: Option<CompactBlock> = None;
        for height in start..=end {
            if tx.is_closed() {
                return;
            }
            let block = match cache.get_compact_block(height) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    let _ = send_stream(&tx, Err(discontinuity_status())).await;
                    return;
                }
                Err(e) => {
                    let _ = send_stream(&tx, Err(cache_status(e))).await;
                    return;
                }
            };
            if let Some(ref p) = prev {
                if let Err(st) = check_successor(p, &block) {
                    let _ = send_stream(&tx, Err(st)).await;
                    return;
                }
            } else if block.height != start {
                let _ = send_stream(&tx, Err(discontinuity_status())).await;
                return;
            }
            if !send_stream(&tx, Ok(map(&block))).await {
                return;
            }
            prev = Some(block);
            tokio::task::yield_now().await;
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

/// One [`proto::CompactOutputBody`] per Money output. Nullifiers are omitted.
pub(super) fn spawn_output_bodies(
    cache: Arc<Cache>,
    start: u32,
    end: u32,
    permit: tokio::sync::OwnedSemaphorePermit,
    stream_guard: ActiveStreamGuard,
) -> tokio_stream::wrappers::ReceiverStream<Result<proto::CompactOutputBody, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        let _permit = permit;
        let _stream_guard = stream_guard;
        let mut prev: Option<CompactBlock> = None;
        for height in start..=end {
            if tx.is_closed() {
                return;
            }
            let block = match cache.get_compact_block(height) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    let _ = send_stream(&tx, Err(discontinuity_status())).await;
                    return;
                }
                Err(e) => {
                    let _ = send_stream(&tx, Err(cache_status(e))).await;
                    return;
                }
            };
            if let Some(ref p) = prev {
                if let Err(st) = check_successor(p, &block) {
                    let _ = send_stream(&tx, Err(st)).await;
                    return;
                }
            } else if block.height != start {
                let _ = send_stream(&tx, Err(discontinuity_status())).await;
                return;
            }
            for tx_body in &block.txs {
                for output in &tx_body.outputs {
                    let body = proto::CompactOutputBody {
                        height: block.height,
                        hash: block.hash.to_vec(),
                        prev_hash: block.prev_hash.to_vec(),
                        coin: output.coin.to_vec(),
                        encrypted_note: output.encrypted_note.clone(),
                        omr_clue: output.omr_clue.clone(),
                        omr_metadata_enc: output.omr_metadata_enc.clone(),
                        tx_hash: tx_body.tx_hash.to_vec(),
                        func_code: u32::from(output.func_code),
                    };
                    if !send_stream(&tx, Ok(body)).await {
                        return;
                    }
                }
            }
            prev = Some(block);
            tokio::task::yield_now().await;
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

/// Money outputs whose `func_code` matches, plus auth-token events with no coin.
pub(super) fn spawn_outputs_by_func(
    cache: Arc<Cache>,
    start: u32,
    end: u32,
    func_code: u32,
    permit: tokio::sync::OwnedSemaphorePermit,
    stream_guard: ActiveStreamGuard,
) -> tokio_stream::wrappers::ReceiverStream<Result<proto::CompactOutputBody, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        let _permit = permit;
        let _stream_guard = stream_guard;
        let mut prev: Option<CompactBlock> = None;
        for height in start..=end {
            if tx.is_closed() {
                return;
            }
            let block = match cache.get_compact_block(height) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    let _ = send_stream(&tx, Err(discontinuity_status())).await;
                    return;
                }
                Err(e) => {
                    let _ = send_stream(&tx, Err(cache_status(e))).await;
                    return;
                }
            };
            if let Some(ref p) = prev {
                if let Err(st) = check_successor(p, &block) {
                    let _ = send_stream(&tx, Err(st)).await;
                    return;
                }
            } else if block.height != start {
                let _ = send_stream(&tx, Err(discontinuity_status())).await;
                return;
            }
            for tx_body in &block.txs {
                for output in &tx_body.outputs {
                    if u32::from(output.func_code) != func_code {
                        continue;
                    }
                    let body = proto::CompactOutputBody {
                        height: block.height,
                        hash: block.hash.to_vec(),
                        prev_hash: block.prev_hash.to_vec(),
                        coin: output.coin.to_vec(),
                        encrypted_note: output.encrypted_note.clone(),
                        omr_clue: output.omr_clue.clone(),
                        omr_metadata_enc: output.omr_metadata_enc.clone(),
                        tx_hash: tx_body.tx_hash.to_vec(),
                        func_code,
                    };
                    if !send_stream(&tx, Ok(body)).await {
                        return;
                    }
                }
            }
            for event in &block.func_events {
                if u32::from(event.func_code) != func_code {
                    continue;
                }
                let body = proto::CompactOutputBody {
                    height: block.height,
                    hash: block.hash.to_vec(),
                    prev_hash: block.prev_hash.to_vec(),
                    coin: vec![0u8; 32],
                    encrypted_note: Vec::new(),
                    omr_clue: Vec::new(),
                    omr_metadata_enc: Vec::new(),
                    tx_hash: event.tx_hash.to_vec(),
                    func_code,
                };
                if !send_stream(&tx, Ok(body)).await {
                    return;
                }
            }
            prev = Some(block);
            tokio::task::yield_now().await;
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

pub(super) fn spawn_dao_calls(
    cache: Arc<Cache>,
    start: u32,
    end: u32,
    permit: tokio::sync::OwnedSemaphorePermit,
    stream_guard: ActiveStreamGuard,
) -> tokio_stream::wrappers::ReceiverStream<Result<proto::CompactDaoCall, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        let _permit = permit;
        let _stream_guard = stream_guard;
        let mut prev: Option<CompactBlock> = None;
        for height in start..=end {
            if tx.is_closed() {
                return;
            }
            let block = match cache.get_compact_block(height) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    let _ = send_stream(&tx, Err(discontinuity_status())).await;
                    return;
                }
                Err(e) => {
                    let _ = send_stream(&tx, Err(cache_status(e))).await;
                    return;
                }
            };
            if let Some(ref p) = prev {
                if let Err(st) = check_successor(p, &block) {
                    let _ = send_stream(&tx, Err(st)).await;
                    return;
                }
            } else if block.height != start {
                let _ = send_stream(&tx, Err(discontinuity_status())).await;
                return;
            }
            for call in &block.dao_calls {
                let body = proto::CompactDaoCall {
                    height: block.height,
                    tx_hash: call.tx_hash.to_vec(),
                    kind: call.kind,
                    bulla: call.bulla.clone(),
                    payload: call.payload.clone(),
                };
                if !send_stream(&tx, Ok(body)).await {
                    return;
                }
            }
            prev = Some(block);
            tokio::task::yield_now().await;
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

/// Canonicalize IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1` -> `127.0.0.1`)
/// so dual-stack listeners and `X-Forwarded-For` hops match `trusted_proxies`
/// and share a single per-IP rate-limit bucket.
pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Normalize client IP for rate limiting & per-peer caps: IPv6 clients are
/// grouped by `/64` prefix so rotating interface IDs cannot bypass limits.
pub(super) fn rate_limit_ip(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (!0u128 << 64);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

/// True if `ip` matches an allow-list entry (exact address or IPv4/IPv6 CIDR).
pub(super) fn ip_matches_proxy_entry(ip: IpAddr, entry: &str) -> bool {
    let ip = canonical_ip(ip);
    let entry = entry.trim();
    if let Ok(exact) = entry.parse::<IpAddr>() {
        return ip == canonical_ip(exact);
    }
    let Some((base, bits)) = entry.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    if let (IpAddr::V4(ip4), Ok(base4)) = (ip, base.parse::<Ipv4Addr>()) {
        if bits <= 32 {
            let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
            return (u32::from(ip4) & mask) == (u32::from(base4) & mask);
        }
    }
    if let (IpAddr::V6(ip6), Ok(base6)) = (ip, base.parse::<Ipv6Addr>()) {
        if bits <= 128 {
            let mask = if bits == 0 { 0 } else { !0u128 << (128 - bits) };
            return (u128::from(ip6) & mask) == (u128::from(base6) & mask);
        }
    }
    false
}

/// Parse one `X-Forwarded-For` hop (bare IPv4/IPv6, bracketed IPv6, or `ip:port`).
pub(super) fn parse_forwarded_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(canonical_ip(ip));
    }
    if let Ok(sa) = hop.parse::<SocketAddr>() {
        return Some(canonical_ip(sa.ip()));
    }
    if let Some(inner) = hop.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(ip) = inner.parse::<Ipv6Addr>() {
            return Some(canonical_ip(IpAddr::V6(ip)));
        }
    }
    None
}

/// Client IP from one or more `X-Forwarded-For` header values when the TCP peer
/// is a trusted proxy.
///
/// Walks headers and comma-separated hops **right-to-left** and skips entries
/// that match `trusted` (the proxies themselves). Both nginx and ngrok append
/// the immediate client IP at the right end (or as a later HTTP/2 header), so
/// leftmost hops are client-controlled and must never be trusted. If an
/// unparseable non-empty hop is encountered before an untrusted IP, stops and
/// returns `None` (falling back to the TCP peer) rather than trusting a spoofed
/// IP further left.
pub(super) fn client_ip_from_forwarded_headers<'a, I>(
    headers: I,
    trusted: &[String],
) -> Option<IpAddr>
where
    I: DoubleEndedIterator<Item = &'a str>,
{
    for header in headers.rev() {
        for hop in header.split(',').rev() {
            let hop = hop.trim();
            if hop.is_empty() {
                continue;
            }
            let ip = parse_forwarded_hop(hop)?;
            if trusted.iter().any(|e| ip_matches_proxy_entry(ip, e)) {
                continue;
            }
            return Some(ip);
        }
    }
    None
}

#[cfg(test)]
pub(super) fn client_ip_from_forwarded(header: &str, trusted: &[String]) -> Option<IpAddr> {
    client_ip_from_forwarded_headers(std::iter::once(header), trusted)
}

/// Resolve the effective client IP from the TCP peer address and gRPC metadata.
pub(super) fn resolve_peer_ip(
    remote: IpAddr,
    metadata: &tonic::metadata::MetadataMap,
    trusted_proxies: &[String],
) -> IpAddr {
    let remote = canonical_ip(remote);
    if trusted_proxies.is_empty() {
        return remote;
    }
    let trusted = trusted_proxies
        .iter()
        .any(|e| ip_matches_proxy_entry(remote, e));
    if !trusted {
        return remote;
    }
    let xff_headers: Vec<&str> = metadata
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    client_ip_from_forwarded_headers(xff_headers.into_iter(), trusted_proxies).unwrap_or(remote)
}

/// Pre-flattened, validated RLWE clues for one `(start, end)` window.
///
/// Shared across concurrent digest requests via `Arc` so repeat digests for
/// the same padded window skip sled reads, clue deserialization, BLAKE3
/// checksums, and slot-height packing. Digest ciphertexts are never stored —
/// they differ per detection key.
#[cfg(feature = "fhe-omr")]
pub(super) struct FlattenedClueWindow {
    pub(super) messages: Vec<crate::unifomr::RlweCiphertext>,
    pub(super) slot_heights_wire: Vec<u8>,
    pub(super) truncated: bool,
}

#[cfg(feature = "fhe-omr")]
pub(super) struct ClueWindowEntry {
    pub(super) end_hash: [u8; 32],
    pub(super) window: Arc<FlattenedClueWindow>,
}

#[cfg(feature = "fhe-omr")]
pub(super) struct ClueWindowCache {
    pub(super) map: HashMap<(u32, u32), ClueWindowEntry>,
    pub(super) order: std::collections::VecDeque<(u32, u32)>,
}

#[cfg(feature = "fhe-omr")]
impl ClueWindowCache {
    const CAP: usize = 8;

    pub(super) fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    pub(super) fn get(
        &self,
        start: u32,
        end: u32,
        end_hash: [u8; 32],
    ) -> Option<Arc<FlattenedClueWindow>> {
        if end_hash == [0u8; 32] {
            return None;
        }
        let hit = self.map.get(&(start, end))?;
        if hit.end_hash != end_hash {
            return None;
        }
        Some(Arc::clone(&hit.window))
    }

    pub(super) fn insert(
        &mut self,
        start: u32,
        end: u32,
        end_hash: [u8; 32],
        window: Arc<FlattenedClueWindow>,
    ) {
        if end_hash == [0u8; 32] {
            return;
        }
        let key = (start, end);
        if let std::collections::hash_map::Entry::Occupied(mut entry) = self.map.entry(key) {
            entry.insert(ClueWindowEntry { end_hash, window });
            return;
        }
        while self.order.len() >= Self::CAP {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(key);
        self.map.insert(key, ClueWindowEntry { end_hash, window });
    }
}

/// Clue-stripped protobuf payloads for one PIR window.
///
/// Limb RPCs share this buffer. The end-block hash drops the entry after a
/// reorg. Digest ciphertexts are not stored.
#[cfg(feature = "fhe-omr")]
pub(super) struct PirWindowEntry {
    pub(super) end_hash: [u8; 32],
    pub(super) payloads: Arc<Vec<Vec<u8>>>,
}

#[cfg(feature = "fhe-omr")]
pub(super) struct PirWindowCache {
    pub(super) map: HashMap<(u32, u32), PirWindowEntry>,
    pub(super) order: std::collections::VecDeque<(u32, u32)>,
}

#[cfg(feature = "fhe-omr")]
impl PirWindowCache {
    const CAP: usize = 4;

    pub(super) fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    pub(super) fn get(
        &self,
        start: u32,
        end: u32,
        end_hash: [u8; 32],
    ) -> Option<Arc<Vec<Vec<u8>>>> {
        if end_hash == [0u8; 32] {
            return None;
        }
        let hit = self.map.get(&(start, end))?;
        if hit.end_hash != end_hash {
            return None;
        }
        Some(Arc::clone(&hit.payloads))
    }

    pub(super) fn insert(
        &mut self,
        start: u32,
        end: u32,
        end_hash: [u8; 32],
        payloads: Arc<Vec<Vec<u8>>>,
    ) {
        if end_hash == [0u8; 32] {
            return;
        }
        let key = (start, end);
        if let std::collections::hash_map::Entry::Occupied(mut entry) = self.map.entry(key) {
            entry.insert(PirWindowEntry { end_hash, payloads });
            return;
        }
        while self.order.len() >= Self::CAP {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(key);
        self.map.insert(key, PirWindowEntry { end_hash, payloads });
    }
}

/// End-block hash for a PIR window, or the tip hash when `end` is the tip
/// and the height index has no row yet.
#[cfg(feature = "fhe-omr")]
pub(super) fn pir_window_end_hash(cache: &Cache, end: u32) -> [u8; 32] {
    if let Ok(Some(hash)) = cache.get_block_hash(end) {
        return hash;
    }
    match cache.get_tip() {
        Ok(Some((tip_h, tip_hash))) if tip_h == end => tip_hash,
        _ => [0u8; 32],
    }
}

/// Prost-encode one compact block for PIR with every `omr_clue` cleared.
///
/// Round 1 already matched the clue. A real UnifOMR clue is larger than
/// `MAX_PIR_PAYLOAD_BYTES`, so limb 0 would be the overflow sentinel and
/// the note could not be reassembled. Coin, encrypted note, metadata, and
/// nullifiers stay on the wire.
#[cfg(feature = "fhe-omr")]
pub(super) fn encode_compact_block_for_pir(block: &CompactBlock) -> Vec<u8> {
    use prost::Message;
    let mut proto_block = block.to_proto();
    for tx in &mut proto_block.txs {
        for output in &mut tx.outputs {
            output.omr_clue.clear();
        }
    }
    proto_block.encode_to_vec()
}

/// Sled → bincode → clue-stripped prost for `[start, end]`, one payload per height.
#[cfg(feature = "fhe-omr")]
#[allow(clippy::result_large_err)]
pub(super) fn load_pir_window_payloads(
    cache: &Cache,
    start: u32,
    end: u32,
) -> Result<Arc<Vec<Vec<u8>>>, Status> {
    let blocks = cache
        .get_compact_blocks_range(start, end)
        .map_err(cache_status)?;
    let expected = (end.saturating_sub(start)).saturating_add(1) as usize;
    if blocks.len() != expected {
        return Err(Status::aborted("chain discontinuity during PIR read"));
    }
    let mut prev: Option<CompactBlock> = None;
    let mut payloads = Vec::with_capacity(blocks.len());
    for block in blocks {
        if let Some(ref p) = prev {
            check_successor(p, &block)?;
        }
        payloads.push(encode_compact_block_for_pir(&block));
        prev = Some(block);
    }
    let encoded_total: usize = payloads.iter().map(|p| p.len()).sum();
    if encoded_total > MAX_PIR_WINDOW_ENCODED_BYTES {
        return Err(Status::resource_exhausted(format!(
            "PIR window encoded size {encoded_total} exceeds {MAX_PIR_WINDOW_ENCODED_BYTES}"
        )));
    }
    Ok(Arc::new(payloads))
}

pub(super) struct CachedTipFacts {
    pub(super) height: u32,
    pub(super) hash: [u8; 32],
    pub(super) block_target: Option<u32>,
    pub(super) difficulty: Option<String>,
    pub(super) retry_after: Option<Instant>,
}

#[derive(Clone, Copy)]
pub(super) enum TipFact {
    BlockTarget,
    Difficulty,
}

#[derive(Clone)]
pub(super) enum TipFactValue {
    BlockTarget(u32),
    Difficulty(String),
}

#[cfg(feature = "fhe-omr")]
pub(super) struct UploadReservation {
    pub(super) _bytes: tokio::sync::OwnedSemaphorePermit,
    pub(super) _slot: SlotGuard,
}

pub(super) fn upload_budget_permits(mib: usize) -> usize {
    mib.saturating_mul(1024 * 1024).max(1)
}

#[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
pub(super) struct SlotGuard {
    pub(super) peer: IpAddr,
    pub(super) slots: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let Ok(mut slots) = self.slots.lock() else {
            return;
        };
        if let Some(n) = slots.get_mut(&self.peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                slots.remove(&self.peer);
            }
        }
    }
}

pub(super) fn tip_fact_hit(
    facts: &Mutex<Option<CachedTipFacts>>,
    height: u32,
    hash: [u8; 32],
    fact: TipFact,
) -> Option<TipFactValue> {
    let guard = facts.lock().unwrap_or_else(|e| e.into_inner());
    let cached = guard.as_ref()?;
    if cached.height != height || cached.hash != hash {
        return None;
    }
    match fact {
        TipFact::BlockTarget => cached.block_target.map(TipFactValue::BlockTarget),
        TipFact::Difficulty => cached.difficulty.clone().map(TipFactValue::Difficulty),
    }
}

pub(super) fn store_tip_fact(
    facts: &Mutex<Option<CachedTipFacts>>,
    height: u32,
    hash: [u8; 32],
    value: TipFactValue,
) {
    let mut guard = facts.lock().unwrap_or_else(|e| e.into_inner());
    let same_tip = guard
        .as_ref()
        .is_some_and(|entry| entry.height == height && entry.hash == hash);
    if !same_tip {
        *guard = Some(CachedTipFacts {
            height,
            hash,
            block_target: None,
            difficulty: None,
            retry_after: None,
        });
    }
    let Some(entry) = guard.as_mut() else {
        return;
    };
    entry.retry_after = None;
    match value {
        TipFactValue::BlockTarget(target) => entry.block_target = Some(target),
        TipFactValue::Difficulty(difficulty) => entry.difficulty = Some(difficulty),
    }
}

fn note_tip_fact_failure(facts: &Mutex<Option<CachedTipFacts>>, height: u32, hash: [u8; 32]) {
    let mut guard = facts.lock().unwrap_or_else(|e| e.into_inner());
    let until = Some(Instant::now() + Duration::from_secs(5));
    if let Some(entry) = guard.as_mut() {
        if entry.height == height && entry.hash == hash {
            entry.retry_after = until;
            return;
        }
    }
    *guard = Some(CachedTipFacts {
        height,
        hash,
        block_target: None,
        difficulty: None,
        retry_after: until,
    });
}

fn tip_fact_in_backoff(facts: &Mutex<Option<CachedTipFacts>>, height: u32, hash: [u8; 32]) -> bool {
    let guard = facts.lock().unwrap_or_else(|e| e.into_inner());
    let Some(entry) = guard.as_ref() else {
        return false;
    };
    entry.height == height
        && entry.hash == hash
        && entry.retry_after.is_some_and(|t| Instant::now() < t)
}

pub(super) fn persisted_tip_fact(
    cache: &Cache,
    height: u32,
    hash: [u8; 32],
    fact: TipFact,
) -> Option<TipFactValue> {
    let (target, difficulty) = cache.tip_chain_facts_for(height, &hash).ok().flatten()?;
    Some(match fact {
        TipFact::BlockTarget => TipFactValue::BlockTarget(target),
        TipFact::Difficulty => TipFactValue::Difficulty(difficulty),
    })
}

pub(super) async fn load_tip_fact(
    facts: &Mutex<Option<CachedTipFacts>>,
    cache: &Cache,
    fetch: &tokio::sync::Mutex<()>,
    rpc: &DarkfidRpcClient,
    tip: (u32, [u8; 32]),
    fact: TipFact,
    wait: Duration,
) -> TipFactValue {
    let (height, hash) = tip;
    if let Some(hit) = tip_fact_hit(facts, height, hash, fact) {
        return hit;
    }
    if let Some(hit) = persisted_tip_fact(cache, height, hash, fact) {
        store_tip_fact(facts, height, hash, hit.clone());
        return hit;
    }
    if tip_fact_in_backoff(facts, height, hash) {
        return match fact {
            TipFact::BlockTarget => TipFactValue::BlockTarget(0),
            TipFact::Difficulty => TipFactValue::Difficulty(String::new()),
        };
    }
    // Bound lock contention across SubscribeBlocks / GetChainTip when darkfid stalls.
    let Ok(_guard) = tokio::time::timeout(wait.max(Duration::from_secs(1)), fetch.lock()).await
    else {
        return match fact {
            TipFact::BlockTarget => TipFactValue::BlockTarget(0),
            TipFact::Difficulty => TipFactValue::Difficulty(String::new()),
        };
    };
    if let Some(hit) = tip_fact_hit(facts, height, hash, fact) {
        return hit;
    }
    if let Some(hit) = persisted_tip_fact(cache, height, hash, fact) {
        store_tip_fact(facts, height, hash, hit.clone());
        return hit;
    }
    if tip_fact_in_backoff(facts, height, hash) {
        return match fact {
            TipFact::BlockTarget => TipFactValue::BlockTarget(0),
            TipFact::Difficulty => TipFactValue::Difficulty(String::new()),
        };
    }
    match fact {
        TipFact::BlockTarget => {
            let target = tokio::time::timeout(wait, rpc.get_block_target())
                .await
                .ok()
                .and_then(Result::ok);
            if let Some(target) = target {
                store_tip_fact(facts, height, hash, TipFactValue::BlockTarget(target));
                return TipFactValue::BlockTarget(target);
            }
            note_tip_fact_failure(facts, height, hash);
            TipFactValue::BlockTarget(0)
        }
        TipFact::Difficulty => {
            let difficulty = tokio::time::timeout(wait, rpc.get_difficulty(height))
                .await
                .ok()
                .and_then(Result::ok);
            if let Some(difficulty) = difficulty {
                store_tip_fact(
                    facts,
                    height,
                    hash,
                    TipFactValue::Difficulty(difficulty.clone()),
                );
                return TipFactValue::Difficulty(difficulty);
            }
            note_tip_fact_failure(facts, height, hash);
            TipFactValue::Difficulty(String::new())
        }
    }
}

pub(super) async fn block_target_from(
    facts: &Mutex<Option<CachedTipFacts>>,
    cache: &Cache,
    fetch: &tokio::sync::Mutex<()>,
    rpc: &DarkfidRpcClient,
    height: u32,
    hash: [u8; 32],
    wait: Duration,
) -> u32 {
    match load_tip_fact(
        facts,
        cache,
        fetch,
        rpc,
        (height, hash),
        TipFact::BlockTarget,
        wait,
    )
    .await
    {
        TipFactValue::BlockTarget(target) => target,
        TipFactValue::Difficulty(_) => 0,
    }
}
