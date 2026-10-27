/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! gRPC server implementation for the DarkFi Lightwallet Service.
//!
//! Implements the `DarkFiLightWallet` service defined in `lightwallet.proto`.
//! Each method reads from the local sled cache (populated by the block processor)
//! and streams/returns data to wallet clients.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};

use crate::detection_pool::{self, DetectionKeyPool, PoolReject, PooledDetectionKey};

use crate::{
    cache::Cache,
    compact_block::CompactBlock,
    continuity::{check_adjacent_pair, check_successor, discontinuity_status},
    proto::{self, dark_fi_light_wallet_server::DarkFiLightWallet},
    rate_limit::PeerRateLimiter,
    rpc_client::DarkfidRpcClient,
};

fn block_hash_vec(cache: &Cache, height: u32) -> Vec<u8> {
    cache
        .get_block_hash(height)
        .ok()
        .flatten()
        .map(|h| h.to_vec())
        .unwrap_or_default()
}

/// Retained snapshot row. `state_root` is blake3(tree_data): the compact cache
/// has no header money-tree root to check against.
fn persisted_tree_state(height: u32, tree_data: Vec<u8>, block_hash: Vec<u8>) -> proto::TreeState {
    let state_root = blake3::hash(&tree_data).as_bytes().to_vec();
    proto::TreeState {
        height,
        tree_data,
        block_hash,
        state_root,
        is_checkpoint: true,
    }
}

fn snapshot_miss_status(height: u32, tip: u32, lower: Option<u32>) -> Status {
    let detail = match lower {
        Some(snap) => format!("greatest snapshot <= {height} is {snap}"),
        None => format!("no snapshot at or below {height}"),
    };
    Status::failed_precondition(format!(
        "GetTreeState height {height} is not a retained snapshot (tip {tip}); {detail}"
    ))
}

/// blake3(height LE || tree_data || nullifier_index) — lockstep with mobile FFI.
fn snapshot_integrity_hash(height: u32, tree_data: &[u8], nullifier_index: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(tree_data);
    hasher.update(nullifier_index);
    *hasher.finalize().as_bytes()
}

/// Maximum number of blocks allowed in a single range request.
/// Prevents DoS via unbounded range requests that would load
/// the entire cache into memory.
const MAX_BLOCKS_PER_REQUEST: u32 = 10_000;
/// Max heights in a sparse GetCompactBlocksAtHeights request.
const MAX_SPARSE_HEIGHTS: usize = 512;
/// Max serialized detection key size before parse (S24 / DoS).
/// Param2 (D=4096, moduli 40×3, n=1024) det-keys measure ~120 MiB on the wire.
const MAX_DETECTION_KEY_BYTES: usize = 160 * 1024 * 1024;
/// Cap on sum of all detection_keys lengths in one request.
const MAX_DETECTION_KEYS_TOTAL_BYTES: usize = 160 * 1024 * 1024;
/// Concurrent FHE worker slots (GetUnifOmrDigest / FetchPirBatch).
const DEFAULT_FHE_PERMITS: usize = 2;
/// Max wait for the next DetectionKeyChunk while an FHE permit may be held.
#[cfg(feature = "fhe-omr")]
const DETECTION_KEY_CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Max SealPIR stripe query ciphertexts (window ≤ stripes × BFV degree).
const MAX_PIR_STRIPES: usize = 8;
/// Max bytes per SealPIR query ciphertext (rejects multi-MB garbage).
const MAX_PIR_QUERY_CT_BYTES: usize = 4 * 1024 * 1024;
/// Max protobuf-encoded compact-block bytes materialized for one PIR window.
const MAX_PIR_WINDOW_ENCODED_BYTES: usize = 64 * 1024 * 1024;
/// Max opaque recipient OMR metadata on SendTransaction.
const MAX_OMR_METADATA_ENC_BYTES: usize = 4096;
/// Compact-block wire version reported by GetLightInfo.
/// Bump when the compact format or RPC contract changes.
/// 2.0.0: historical snapshots, padded ranges, detection-key pool,
/// ChainTip subscribe, compact output bodies. No 1.0.0 compatibility path.
const LIGHTWALLET_PROTO_VERSION: &str = "2.0.0";

/// Default max raw tx bytes (overridden by Config.max_tx_bytes).
const DEFAULT_MAX_TX_BYTES: usize = 2_000_000;
/// Minimum span for GetNoteCommitments, GetNullifiers, and GetCompactOutputBodies.
/// Matches the client pad rule: span is a power of two of at least this size.
const MIN_PADDED_RANGE_SPAN: u32 = 1024;
/// A client pads against the tip it saw at the start of its sync cycle. A
/// bucket it cut short at that tip may end this many blocks below ours. Kept
/// well under one bucket so a raw cursor range is not mistaken for a cut bucket.
const MAX_PADDED_TIP_LAG: u32 = 64;
/// SubscribeBlocks keeps one unsent ChainTip. Further tips are skipped, not dropped.
const SUBSCRIBE_TIP_BUFFER: usize = 1;
/// Max characters in LookupZkas contract id (base58 + headroom).
const MAX_CONTRACT_ID_CHARS: usize = 128;

/// How long a SendTransaction peer binding remains valid for RegisterOmrClue (S12).
const SEND_PEER_BIND_TTL: Duration = Duration::from_secs(86_400);
/// Hard cap on `recent_send_peers` entries to prevent unbounded memory growth (M2).
const MAX_SEND_PEER_ENTRIES: usize = 100_000;

/// Inclusive height span as `u64` so `end = u32::MAX` cannot wrap the cap.
fn height_span(start: u32, end: u32) -> Result<u64, Status> {
    if start > end {
        return Err(Status::invalid_argument(format!(
            "Invalid height range: start={start} > end={end}"
        )));
    }
    Ok((end as u64) - (start as u64) + 1)
}

/// `end == 0` means "through the cached tip". Any other end is clamped to the tip.
fn resolve_block_range(
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
fn digest_evaluable_end(
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
    for h in start..=last {
        if cache.get_block_hash(h).map_err(cache_status)?.is_none() {
            return Ok((h.checked_sub(1).filter(|&p| p >= start), false));
        }
    }
    Ok((Some(last), tip >= end))
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

fn reject_oversized_window(start: u32, end: u32) -> Result<u64, Status> {
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
fn padded_range_rejection(start: u32, end: u32, tip: u32, max_range: u32) -> Option<String> {
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
    if (start as u64) % align != 0 {
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
fn require_padded_block_range(cache: &Cache, start: u32, end: u32) -> Result<(u32, u32), Status> {
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

fn cache_status(e: impl std::fmt::Display) -> Status {
    tracing::error!(target: "lightwalletd::server", "cache error: {e}");
    Status::internal("cache error")
}

fn backend_unavailable() -> Status {
    Status::unavailable("backend unavailable")
}

/// Stream compact blocks one sled read at a time; abort on holes, mixed forks,
/// or client disconnect (do not materialize the whole window).
fn spawn_compact_range<T, F>(
    cache: Arc<Cache>,
    start: u32,
    end: u32,
    map: F,
) -> tokio_stream::wrappers::ReceiverStream<Result<T, Status>>
where
    T: Send + 'static,
    F: Fn(&CompactBlock) -> T + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        let mut prev: Option<CompactBlock> = None;
        for height in start..=end {
            if tx.is_closed() {
                return;
            }
            let block = match cache.get_compact_block(height) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    let _ = tx.send(Err(discontinuity_status())).await;
                    return;
                }
                Err(e) => {
                    let _ = tx.send(Err(cache_status(e))).await;
                    return;
                }
            };
            if let Some(ref p) = prev {
                if let Err(st) = check_successor(p, &block) {
                    let _ = tx.send(Err(st)).await;
                    return;
                }
            } else if block.height != start {
                let _ = tx.send(Err(discontinuity_status())).await;
                return;
            }
            if tx.send(Ok(map(&block))).await.is_err() {
                return;
            }
            prev = Some(block);
            tokio::task::yield_now().await;
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

/// One [`proto::CompactOutputBody`] per Money output. Nullifiers are omitted.
fn spawn_output_bodies(
    cache: Arc<Cache>,
    start: u32,
    end: u32,
) -> tokio_stream::wrappers::ReceiverStream<Result<proto::CompactOutputBody, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        let mut prev: Option<CompactBlock> = None;
        for height in start..=end {
            if tx.is_closed() {
                return;
            }
            let block = match cache.get_compact_block(height) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    let _ = tx.send(Err(discontinuity_status())).await;
                    return;
                }
                Err(e) => {
                    let _ = tx.send(Err(cache_status(e))).await;
                    return;
                }
            };
            if let Some(ref p) = prev {
                if let Err(st) = check_successor(p, &block) {
                    let _ = tx.send(Err(st)).await;
                    return;
                }
            } else if block.height != start {
                let _ = tx.send(Err(discontinuity_status())).await;
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
                    };
                    if tx.send(Ok(body)).await.is_err() {
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

/// True if `ip` matches an allow-list entry (`1.2.3.4` or IPv4 CIDR).
fn ip_matches_proxy_entry(ip: IpAddr, entry: &str) -> bool {
    let entry = entry.trim();
    if let Ok(exact) = entry.parse::<IpAddr>() {
        return ip == exact;
    }
    let Some((base, bits)) = entry.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    match (ip, base.parse::<Ipv4Addr>()) {
        (IpAddr::V4(ip4), Ok(base4)) if bits <= 32 => {
            let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
            (u32::from(ip4) & mask) == (u32::from(base4) & mask)
        }
        _ => false,
    }
}

/// Client IP from `X-Forwarded-For` when the TCP peer is a trusted proxy.
///
/// Walk hops **right-to-left** and skip entries that match `trusted` (the
/// proxies themselves). nginx `$proxy_add_x_forwarded_for` *appends*, so the
/// leftmost hop is client-controlled and must not be used for rate limits.
fn client_ip_from_forwarded(header: &str, trusted: &[String]) -> Option<IpAddr> {
    for hop in header.split(',').rev() {
        let hop = hop.trim();
        if hop.is_empty() {
            continue;
        }
        let Ok(ip) = hop.parse::<IpAddr>() else {
            continue;
        };
        if trusted.iter().any(|e| ip_matches_proxy_entry(ip, e)) {
            continue;
        }
        return Some(ip);
    }
    None
}

/// In-memory clue/note list for one `(start, end)` window.
///
/// A second digest for the same window skips the sled compact-block scan.
/// Digest ciphertexts are not stored — they differ per handle and per range.
#[cfg(feature = "fhe-omr")]
struct ClueWindowEntry {
    end_hash: [u8; 32],
    notes: Vec<(u32, Vec<crate::omr_detector::NoteForDetection>)>,
}

#[cfg(feature = "fhe-omr")]
struct ClueWindowCache {
    map: HashMap<(u32, u32), ClueWindowEntry>,
    order: std::collections::VecDeque<(u32, u32)>,
}

#[cfg(feature = "fhe-omr")]
impl ClueWindowCache {
    const CAP: usize = 8;

    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn get(
        &self,
        start: u32,
        end: u32,
        end_hash: [u8; 32],
    ) -> Option<Vec<(u32, Vec<crate::omr_detector::NoteForDetection>)>> {
        let hit = self.map.get(&(start, end))?;
        if hit.end_hash != end_hash {
            return None;
        }
        Some(hit.notes.clone())
    }

    fn insert(
        &mut self,
        start: u32,
        end: u32,
        end_hash: [u8; 32],
        notes: Vec<(u32, Vec<crate::omr_detector::NoteForDetection>)>,
    ) {
        let key = (start, end);
        if self.map.contains_key(&key) {
            self.map.insert(key, ClueWindowEntry { end_hash, notes });
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
        self.map.insert(key, ClueWindowEntry { end_hash, notes });
    }
}

/// Server state shared across all gRPC handlers.
pub struct LightWalletService {
    /// Local compact block cache
    cache: Arc<Cache>,
    /// RPC client for proxying to darkfid
    rpc_client: Arc<DarkfidRpcClient>,
    /// Server version string
    version: String,
    /// Chain name
    chain_name: String,
    /// UnifOMR wire network byte (`0x00` mainnet / `0x01` testnet)
    network_byte: u8,
    /// Per-peer UnifOMR digest rate limiter (S6)
    omr_rate_limiter: Arc<PeerRateLimiter>,
    /// Per-peer FetchPirBatch limiter (higher than digest — one window is many limbs)
    pir_rate_limiter: Arc<PeerRateLimiter>,
    /// Per-peer RegisterOmrClue rate limiter (S12) — tighter than digest.
    clue_rate_limiter: Arc<PeerRateLimiter>,
    /// Per-peer GetBlockRange / SendTransaction rate limiter.
    rpc_rate_limiter: Arc<PeerRateLimiter>,
    /// Max raw transaction bytes after envelope strip.
    max_tx_bytes: usize,
    /// Recent SendTransaction peers keyed by tx hash (S12 peer bind).
    #[allow(clippy::type_complexity)]
    recent_send_peers: Arc<Mutex<HashMap<[u8; 32], (IpAddr, Instant)>>>,
    /// Tip height watch from the chain poller (wakes SubscribeBlocks).
    tip_notify: tokio::sync::watch::Receiver<u32>,
    /// Limits concurrent FHE `spawn_blocking` workers (CPU / RAM).
    fhe_permits: Arc<tokio::sync::Semaphore>,
    /// TCP peers from which `X-Forwarded-For` is trusted (empty = ignore the header).
    trusted_proxies: Vec<String>,
    max_detection_key_bytes: usize,
    max_detection_keys_total_bytes: usize,
    max_send_peer_entries: usize,
    /// In-memory detection keys. Not persisted. Handles are never logged.
    detection_pool: Arc<Mutex<DetectionKeyPool>>,
    /// Wakes tests observing SubscribeBlocks enqueue attempts.
    tip_notice: Arc<tokio::sync::Notify>,
    /// Flattened clue/note lists keyed by evaluated `(start, end)`. Not digests.
    #[cfg(feature = "fhe-omr")]
    clue_windows: Arc<Mutex<ClueWindowCache>>,
}

impl LightWalletService {
    pub fn new(
        cache: Arc<Cache>,
        rpc_client: Arc<DarkfidRpcClient>,
        chain_name: String,
        network_byte: u8,
        tip_notify: tokio::sync::watch::Receiver<u32>,
    ) -> Self {
        Self::with_limits(
            cache,
            rpc_client,
            chain_name,
            network_byte,
            30,
            120,
            DEFAULT_MAX_TX_BYTES,
            tip_notify,
            Vec::new(),
        )
    }

    /// Create a service with custom rate limits and tx size cap.
    pub fn with_limits(
        cache: Arc<Cache>,
        rpc_client: Arc<DarkfidRpcClient>,
        chain_name: String,
        network_byte: u8,
        omr_rate_limit_per_min: u32,
        rpc_rate_limit_per_min: u32,
        max_tx_bytes: usize,
        tip_notify: tokio::sync::watch::Receiver<u32>,
        trusted_proxies: Vec<String>,
    ) -> Self {
        Self {
            cache,
            rpc_client,
            version: format!(
                "{} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_HASH").unwrap_or("unknown")
            ),
            chain_name,
            network_byte,
            omr_rate_limiter: Arc::new(PeerRateLimiter::new(
                omr_rate_limit_per_min,
                Duration::from_secs(60),
            )),
            // PIR is one RPC per limb (2 payload bytes each, padded to a power
            // of two). The digest limiter (default 30/min) would fail every window.
            pir_rate_limiter: Arc::new(PeerRateLimiter::new(600, Duration::from_secs(60))),
            clue_rate_limiter: Arc::new(PeerRateLimiter::new(32, Duration::from_secs(60))),
            rpc_rate_limiter: Arc::new(PeerRateLimiter::new(
                rpc_rate_limit_per_min,
                Duration::from_secs(60),
            )),
            max_tx_bytes,
            recent_send_peers: Arc::new(Mutex::new(HashMap::new())),
            tip_notify,
            fhe_permits: Arc::new(tokio::sync::Semaphore::new(DEFAULT_FHE_PERMITS)),
            trusted_proxies,
            max_detection_key_bytes: MAX_DETECTION_KEY_BYTES,
            max_detection_keys_total_bytes: MAX_DETECTION_KEYS_TOTAL_BYTES,
            max_send_peer_entries: MAX_SEND_PEER_ENTRIES,
            detection_pool: Arc::new(Mutex::new(DetectionKeyPool::new())),
            tip_notice: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "fhe-omr")]
            clue_windows: Arc::new(Mutex::new(ClueWindowCache::new())),
        }
    }

    /// Override DoS caps from operator config (defaults stay conservative).
    pub fn apply_resource_caps(
        &mut self,
        max_detection_key_bytes: usize,
        max_send_peer_entries: usize,
        rate_limit_gc_threshold: usize,
    ) {
        self.max_detection_key_bytes = max_detection_key_bytes.max(1);
        self.max_detection_keys_total_bytes = max_detection_key_bytes.max(1);
        self.max_send_peer_entries = max_send_peer_entries.max(1);
        self.omr_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
        self.pir_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
        self.clue_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
        self.rpc_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
    }

    fn peer_ip<T>(&self, request: &Request<T>) -> IpAddr {
        let remote = request
            .remote_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        if self.trusted_proxies.is_empty() {
            return remote;
        }
        let trusted = self
            .trusted_proxies
            .iter()
            .any(|e| ip_matches_proxy_entry(remote, e));
        if !trusted {
            return remote;
        }
        request
            .metadata()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|h| client_ip_from_forwarded(h, &self.trusted_proxies))
            .unwrap_or(remote)
    }

    fn remember_send_peer(&self, tx_hash: [u8; 32], peer: IpAddr) {
        if let Ok(mut map) = self.recent_send_peers.lock() {
            let now = Instant::now();
            map.retain(|_, (_, t)| now.duration_since(*t) < SEND_PEER_BIND_TTL);
            // M2: hard-cap to prevent unbounded growth under sustained traffic.
            if map.len() >= self.max_send_peer_entries {
                // Evict oldest entries to make room.
                let mut entries: Vec<_> = map.iter().map(|(k, (_, t))| (*k, *t)).collect();
                entries.sort_by_key(|(_, t)| *t);
                let evict_count = map.len().saturating_sub(self.max_send_peer_entries) + 1;
                for (k, _) in entries.into_iter().take(evict_count) {
                    map.remove(&k);
                }
            }
            map.insert(tx_hash, (peer, now));
        }
    }

    fn send_peer_matches(&self, tx_hash: &[u8; 32], peer: IpAddr) -> bool {
        let Ok(mut map) = self.recent_send_peers.lock() else {
            return false;
        };
        let now = Instant::now();
        map.retain(|_, (_, t)| now.duration_since(*t) < SEND_PEER_BIND_TTL);
        match map.get(tx_hash) {
            Some((bound, _)) => *bound == peer,
            None => false,
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_omr_rate_limit(&self, peer: IpAddr, n: u32) -> Result<(), Status> {
        if self.omr_rate_limiter.check_n(peer, n.max(1)) {
            Ok(())
        } else {
            Err(Status::resource_exhausted(
                "OMR digest rate limit exceeded; retry later",
            ))
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_pir_rate_limit(&self, peer: IpAddr) -> Result<(), Status> {
        if self.pir_rate_limiter.check_n(peer, 1) {
            Ok(())
        } else {
            Err(Status::resource_exhausted(
                "PIR rate limit exceeded; retry later",
            ))
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_clue_rate_limit<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.clue_rate_limiter.check(self.peer_ip(request)) {
            Ok(())
        } else {
            Err(Status::resource_exhausted(
                "OMR clue registration rate limit exceeded; retry later",
            ))
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_rpc_rate_limit<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.rpc_rate_limiter.check(self.peer_ip(request)) {
            Ok(())
        } else {
            Err(Status::resource_exhausted(
                "RPC rate limit exceeded; retry later",
            ))
        }
    }

    /// Store a validated SendTransaction clue; `true` if this call stored it.
    ///
    /// S3: first-writer-wins — an existing hint is never overwritten.
    fn store_send_clue_hint(&self, hash: &[u8; 32], clue: Vec<u8>, output_index: u32) -> bool {
        if self
            .cache
            .omr_clue_index_taken(hash, output_index)
            .unwrap_or(false)
        {
            tracing::info!(
                target: "lightwalletd::server",
                "OMR clue already present for tx output {output_index}; first-writer-wins, not overwriting"
            );
            return false;
        }
        match self
            .cache
            .store_omr_clue_hint(hash, clue, Some(output_index))
        {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    target: "lightwalletd::server",
                    "Failed to store OMR clue hint: {e}"
                );
                false
            }
        }
    }

    /// Validate a sender-supplied UnifOMR clue (requires `fhe-omr`).
    fn validate_omr_clue(omr_clue: &[u8]) -> Result<(), String> {
        #[cfg(feature = "fhe-omr")]
        {
            crate::unifomr::validate_unifomr_clue(omr_clue)
        }
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = omr_clue;
            Err("UnifOMR clue validation requires the fhe-omr feature".into())
        }
    }

    fn pool_lock(&self) -> Result<std::sync::MutexGuard<'_, DetectionKeyPool>, Status> {
        self.detection_pool
            .lock()
            .map_err(|_| Status::internal("detection key pool unavailable"))
    }

    #[cfg(feature = "fhe-omr")]
    fn cached_encrypted_notes(
        &self,
        start: u32,
        end: u32,
    ) -> Result<Vec<(u32, Vec<crate::omr_detector::NoteForDetection>)>, Status> {
        let end_hash = self
            .cache
            .get_block_hash(end)
            .map_err(cache_status)?
            .unwrap_or([0u8; 32]);
        if let Ok(guard) = self.clue_windows.lock() {
            if let Some(hit) = guard.get(start, end, end_hash) {
                return Ok(hit);
            }
        }
        let notes = self
            .cache
            .get_encrypted_notes_range(start, end)
            .map_err(cache_status)?;
        if let Ok(mut guard) = self.clue_windows.lock() {
            guard.insert(start, end, end_hash, notes.clone());
        }
        Ok(notes)
    }

    /// Same digest evaluator `GetUnifOmrDigest` uses after the key is in hand.
    ///
    /// Does not cache the ciphertext. The clue/note list for `(start, eval_end)`
    /// may be reused across handles.
    #[cfg(feature = "fhe-omr")]
    async fn evaluate_detection_keys(
        &self,
        keys: Vec<Arc<Vec<u8>>>,
        start: u32,
        end: u32,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<proto::OmrDigestResponse, Status> {
        reject_oversized_window(start, end)?;
        let (eval_end, range_complete) = digest_evaluable_end(&self.cache, start, end)?;
        let block_notes = match eval_end {
            Some(eval_end) => self.cached_encrypted_notes(start, eval_end)?,
            None => Vec::new(),
        };
        let network_byte = self.network_byte;
        let (encrypted_digest, slot_heights_wire, truncated) =
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let detector = crate::unifomr::UnifOmrDetector::new(network_byte);
                let clue_notes = crate::unifomr::block_notes_from_detection(&block_notes);
                let (mut messages, mut slot_heights) =
                    crate::unifomr::flatten_messages(&clue_notes);
                let truncated =
                    crate::unifomr::cap_messages_to_whole_heights(&mut messages, &mut slot_heights);
                let slot_heights_wire = crate::unifomr::pack_slot_heights(&slot_heights);
                let digest = if keys.len() == 1 {
                    crate::unifomr::encode_messages_padded(&detector, &keys[0], &messages)
                        .map_err(|e| e.to_string())?
                } else {
                    let mut out = Vec::new();
                    for key in &keys {
                        let d = crate::unifomr::encode_messages_padded(&detector, key, &messages)
                            .map_err(|e| e.to_string())?;
                        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
                        out.extend_from_slice(&d);
                    }
                    out
                };
                Ok::<(Vec<u8>, Vec<u8>, bool), String>((digest, slot_heights_wire, truncated))
            })
            .await
            .map_err(|e| Status::internal(format!("UnifOMR worker join error: {e}")))?
            .map_err(|e| Status::invalid_argument(format!("UnifOMR detection error: {e}")))?;

        Ok(proto::OmrDigestResponse {
            encrypted_digest,
            complete: range_complete && !truncated,
            slot_heights: slot_heights_wire,
        })
    }

    /// Read a detection-key upload. `enforce_range` is false for registration,
    /// which ignores start/end; the digest window is `PoolDigestRequest`.
    #[cfg(feature = "fhe-omr")]
    async fn read_detection_key_upload(
        &self,
        mut stream: tonic::Streaming<proto::DetectionKeyChunk>,
        peer: IpAddr,
        enforce_range: bool,
    ) -> Result<DetectionKeyUpload, Status> {
        use tokio_stream::StreamExt;

        let mut start = 0;
        let mut end = 0;
        let mut num_keys = 0;
        let mut header_received = false;
        let mut fhe_permit = None;
        let mut current_key = Vec::new();
        let mut keys = Vec::new();

        loop {
            let next = tokio::time::timeout(DETECTION_KEY_CHUNK_IDLE_TIMEOUT, stream.next())
                .await
                .map_err(|_| Status::deadline_exceeded("UnifOMR detection-key upload stalled"))?;
            let Some(chunk_res) = next else { break };
            let chunk = chunk_res?;

            if !header_received {
                start = chunk.start_height;
                end = chunk.end_height;
                num_keys = chunk.num_keys;
                header_received = true;

                if num_keys == 0 {
                    return Err(Status::invalid_argument("num_keys must be > 0"));
                }
                if num_keys > 16 {
                    return Err(Status::invalid_argument(
                        "Too many UnifOMR detection_keys (max 16)",
                    ));
                }
                if enforce_range {
                    reject_oversized_window(start, end)?;
                }
                self.check_omr_rate_limit(peer, num_keys)?;
                fhe_permit = Some(
                    Arc::clone(&self.fhe_permits)
                        .acquire_owned()
                        .await
                        .map_err(|_| Status::resource_exhausted("FHE workers unavailable"))?,
                );
            }

            current_key.extend_from_slice(&chunk.data);

            if current_key.len() > self.max_detection_key_bytes {
                return Err(Status::invalid_argument(format!(
                    "UnifOMR detection key[{}] too large: {} bytes",
                    keys.len(),
                    current_key.len()
                )));
            }

            if chunk.key_done {
                keys.push(std::mem::take(&mut current_key));
            }

            let total_key_bytes: usize =
                keys.iter().map(|k| k.len()).sum::<usize>() + current_key.len();
            if total_key_bytes > self.max_detection_keys_total_bytes {
                return Err(Status::invalid_argument(format!(
                    "UnifOMR detection_keys total size too large: {total_key_bytes} bytes \
                     (max {})",
                    self.max_detection_keys_total_bytes
                )));
            }
        }

        if !header_received {
            return Err(Status::invalid_argument("Empty stream"));
        }
        if !current_key.is_empty() {
            return Err(Status::invalid_argument(
                "Stream ended before key_done = true for the last key",
            ));
        }
        if keys.len() != num_keys as usize {
            return Err(Status::invalid_argument(format!(
                "Expected {} keys, but received {}",
                num_keys,
                keys.len()
            )));
        }
        if keys.iter().any(|k| k.is_empty()) {
            return Err(Status::invalid_argument("empty detection key not allowed"));
        }
        if let Some(max_len) = keys.iter().map(|k| k.len()).max() {
            if keys.len().saturating_mul(max_len) > self.max_detection_keys_total_bytes {
                return Err(Status::invalid_argument(
                    "UnifOMR detection_keys count×size exceeds total size budget",
                ));
            }
        }

        let permit = fhe_permit.ok_or_else(|| Status::invalid_argument("Empty stream"))?;
        Ok(DetectionKeyUpload {
            start,
            end,
            keys,
            permit,
        })
    }
}

#[cfg(feature = "fhe-omr")]
struct DetectionKeyUpload {
    start: u32,
    end: u32,
    keys: Vec<Vec<u8>>,
    permit: tokio::sync::OwnedSemaphorePermit,
}

#[tonic::async_trait]
impl DarkFiLightWallet for LightWalletService {
    type GetBlockRangeStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactBlock, Status>>;

    type GetCompactOutputBodiesStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactOutputBody, Status>>;

    /// Stream one compact output body per Money output in a padded range.
    async fn get_compact_output_bodies(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetCompactOutputBodiesStream>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;
        Ok(Response::new(spawn_output_bodies(
            Arc::clone(&self.cache),
            start,
            end,
        )))
    }

    /// Stream compact blocks in a height range.
    async fn get_block_range(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) = resolve_block_range(&self.cache, range.start_height, range.end_height)?;

        Ok(Response::new(spawn_compact_range(
            Arc::clone(&self.cache),
            start,
            end,
            CompactBlock::to_proto,
        )))
    }

    /// Get a single compact block by height.
    async fn get_block(
        &self,
        request: Request<proto::BlockHeight>,
    ) -> Result<Response<proto::CompactBlock>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let height = request.into_inner().height;

        match self.cache.get_compact_block(height) {
            Ok(Some(block)) => Ok(Response::new(block.to_proto())),
            Ok(None) => Err(Status::not_found(format!(
                "Block not found at height {height}"
            ))),
            Err(e) => Err(cache_status(e)),
        }
    }

    type GetCompactBlocksAtHeightsStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactBlock, Status>>;

    /// Stream compact blocks at specific heights (sparse fetch).
    ///
    /// Rejects empty lists and lists over [`MAX_SPARSE_HEIGHTS`]. Server
    /// sorts/dedups. Returns NOT_FOUND if any requested height is missing
    /// so tip advance stays correct.
    async fn get_compact_blocks_at_heights(
        &self,
        request: Request<proto::HeightList>,
    ) -> Result<Response<Self::GetCompactBlocksAtHeightsStream>, Status> {
        let mut heights = request.into_inner().heights;
        if heights.is_empty() {
            return Err(Status::invalid_argument(
                "HeightList.heights must not be empty",
            ));
        }
        if heights.len() > MAX_SPARSE_HEIGHTS {
            return Err(Status::invalid_argument(format!(
                "Too many heights: {} requested, max is {MAX_SPARSE_HEIGHTS}",
                heights.len()
            )));
        }

        heights.sort_unstable();
        heights.dedup();

        // M6: Single-pass — collect all blocks first (fail early on missing),
        // then stream the pre-fetched results. Avoids double sled I/O.
        let mut blocks = Vec::with_capacity(heights.len());
        for &h in &heights {
            match self.cache.get_compact_block(h) {
                Ok(Some(block)) => blocks.push(block),
                Ok(None) => {
                    return Err(Status::not_found(format!("Block not found at height {h}")));
                }
                Err(e) => return Err(cache_status(e)),
            }
        }

        for w in blocks.windows(2) {
            check_adjacent_pair(&w[0], &w[1])?;
        }

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            for block in blocks {
                if tx.is_closed() {
                    return;
                }
                if tx.send(Ok(block.to_proto())).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Get the current chain tip.
    async fn get_chain_tip(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<proto::ChainTip>, Status> {
        match self.cache.get_tip() {
            Ok(Some((height, hash))) => {
                let block = self.cache.get_compact_block(height).map_err(cache_status)?;
                let timestamp = block.as_ref().map(|b| b.timestamp).unwrap_or(0);
                let prev_hash = block.map(|b| b.prev_hash.to_vec()).unwrap_or_default();

                let block_target = tokio::time::timeout(
                    Duration::from_secs(2),
                    self.rpc_client.get_block_target(),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);

                Ok(Response::new(proto::ChainTip {
                    height,
                    hash: hash.to_vec(),
                    timestamp,
                    block_target,
                    prev_hash,
                }))
            }
            Ok(None) => Err(Status::unavailable("No blocks cached yet")),
            Err(e) => Err(cache_status(e)),
        }
    }

    type SubscribeBlocksStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::ChainTip, Status>>;

    /// Stream [`proto::ChainTip`] when the poller watch fires.
    ///
    /// A slow client is not disconnected. If the one-slot buffer is full the
    /// notice is skipped; the next tip the client reads covers the gap.
    async fn subscribe_blocks(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<Self::SubscribeBlocksStream>, Status> {
        let cache = Arc::clone(&self.cache);
        let rpc = Arc::clone(&self.rpc_client);
        let mut tip_rx = self.tip_notify.clone();
        let notice = Arc::clone(&self.tip_notice);
        let (tx, rx) = tokio::sync::mpsc::channel(SUBSCRIBE_TIP_BUFFER);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = tx.closed() => return,
                    changed = tip_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                // Wakeup only. The payload is the cache tip, so a rewind is visible.
                let _watched = *tip_rx.borrow_and_update();

                let Some((height, hash)) = cache.get_tip().unwrap_or(None) else {
                    notice.notify_one();
                    continue;
                };
                let block = match cache.get_compact_block(height) {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        tracing::warn!(
                            target: "lightwalletd::server",
                            "SubscribeBlocks tip has no compact block"
                        );
                        notice.notify_one();
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(
                            target: "lightwalletd::server",
                            "SubscribeBlocks cache error: {e}"
                        );
                        notice.notify_one();
                        continue;
                    }
                };
                let block_target =
                    tokio::time::timeout(Duration::from_millis(200), rpc.get_block_target())
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or(0);
                let chain_tip = proto::ChainTip {
                    height,
                    hash: hash.to_vec(),
                    timestamp: block.timestamp,
                    block_target,
                    prev_hash: block.prev_hash.to_vec(),
                };
                match tx.try_send(Ok(chain_tip)) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        tracing::debug!(
                            target: "lightwalletd::server",
                            "SubscribeBlocks client is behind; skipping this tip notice"
                        );
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
                notice.notify_one();
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Get a full transaction by hash.
    async fn get_transaction(
        &self,
        request: Request<proto::TxHash>,
    ) -> Result<Response<proto::RawTransaction>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let hash = request.into_inner().hash;
        if hash.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "transaction hash must be 32 bytes, got {}",
                hash.len()
            )));
        }
        let hash_hex = hex::encode(&hash);

        match self.rpc_client.get_tx(&hash_hex).await {
            Ok(tx_bytes) => Ok(Response::new(proto::RawTransaction {
                data: tx_bytes,
                omr_clue: vec![],
                omr_clue_output_index: 0,
                omr_metadata_enc: vec![],
                extra_omr_clues: vec![],
            })),
            Err(e) if e.is_connection() => Err(backend_unavailable()),
            Err(_) => Err(Status::not_found("transaction not found")),
        }
    }

    /// Submit a signed transaction.
    ///
    /// SECURITY: Error messages are sanitized to prevent leaking darkfid
    /// internal state (RPC errors, stack traces, contract names) to the
    /// wallet client.
    async fn send_transaction(
        &self,
        request: Request<proto::RawTransaction>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let peer = self.peer_ip(&request);
        let req = request.into_inner();
        let mut tx_data = req.data;
        let mut omr_clue = req.omr_clue;

        if tx_data.starts_with(crate::omr_envelope::OMR_ENVELOPE_TAG) {
            let env = crate::omr_envelope::parse_envelope(&tx_data).ok_or_else(|| {
                Status::invalid_argument("malformed OMR envelope on SendTransaction")
            })?;
            if omr_clue.is_empty() && !env.fhe_clue.is_empty() {
                omr_clue = env.fhe_clue.to_vec();
            }
            tx_data = env.raw_tx.to_vec();
        }

        if tx_data.len() > self.max_tx_bytes {
            return Err(Status::invalid_argument(format!(
                "transaction size {} exceeds limit {}",
                tx_data.len(),
                self.max_tx_bytes
            )));
        }

        // Pre-compute tx hash so we can index the OMR clue before the block lands.
        let tx_hash_for_clue = darkfi_serial::deserialize::<darkfi::tx::Transaction>(&tx_data)
            .ok()
            .map(|tx| *tx.hash().inner());

        // S22: surface whether the attached clue was accepted (tx may still succeed).
        let mut clue_accepted = false;
        if !omr_clue.is_empty() {
            // S12: validate on SendTransaction the same as RegisterOmrClue.
            if let Err(e) = Self::validate_omr_clue(&omr_clue) {
                tracing::warn!(
                    target: "lightwalletd::server",
                    "Rejecting OMR clue on SendTransaction: {e}"
                );
                omr_clue.clear();
            } else if let Some(hash) = tx_hash_for_clue {
                // Stored before broadcast: the tx can be mined (and the block
                // indexed) before broadcast_tx returns.
                clue_accepted = self.store_send_clue_hint(
                    &hash,
                    std::mem::take(&mut omr_clue),
                    req.omr_clue_output_index,
                );
                for extra in &req.extra_omr_clues {
                    if extra.omr_clue.is_empty() {
                        continue;
                    }
                    if let Err(e) = Self::validate_omr_clue(&extra.omr_clue) {
                        tracing::warn!(
                            target: "lightwalletd::server",
                            "Rejecting extra OMR clue on SendTransaction: {e}"
                        );
                        continue;
                    }
                    let _ = self.store_send_clue_hint(
                        &hash,
                        extra.omr_clue.clone(),
                        extra.output_index,
                    );
                }
            }
        }

        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.rpc_client.broadcast_tx(&tx_data),
        )
        .await
        {
            Ok(Ok(tx_hash)) => {
                let tx_hash_bytes = hex::decode(&tx_hash).unwrap_or_else(|_| {
                    tracing::warn!(
                        target: "lightwalletd::server",
                        "Darkfid returned non-hex tx_hash: redacted (len={})",
                        tx_hash.len()
                    );
                    Vec::new()
                });

                let hash = tx_hash_for_clue.or_else(|| {
                    if tx_hash_bytes.len() == 32 {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&tx_hash_bytes);
                        Some(h)
                    } else {
                        None
                    }
                });

                // S12: remember which peer submitted this tx so RegisterOmrClue
                // can be bound to the same peer when clue arrives out-of-band.
                if let Some(hash) = hash {
                    self.remember_send_peer(hash, peer);
                }

                // Validated clue whose hash only darkfid could tell us.
                if let Some(hash) = hash {
                    if !omr_clue.is_empty() {
                        clue_accepted =
                            self.store_send_clue_hint(&hash, omr_clue, req.omr_clue_output_index);
                    }
                    for extra in &req.extra_omr_clues {
                        if extra.omr_clue.is_empty() {
                            continue;
                        }
                        if Self::validate_omr_clue(&extra.omr_clue).is_err() {
                            continue;
                        }
                        let _ = self.store_send_clue_hint(
                            &hash,
                            extra.omr_clue.clone(),
                            extra.output_index,
                        );
                    }
                }

                // Store recipient-encrypted OMR metadata (opaque to LWD).
                if !req.omr_metadata_enc.is_empty() {
                    if req.omr_metadata_enc.len() > MAX_OMR_METADATA_ENC_BYTES {
                        tracing::warn!(
                            target: "lightwalletd::server",
                            "Rejecting omr_metadata_enc: {} bytes (max {MAX_OMR_METADATA_ENC_BYTES})",
                            req.omr_metadata_enc.len()
                        );
                    } else if let Some(hash) = hash {
                        if self.cache.has_omr_metadata_enc(&hash).unwrap_or(false) {
                            tracing::info!(
                                target: "lightwalletd::server",
                                "OMR metadata_enc already present for tx; first-writer-wins, not overwriting"
                            );
                        } else if let Err(e) = self.cache.store_omr_metadata_enc(
                            &hash,
                            req.omr_metadata_enc,
                            Some(req.omr_clue_output_index),
                        ) {
                            tracing::warn!(
                                target: "lightwalletd::server",
                                "Failed to store OMR metadata_enc: {e}"
                            );
                        }
                    }
                }

                Ok(Response::new(proto::SendResponse {
                    tx_hash: tx_hash_bytes,
                    error: String::new(),
                    clue_accepted,
                }))
            }
            Ok(Err(e)) => {
                tracing::error!(
                    target: "lightwalletd::server",
                    "Transaction broadcast failed: {e}"
                );
                // Rejected txs must not park clue hints for the full TTL.
                if clue_accepted {
                    if let Some(hash) = tx_hash_for_clue {
                        if let Err(e) = self.cache.remove_omr_clue_hint(&hash) {
                            tracing::warn!(
                                target: "lightwalletd::server",
                                "Failed to drop OMR clue hint for rejected tx: {e}"
                            );
                        }
                    }
                }
                Ok(Response::new(proto::SendResponse {
                    tx_hash: Vec::new(),
                    error: "Transaction broadcast failed".to_string(),
                    clue_accepted: false,
                }))
            }
            Err(_elapsed) => {
                tracing::error!(
                    target: "lightwalletd::server",
                    "Transaction broadcast timed out after 10 seconds"
                );
                Err(Status::deadline_exceeded(
                    "Transaction broadcast timeout after 10s",
                ))
            }
        }
    }

    type GetNoteCommitmentsStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::NoteCommitmentUpdate, Status>>;

    /// Get note commitments for a block range.
    async fn get_note_commitments(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetNoteCommitmentsStream>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;

        Ok(Response::new(spawn_compact_range(
            Arc::clone(&self.cache),
            start,
            end,
            |block| proto::NoteCommitmentUpdate {
                height: block.height,
                coins: block
                    .txs
                    .iter()
                    .flat_map(|tx| tx.outputs.iter().map(|o| o.coin.to_vec()))
                    .collect(),
            },
        )))
    }

    type GetNullifiersStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::NullifierUpdate, Status>>;

    /// Get nullifiers for a block range.
    async fn get_nullifiers(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetNullifiersStream>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;

        Ok(Response::new(spawn_compact_range(
            Arc::clone(&self.cache),
            start,
            end,
            |block| proto::NullifierUpdate {
                height: block.height,
                nullifiers: block
                    .txs
                    .iter()
                    .flat_map(|tx| tx.nullifiers.iter().map(|n| n.to_vec()))
                    .collect(),
            },
        )))
    }

    /// Merkle tree at the tip or a retained snapshot.
    ///
    /// Other heights are `FAILED_PRECONDITION`. The status text includes the
    /// greatest stored snapshot `<=` the request.
    async fn get_tree_state(
        &self,
        request: Request<proto::BlockHeight>,
    ) -> Result<Response<proto::TreeState>, Status> {
        let height = request.into_inner().height;
        let tip = self
            .cache
            .get_tip()
            .map_err(cache_status)?
            .map(|(h, _)| h)
            .unwrap_or(0);

        if height == tip {
            return match self.cache.get_tip_tree_state().map_err(cache_status)? {
                Some((tree_height, tree_data)) if tree_height == tip => {
                    let block_hash = block_hash_vec(&self.cache, tree_height);
                    Ok(Response::new(persisted_tree_state(
                        tree_height,
                        tree_data,
                        block_hash,
                    )))
                }
                Some((tree_height, _)) => Err(Status::failed_precondition(format!(
                    "Tip Merkle tree height {tree_height} does not match tip {tip}; resync required"
                ))),
                None => {
                    if tip == 0 {
                        // Nothing indexed yet: not a retained snapshot row.
                        let tree = darkfi_sdk::crypto::MerkleTree::new(100);
                        let tree_data = darkfi_serial::serialize(&tree);
                        let state_root = blake3::hash(&tree_data).as_bytes().to_vec();
                        Ok(Response::new(proto::TreeState {
                            height: 0,
                            tree_data,
                            block_hash: vec![],
                            state_root,
                            is_checkpoint: false,
                        }))
                    } else {
                        Err(Status::not_found(
                            "Tip Merkle tree not available yet; wait for chain poller to index blocks",
                        ))
                    }
                }
            };
        }

        if let Some(tree_data) = self.cache.merkle_snapshot(height).map_err(cache_status)? {
            let block_hash = block_hash_vec(&self.cache, height);
            return Ok(Response::new(persisted_tree_state(
                height, tree_data, block_hash,
            )));
        }

        let lower = self
            .cache
            .greatest_snapshot_at_or_below(height)
            .map_err(cache_status)?
            .map(|(h, _)| h);
        Err(snapshot_miss_status(height, tip, lower))
    }

    type GetCheckpointSnapshotStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CheckpointSnapshot, Status>>;

    /// Stream a retained snapshot in 1 MiB `tree_data` chunks.
    ///
    /// `preferred_height == 0` is the latest snapshot. Otherwise the greatest
    /// snapshot at or below that height. `NOT_FOUND` when none exist.
    async fn get_checkpoint_snapshot(
        &self,
        request: Request<proto::CheckpointRequest>,
    ) -> Result<Response<Self::GetCheckpointSnapshotStream>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let preferred = request.into_inner().preferred_height;
        let found = if preferred == 0 {
            self.cache.latest_snapshot().map_err(cache_status)?
        } else {
            self.cache
                .greatest_snapshot_at_or_below(preferred)
                .map_err(cache_status)?
        };
        let Some((tree_height, tree_data)) = found else {
            return Err(Status::not_found(
                "no checkpoint snapshot at or below the requested height",
            ));
        };

        let block_hash = block_hash_vec(&self.cache, tree_height);
        // CompactBlock does not store the header money-tree root. state_root
        // stays blake3(tree_data); see the snapshot unit test.
        let state_root = blake3::hash(&tree_data).as_bytes().to_vec();
        let snapshot_hash = snapshot_integrity_hash(tree_height, &tree_data, &[]).to_vec();
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            const CHUNK_SIZE: usize = 1024 * 1024;
            let total_chunks = if tree_data.is_empty() {
                1
            } else {
                (tree_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE
            };

            for i in 0..total_chunks {
                let start = i * CHUNK_SIZE;
                let end = std::cmp::min(start + CHUNK_SIZE, tree_data.len());
                let chunk_data = if tree_data.is_empty() {
                    vec![]
                } else {
                    tree_data[start..end].to_vec()
                };
                let snapshot = proto::CheckpointSnapshot {
                    height: tree_height,
                    block_hash: block_hash.clone(),
                    state_root: state_root.clone(),
                    tree_data: chunk_data,
                    nullifier_index: vec![],
                    scan_cursor: tree_height,
                    snapshot_hash: snapshot_hash.clone(),
                };
                if tx.send(Ok(snapshot)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Lookup zkas bincodes for a contract.
    async fn lookup_zkas(
        &self,
        request: Request<proto::ContractId>,
    ) -> Result<Response<proto::ZkasResponse>, Status> {
        self.check_rpc_rate_limit(&request)?;
        let contract_id = request.into_inner().id;
        if contract_id.is_empty() || contract_id.len() > MAX_CONTRACT_ID_CHARS {
            return Err(Status::invalid_argument("invalid contract id"));
        }

        match self.rpc_client.lookup_zkas(&contract_id).await {
            Ok(bincodes) => {
                let proto_bincodes: Vec<proto::ZkasBincode> = bincodes
                    .into_iter()
                    .map(|(ns, bc)| proto::ZkasBincode {
                        namespace: ns,
                        bincode: bc,
                    })
                    .collect();
                Ok(Response::new(proto::ZkasResponse {
                    bincodes: proto_bincodes,
                }))
            }
            Err(e) if e.is_connection() => Err(backend_unavailable()),
            Err(_) => Err(Status::not_found("contract not found")),
        }
    }

    /// Get server metadata.
    async fn get_light_info(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<proto::LightInfo>, Status> {
        let (height, hash) = self
            .cache
            .get_tip()
            .map_err(cache_status)?
            .unwrap_or((0, [0u8; 32]));

        // darkfid RPC can stall during heavy sync; never block LightInfo forever.
        let block_target =
            tokio::time::timeout(Duration::from_secs(2), self.rpc_client.get_block_target())
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
        let difficulty =
            tokio::time::timeout(Duration::from_secs(2), self.rpc_client.get_difficulty())
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();

        Ok(Response::new(proto::LightInfo {
            version: self.version.clone(),
            chain_name: self.chain_name.clone(),
            block_height: height,
            block_target,
            difficulty,
            omr_supported: cfg!(feature = "fhe-omr"),
            best_block_hash: hash.to_vec(),
            backend_version: format!(
                "lightwalletd {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_HASH").unwrap_or("unknown")
            ),
            directory_attest_pubkey: self
                .cache
                .directory_attest_public_key()
                .map_err(cache_status)?
                .to_vec(),
            proto_version: LIGHTWALLET_PROTO_VERSION.to_string(),
        }))
    }

    /// Get OMR capabilities.
    ///
    /// Reports whether UnifOMR is enabled and its configuration.
    /// Clients use this to decide whether to attempt OMR or fall back
    /// to trial decryption immediately.
    async fn get_omr_capabilities(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<proto::OmrCapabilities>, Status> {
        #[cfg(feature = "fhe-omr")]
        {
            Ok(Response::new(proto::OmrCapabilities {
                enabled: true,
                scheme: "unifomr".to_string(),
                // Honest MVP: paper FP rates are not claimed (see unifomr_mvp_limits.md).
                false_positive_rate: 0.0,
                max_range_per_request: 10_000,
            }))
        }
        #[cfg(not(feature = "fhe-omr"))]
        {
            Ok(Response::new(proto::OmrCapabilities {
                enabled: false,
                scheme: String::new(),
                false_positive_rate: 0.0,
                max_range_per_request: 0,
            }))
        }
    }

    /// Register a sender-supplied UnifOMR clue for a pending transaction.
    ///
    /// Transitional until consensus-native `CompactOutput.omr_clue`. Validates
    /// clue size/structure via `validate_unifomr_clue` before storing (S12). When
    /// the tx was previously submitted via SendTransaction, Register must come
    /// from the same peer within the bind TTL.
    async fn register_omr_clue(
        &self,
        request: Request<proto::OmrClueRegistration>,
    ) -> Result<Response<proto::Empty>, Status> {
        // Prefer clue-on-SendTransaction; standalone Register is transitional and rate-limited.
        self.check_clue_rate_limit(&request)?;
        let peer = self.peer_ip(&request);

        let req = request.into_inner();
        if req.tx_hash.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "tx_hash must be 32 bytes, got {}",
                req.tx_hash.len()
            )));
        }
        if req.omr_clue.is_empty() {
            return Err(Status::invalid_argument("omr_clue cannot be empty"));
        }

        // Reject poison / oversized clues before they enter the sled hint cache (S12).
        if let Err(e) = Self::validate_omr_clue(&req.omr_clue) {
            return Err(Status::invalid_argument(format!("omr_clue rejected: {e}")));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&req.tx_hash);

        // S12: RegisterOmrClue must follow SendTransaction from the same peer.
        // Unbound Register (no prior Send binding) is rejected — prefer attaching
        // the clue on SendTransaction. Mobile darkfid-broadcast fallback will
        // warn if Register fails; SendTransaction remains the primary path.
        if !self.send_peer_matches(&hash, peer) {
            return Err(Status::failed_precondition(
                "RegisterOmrClue requires a prior SendTransaction from this peer; \
                 attach omr_clue on SendTransaction instead",
            ));
        }

        if self
            .cache
            .omr_clue_index_taken(&hash, req.omr_clue_output_index)
            .unwrap_or(false)
        {
            // S3: first-writer-wins per output index — do not overwrite.
            tracing::info!(
                target: "lightwalletd::server",
                "OMR clue already present for RegisterOmrClue output {}; first-writer-wins",
                req.omr_clue_output_index
            );
            return Ok(Response::new(proto::Empty {}));
        }

        self.cache
            .store_omr_clue_hint(&hash, req.omr_clue, Some(req.omr_clue_output_index))
            .map_err(|e| Status::internal(format!("Failed to store OMR clue: {e}")))?;

        Ok(Response::new(proto::Empty {}))
    }

    async fn get_unif_omr_digest(
        &self,
        request: Request<tonic::Streaming<proto::DetectionKeyChunk>>,
    ) -> Result<Response<proto::OmrDigestResponse>, Status> {
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "UnifOMR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let peer = self.peer_ip(&request);
            let upload = self
                .read_detection_key_upload(request.into_inner(), peer, true)
                .await?;
            let keys = upload.keys.into_iter().map(Arc::new).collect();
            let response = self
                .evaluate_detection_keys(keys, upload.start, upload.end, upload.permit)
                .await?;
            return Ok(Response::new(response));
        }
    }

    async fn register_detection_key(
        &self,
        request: Request<tonic::Streaming<proto::DetectionKeyChunk>>,
    ) -> Result<Response<proto::DetectionKeyHandle>, Status> {
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "UnifOMR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let peer = self.peer_ip(&request);
            let upload = self
                .read_detection_key_upload(request.into_inner(), peer, false)
                .await?;
            let network_byte = self.network_byte;
            let max_key_bytes = self.max_detection_key_bytes;
            let permit = upload.permit;
            let keys = upload.keys;
            // Parse off the runtime. Ciphertexts are dropped; the wire bytes go
            // back through encode_messages_padded on digest so there is one
            // partial-decrypt path. Do not log the key.
            let (keys, byte_length) = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let detector = crate::unifomr::UnifOmrDetector::new(network_byte);
                let mut byte_length = 0usize;
                for key in &keys {
                    let (net, _parsed) =
                        crate::unifomr::parse_detection_key(key, &detector.params)?;
                    if net != network_byte {
                        return Err("detection key network does not match this server".to_string());
                    }
                    byte_length += key.len();
                }
                Ok::<_, String>((keys, byte_length))
            })
            .await
            .map_err(|e| Status::internal(format!("UnifOMR worker join error: {e}")))?
            .map_err(|e| Status::invalid_argument(format!("detection key: {e}")))?;

            let now = detection_pool::unix_now();
            let expires_unix = detection_pool::expiry_from(now);
            let pooled = PooledDetectionKey {
                keys: keys.into_iter().map(Arc::new).collect(),
                network_byte,
                expires_unix,
                byte_length,
            };
            let handle = self
                .pool_lock()?
                .insert(pooled, max_key_bytes, now)
                .map_err(|e| match e {
                    PoolReject::Full => Status::resource_exhausted("detection key pool is full"),
                    PoolReject::TooLarge => {
                        Status::invalid_argument("detection key exceeds the size cap")
                    }
                    PoolReject::Empty => Status::invalid_argument("empty detection key"),
                })?;
            Ok(Response::new(proto::DetectionKeyHandle {
                handle: handle.to_vec(),
                expires_unix,
            }))
        }
    }

    async fn get_unif_omr_digest_from_pool(
        &self,
        request: Request<proto::PoolDigestRequest>,
    ) -> Result<Response<proto::OmrDigestResponse>, Status> {
        let peer = self.peer_ip(&request);
        let req = request.into_inner();
        if req.handle.len() != 32 {
            return Err(Status::invalid_argument(
                "detection key handle must be 32 bytes",
            ));
        }
        let mut handle = [0u8; 32];
        handle.copy_from_slice(&req.handle);
        // Same OMR limiter as GetUnifOmrDigest. A miss still costs one credit
        // so handle scanning cannot skip the limiter. Do not log the handle.
        self.check_omr_rate_limit(peer, 1)?;
        let pooled = {
            let mut pool = self.pool_lock()?;
            pool.lookup(&handle, detection_pool::unix_now())
        };
        let Some(pooled) = pooled else {
            return Err(Status::not_found(
                "detection key handle not found or expired",
            ));
        };
        if pooled.network_byte != self.network_byte {
            return Err(Status::invalid_argument(
                "detection key network does not match this server",
            ));
        }
        let extra = (pooled.keys.len() as u32).saturating_sub(1);
        if extra > 0 {
            self.check_omr_rate_limit(peer, extra)?;
        }
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = (pooled, req);
            return Err(Status::unimplemented(
                "UnifOMR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let permit = Arc::clone(&self.fhe_permits)
                .acquire_owned()
                .await
                .map_err(|_| Status::resource_exhausted("FHE workers unavailable"))?;
            let response = self
                .evaluate_detection_keys(pooled.keys, req.start_height, req.end_height, permit)
                .await?;
            Ok(Response::new(response))
        }
    }

    async fn fetch_pir_batch(
        &self,
        request: Request<proto::BatchPirRequest>,
    ) -> Result<Response<proto::BatchPirResponse>, Status> {
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "Batch PIR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let peer = self.peer_ip(&request);
            self.check_pir_rate_limit(peer)?;
            let req = request.into_inner();

            if req.query_ciphertexts.is_empty() {
                return Err(Status::invalid_argument("query_ciphertexts required"));
            }
            let start = req.start_height;
            let end = req.end_height;
            let window = reject_oversized_window(start, end)? as usize;
            let degree = crate::unifomr::packing_degree();
            let num_stripes = crate::pir_server::sealpir_stripe_count(window, degree);
            if num_stripes > MAX_PIR_STRIPES {
                return Err(Status::invalid_argument(format!(
                    "PIR window {window} needs {num_stripes} SealPIR stripes (max {MAX_PIR_STRIPES})"
                )));
            }
            // SealPIR-style: one query CT per stripe (always), hiding which stripe
            // contains the match. Single-CT still works for window ≤ degree.
            if req.query_ciphertexts.len() != num_stripes {
                return Err(Status::invalid_argument(format!(
                    "SealPIR expects {num_stripes} query ciphertext(s) for window {window}, got {}",
                    req.query_ciphertexts.len()
                )));
            }
            if req
                .query_ciphertexts
                .iter()
                .any(|ct| ct.len() > MAX_PIR_QUERY_CT_BYTES)
            {
                return Err(Status::invalid_argument(format!(
                    "PIR query ciphertext exceeds {MAX_PIR_QUERY_CT_BYTES} bytes"
                )));
            }
            if (req.limb_index as usize) >= crate::pir_server::MAX_PIR_LIMBS {
                return Err(Status::invalid_argument(format!(
                    "limb_index {} >= max {}",
                    req.limb_index,
                    crate::pir_server::MAX_PIR_LIMBS
                )));
            }

            let permit = Arc::clone(&self.fhe_permits)
                .acquire_owned()
                .await
                .map_err(|_| Status::resource_exhausted("FHE workers unavailable"))?;
            let cache = Arc::clone(&self.cache);
            let limb_index = req.limb_index as usize;
            let queries = req.query_ciphertexts;

            #[allow(clippy::result_large_err)]
            let payload_ciphertexts = tokio::task::spawn_blocking(move || {
                // Held for the computation even if the handler is cancelled.
                let _permit = permit;
                let blocks = cache
                    .get_compact_blocks_range(start, end)
                    .map_err(cache_status)?;

                // Align payloads to every height in [start, end] (S19-style).
                // Encode as protobuf CompactBlock so moonshine + mobile share one codec.
                use prost::Message;
                let mut by_h: std::collections::BTreeMap<u32, Vec<u8>> =
                    std::collections::BTreeMap::new();
                for b in blocks {
                    by_h.insert(b.height, b.to_proto().encode_to_vec());
                }
                let payloads: Vec<Vec<u8>> = (start..=end)
                    .map(|h| by_h.remove(&h).unwrap_or_default())
                    .collect();
                let encoded_total: usize = payloads.iter().map(|p| p.len()).sum();
                if encoded_total > MAX_PIR_WINDOW_ENCODED_BYTES {
                    return Err(Status::resource_exhausted(format!(
                        "PIR window encoded size {encoded_total} exceeds \
                         {MAX_PIR_WINDOW_ENCODED_BYTES}"
                    )));
                }

                let db = crate::pir_server::limb_column(&payloads, limb_index);
                let server = crate::pir_server::BatchPirServer::with_unifomr_params();
                server
                    .evaluate_sealpir_stripes(&queries, &db, window)
                    .map_err(|e| Status::invalid_argument(format!("PIR evaluation error: {e}")))
            })
            .await
            .map_err(|e| Status::internal(format!("PIR worker join error: {e}")))??;

            Ok(Response::new(proto::BatchPirResponse {
                payload_ciphertexts,
            }))
        }
    }

    async fn register_clue_public_key(
        &self,
        request: Request<proto::CluePublicKeyRegistration>,
    ) -> Result<Response<proto::Empty>, Status> {
        self.check_clue_rate_limit(&request)?;
        let req = request.into_inner();
        if req.payment_pubkey.len() != 32 {
            return Err(Status::invalid_argument("payment_pubkey must be 32 bytes"));
        }
        if req.clue_public_key.is_empty() {
            return Err(Status::invalid_argument("clue_public_key required"));
        }
        if req.ownership_proof.is_empty() {
            return Err(Status::invalid_argument("ownership_proof required"));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&req.payment_pubkey);
        // v2 proof binds this server's network byte (no cross-network replay)
        // and the client's monotonic key_version (no stale-registration replay).
        crate::clue_ownership::verify_clue_pk_ownership(
            self.network_byte,
            req.key_version,
            &pk,
            &req.clue_public_key,
            &req.ownership_proof,
        )
        .map_err(Status::invalid_argument)?;
        #[cfg(feature = "fhe-omr")]
        {
            crate::unifomr::deserialize_public_key(&req.clue_public_key).map_err(|e| {
                Status::invalid_argument(format!("invalid UnifOMR clue public key: {e}"))
            })?;
        }
        self.cache
            .store_clue_public_key(
                &pk,
                &req.clue_public_key,
                req.key_version,
                &req.ownership_proof,
            )
            .map_err(|e| Status::invalid_argument(format!("Failed to store clue pk: {e}")))?;
        Ok(Response::new(proto::Empty {}))
    }

    async fn get_clue_public_key(
        &self,
        request: Request<proto::PaymentPubkey>,
    ) -> Result<Response<proto::CluePublicKey>, Status> {
        self.check_clue_rate_limit(&request)?;
        let start = Instant::now();
        let req = request.into_inner();
        if req.payment_pubkey.len() != 32 {
            return Err(Status::invalid_argument("payment_pubkey must be 32 bytes"));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&req.payment_pubkey);

        let attest_sk = self
            .cache
            .get_or_create_directory_attest_secret()
            .map_err(cache_status)?;

        #[cfg(feature = "fhe-omr")]
        let (clue_public_key, key_version) = {
            let registered = self
                .cache
                .get_clue_public_key_entry(&pk)
                .map_err(cache_status)?;
            match registered {
                Some((ver, _stored_proof, real)) => (real, ver),
                None => {
                    let pepper = self
                        .cache
                        .get_or_create_clue_dir_pepper()
                        .map_err(cache_status)?;
                    let anchor = self
                        .cache
                        .get_or_create_clue_dir_pepper_anchor()
                        .map_err(cache_status)?;
                    let pk_c = pk;
                    tokio::task::spawn_blocking(move || {
                        (
                            crate::unifomr::decoy_clue_public_key(&pk_c, &pepper),
                            crate::unifomr::decoy_key_version(&pk_c, &pepper, anchor),
                        )
                    })
                    .await
                    .map_err(|e| Status::internal(format!("decoy keygen join error: {e}")))?
                }
            }
        };
        #[cfg(not(feature = "fhe-omr"))]
        let (clue_public_key, key_version) = {
            match self
                .cache
                .get_clue_public_key_entry(&pk)
                .map_err(cache_status)?
            {
                Some((ver, _stored_proof, real)) => (real, ver),
                None => {
                    // Non-empty dummy so `found=true` + empty body cannot leak
                    // the registration bit on non-fhe-omr builds.
                    let dummy = blake3::hash(&pk).as_bytes().to_vec();
                    let anchor = self
                        .cache
                        .get_or_create_clue_dir_pepper_anchor()
                        .map_err(cache_status)?;
                    (dummy, anchor.saturating_sub(u64::from(pk[0]) * 86_400))
                }
            }
        };

        let ownership_proof = crate::clue_ownership::pad_ownership_proof(
            &crate::clue_ownership::sign_directory_attestation(
                &attest_sk,
                self.network_byte,
                key_version,
                &pk,
                &clue_public_key,
            ),
        )
        .map_err(Status::internal)?;

        // Fixed deadline (not a floor after leftover work) so load-induced
        // decoy keygen overruns still aim at the same response time.
        const MIN_CLUE_LOOKUP: Duration = Duration::from_millis(250);
        let deadline = start + MIN_CLUE_LOOKUP;
        let now = Instant::now();
        if now < deadline {
            tokio::time::sleep(deadline.saturating_duration_since(now)).await;
        }

        // Always report found=true with a fixed-size valid key (real or decoy)
        // so the registration bit does not leak via the boolean or empty body.
        Ok(Response::new(proto::CluePublicKey {
            found: true,
            clue_public_key,
            ownership_proof,
            key_version,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_height_zero_resolves_to_cached_tip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::new(dir.path().to_str().unwrap()).unwrap();
        assert!(resolve_block_range(&cache, 0, 0).is_err());

        cache
            .insert_compact_block(&crate::compact_block::CompactBlock {
                height: 40,
                hash: [9u8; 32],
                prev_hash: [0u8; 32],
                timestamp: 1,
                txs: vec![],
            })
            .unwrap();
        assert_eq!(resolve_block_range(&cache, 0, 0).unwrap(), (0, 40));
        assert_eq!(resolve_block_range(&cache, 10, 0).unwrap(), (10, 40));
        assert_eq!(resolve_block_range(&cache, 0, 10_000).unwrap(), (0, 40));
        assert!(resolve_block_range(&cache, 41, 0).is_err());

        cache
            .insert_compact_block(&crate::compact_block::CompactBlock {
                height: 20_000,
                hash: [8u8; 32],
                prev_hash: [0u8; 32],
                timestamp: 2,
                txs: vec![],
            })
            .unwrap();
        assert!(resolve_block_range(&cache, 0, 0).is_err());
        assert_eq!(
            resolve_block_range(&cache, 19_000, 0).unwrap(),
            (19_000, 20_000)
        );
    }

    #[test]
    fn digest_stops_before_first_missing_height() {
        let dir = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::new(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(digest_evaluable_end(&cache, 0, 5).unwrap(), (None, false));

        for h in [10u32, 11, 12, 14, 15] {
            cache
                .insert_compact_block(&crate::compact_block::CompactBlock {
                    height: h,
                    hash: [h as u8; 32],
                    prev_hash: [h.wrapping_sub(1) as u8; 32],
                    timestamp: h as u64,
                    txs: vec![],
                })
                .unwrap();
        }
        // Fully cached window below the tip.
        assert_eq!(
            digest_evaluable_end(&cache, 10, 12).unwrap(),
            (Some(12), true)
        );
        // Interior hole at 13: evaluate only 10..=12, never 14/15.
        assert_eq!(
            digest_evaluable_end(&cache, 10, 15).unwrap(),
            (Some(12), false)
        );
        // Hole at the window start: nothing evaluable.
        assert_eq!(digest_evaluable_end(&cache, 13, 15).unwrap(), (None, false));
        // End beyond tip: truncate at tip, incomplete.
        assert_eq!(
            digest_evaluable_end(&cache, 14, 20).unwrap(),
            (Some(15), false)
        );
        // Start beyond tip.
        assert_eq!(digest_evaluable_end(&cache, 16, 20).unwrap(), (None, false));
        // Hole at 0 below the first cached block.
        assert_eq!(digest_evaluable_end(&cache, 0, 12).unwrap(), (None, false));
    }

    #[test]
    fn height_span_rejects_wraparound() {
        assert!(height_span(0, u32::MAX).unwrap() > MAX_BLOCKS_PER_REQUEST as u64);
        assert!(reject_oversized_window(0, u32::MAX).is_err());
        assert!(reject_oversized_window(10, 9).is_err());
        assert_eq!(reject_oversized_window(1, 1).unwrap(), 1);
        assert_eq!(reject_oversized_window(1, 10_000).unwrap(), 10_000);
        assert!(reject_oversized_window(1, 10_001).is_err());
    }

    #[test]
    fn snapshot_integrity_hash_covers_height_tree_and_nullifiers() {
        let a = snapshot_integrity_hash(10, b"tree", b"nf");
        let b = snapshot_integrity_hash(10, b"tree", b"nf");
        assert_eq!(a, b);
        assert_ne!(snapshot_integrity_hash(11, b"tree", b"nf"), a);
        assert_ne!(snapshot_integrity_hash(10, b"TREE", b"nf"), a);
        assert_ne!(snapshot_integrity_hash(10, b"tree", b"NF"), a);
        assert_ne!(blake3::hash(b"tree").as_bytes(), &a);
    }

    #[test]
    fn trusted_proxy_match_exact_and_cidr() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(ip_matches_proxy_entry(loopback, "127.0.0.1"));
        assert!(ip_matches_proxy_entry(loopback, "127.0.0.0/8"));
        assert!(!ip_matches_proxy_entry(loopback, "10.0.0.0/8"));
        let trusted = vec!["127.0.0.1".to_string()];
        // nginx appends; leftmost hop is client-spoofable and must be ignored.
        assert_eq!(
            client_ip_from_forwarded("1.2.3.4, 203.0.113.9, 127.0.0.1", &trusted),
            "203.0.113.9".parse::<IpAddr>().ok()
        );
        assert_eq!(
            client_ip_from_forwarded("203.0.113.9", &trusted),
            "203.0.113.9".parse::<IpAddr>().ok()
        );
    }

    fn test_block(height: u32, prev: u8) -> crate::compact_block::CompactBlock {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&height.to_be_bytes());
        crate::compact_block::CompactBlock {
            height,
            hash,
            prev_hash: [prev; 32],
            timestamp: 1_000 + height as u64,
            txs: vec![],
        }
    }

    fn test_service(cache: Arc<Cache>) -> (LightWalletService, tokio::sync::watch::Sender<u32>) {
        let (tx, rx) = tokio::sync::watch::channel(0u32);
        let endpoint = url::Url::parse("http://127.0.0.1:9").unwrap();
        let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(endpoint));
        let svc = LightWalletService::with_limits(
            cache,
            rpc,
            "test".into(),
            0x01,
            10_000,
            10_000,
            DEFAULT_MAX_TX_BYTES,
            rx,
            Vec::new(),
        );
        (svc, tx)
    }

    #[test]
    fn padded_range_accepts_power_of_two_bucket_and_rejects_short() {
        // Exactly 1024, ending at the tip.
        assert!(padded_range_rejection(0, 1023, 1023, MAX_BLOCKS_PER_REQUEST).is_none());
        // Power of two, not aligned to zero, ending before the tip.
        assert!(padded_range_rejection(100, 1123, 5_000, MAX_BLOCKS_PER_REQUEST).is_none());
        assert!(padded_range_rejection(0, 8191, 8191, MAX_BLOCKS_PER_REQUEST).is_none());
        // Short unpadded range.
        assert!(padded_range_rejection(0, 100, 10_000, MAX_BLOCKS_PER_REQUEST).is_some());
        // 512 is a power of two but below the 1024 minimum.
        assert!(padded_range_rejection(0, 511, 10_000, MAX_BLOCKS_PER_REQUEST).is_some());
        // 1025 is not a power of two.
        assert!(padded_range_rejection(0, 1024, 10_000, MAX_BLOCKS_PER_REQUEST).is_some());
        // 16384 is a power of two but above max_range (10_000).
        assert!(padded_range_rejection(0, 16_383, 100_000, MAX_BLOCKS_PER_REQUEST).is_some());
        // Ends past the tip.
        assert!(padded_range_rejection(0, 1023, 100, MAX_BLOCKS_PER_REQUEST).is_some());
        assert!(padded_range_rejection(5, 4, 10, MAX_BLOCKS_PER_REQUEST).is_some());

        // A short cursor near a high tip pads to a bucket the server accepts.
        let (padded_start, padded_end) = pad_block_range(4990, 5000, 5000);
        assert!(padded_start <= 4990 && padded_end == 5000);
        assert!(
            padded_range_rejection(padded_start, padded_end, 5000, MAX_BLOCKS_PER_REQUEST)
                .is_none()
        );
        let span = padded_end - padded_start + 1;
        assert!(span >= MIN_PADDED_RANGE_SPAN && span.is_power_of_two());
        // The unpadded cursor itself is still rejected.
        assert!(padded_range_rejection(4990, 5000, 5000, MAX_BLOCKS_PER_REQUEST).is_some());
        // A chain shorter than one bucket is served whole, from genesis only.
        let (short_start, short_end) = pad_block_range(0, 10, 10);
        assert_eq!((short_start, short_end), (0, 10));
        assert!(
            padded_range_rejection(short_start, short_end, 10, MAX_BLOCKS_PER_REQUEST).is_none()
        );
        assert!(padded_range_rejection(5, 10, 10, MAX_BLOCKS_PER_REQUEST).is_some());
    }

    #[test]
    fn padded_range_accepts_client_buckets_cut_at_the_tip() {
        // Client pad_block_range(4990, 5000, 5000): bucket 4096..=5119 cut at the tip.
        assert!(padded_range_rejection(4096, 5000, 5000, MAX_BLOCKS_PER_REQUEST).is_none());
        // The client's tip trails ours by a few blocks.
        assert!(padded_range_rejection(4096, 5000, 5003, MAX_BLOCKS_PER_REQUEST).is_none());
        // Two 1024 buckets cut at the tip (client pad of 1500..=2500).
        assert!(padded_range_rejection(1024, 2600, 2600, MAX_BLOCKS_PER_REQUEST).is_none());
        // Two full 1024 buckets.
        assert!(padded_range_rejection(1024, 3071, 50_000, MAX_BLOCKS_PER_REQUEST).is_none());
        // A partial bucket far below the tip publishes the cursor.
        assert!(padded_range_rejection(4096, 4990, 50_000, MAX_BLOCKS_PER_REQUEST).is_some());
        assert!(padded_range_rejection(4096, 5000, 5065, MAX_BLOCKS_PER_REQUEST).is_some());
        assert!(padded_range_rejection(4096, 5000, 5064, MAX_BLOCKS_PER_REQUEST).is_none());
        // A partial bucket must start on its boundary.
        assert!(padded_range_rejection(4097, 5000, 5000, MAX_BLOCKS_PER_REQUEST).is_some());
        assert!(padded_range_rejection(1536, 2600, 2600, MAX_BLOCKS_PER_REQUEST).is_some());
    }

    #[test]
    fn require_padded_block_range_rejects_unpadded_against_tip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
        assert!(require_padded_block_range(&cache, 0, 1023).is_err());

        cache.insert_compact_block(&test_block(3000, 0)).unwrap();
        assert_eq!(
            require_padded_block_range(&cache, 0, 1023).unwrap(),
            (0, 1023)
        );
        assert!(require_padded_block_range(&cache, 0, 100).is_err());
        // span = 3000 - 1977 + 1 = 1024, end == tip.
        assert!(require_padded_block_range(&cache, 1977, 3000).is_ok());
        assert!(require_padded_block_range(&cache, 1976, 3000).is_err());
    }

    #[tokio::test]
    async fn checkpoint_snapshot_at_or_below_birthday_and_tree_state_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
        cache.insert_compact_block(&test_block(0, 0)).unwrap();
        cache.insert_compact_block(&test_block(1, 1)).unwrap();
        cache.insert_compact_block(&test_block(2, 2)).unwrap();
        let (svc, _) = test_service(Arc::clone(&cache));

        let miss =
            DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 1 }))
                .await
                .unwrap_err();
        assert_eq!(miss.code(), tonic::Code::FailedPrecondition);
        assert!(
            miss.message().contains("greatest snapshot <= 1 is 0"),
            "status text: {}",
            miss.message()
        );

        let tip_state =
            DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 2 }))
                .await
                .unwrap()
                .into_inner();
        assert!(tip_state.is_checkpoint);
        assert_eq!(tip_state.height, 2);

        let snap0 =
            DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 0 }))
                .await
                .unwrap()
                .into_inner();
        assert!(snap0.is_checkpoint);
        assert_eq!(snap0.height, 0);

        use tokio_stream::StreamExt;
        let mut stream = DarkFiLightWallet::get_checkpoint_snapshot(
            &svc,
            Request::new(proto::CheckpointRequest {
                preferred_height: 1,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let mut tree_data = Vec::new();
        let mut height = None;
        let mut state_root = Vec::new();
        let mut snapshot_hash = Vec::new();
        let mut scan_cursor = 0u32;
        while let Some(chunk) = stream.next().await {
            let snap = chunk.unwrap();
            if height.is_none() {
                height = Some(snap.height);
                state_root = snap.state_root.clone();
                snapshot_hash = snap.snapshot_hash.clone();
                scan_cursor = snap.scan_cursor;
            }
            assert!(snap.nullifier_index.is_empty());
            assert_eq!(snap.scan_cursor, snap.height);
            tree_data.extend_from_slice(&snap.tree_data);
        }
        let height = height.unwrap();
        assert!(height <= 1, "birthday 1 must not receive a later snapshot");
        assert_eq!(height, 0);
        assert_eq!(scan_cursor, height);
        assert_eq!(
            snapshot_hash,
            snapshot_integrity_hash(height, &tree_data, &[]).to_vec()
        );
        // Gap: CompactBlock has no block-header money-tree / coin root.
        // state_root stays blake3(tree_data). Do not invent a second root
        // until darkfid exposes that field on the cached compact block.
        assert_eq!(state_root, blake3::hash(&tree_data).as_bytes().to_vec());

        let mut latest = DarkFiLightWallet::get_checkpoint_snapshot(
            &svc,
            Request::new(proto::CheckpointRequest {
                preferred_height: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let first = latest.next().await.unwrap().unwrap();
        assert_eq!(
            first.height, 2,
            "preferred 0 is the latest snapshot, the tip"
        );
        assert_eq!(first.scan_cursor, 2);

        let empty_dir = tempfile::tempdir().unwrap();
        let empty = Arc::new(Cache::new(empty_dir.path().to_str().unwrap()).unwrap());
        let (empty_svc, _) = test_service(empty);
        let missing = DarkFiLightWallet::get_checkpoint_snapshot(
            &empty_svc,
            Request::new(proto::CheckpointRequest {
                preferred_height: 5,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn pool_digest_missing_and_expired_handles_are_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
        let (svc, _) = test_service(cache);

        let missing = DarkFiLightWallet::get_unif_omr_digest_from_pool(
            &svc,
            Request::new(proto::PoolDigestRequest {
                handle: vec![9u8; 32],
                start_height: 0,
                end_height: 10,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);

        let bad_len = DarkFiLightWallet::get_unif_omr_digest_from_pool(
            &svc,
            Request::new(proto::PoolDigestRequest {
                handle: vec![1, 2, 3],
                start_height: 0,
                end_height: 10,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(bad_len.code(), tonic::Code::InvalidArgument);

        let handle = {
            let mut pool = svc.detection_pool.lock().unwrap();
            pool.insert(
                PooledDetectionKey {
                    keys: vec![Arc::new(vec![1, 2, 3])],
                    network_byte: 1,
                    expires_unix: 10,
                    byte_length: 3,
                },
                svc.max_detection_key_bytes,
                0,
            )
            .unwrap()
        };
        let expired = DarkFiLightWallet::get_unif_omr_digest_from_pool(
            &svc,
            Request::new(proto::PoolDigestRequest {
                handle: handle.to_vec(),
                start_height: 0,
                end_height: 10,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(expired.code(), tonic::Code::NotFound);
        assert!(
            expired.message().contains("expired") || expired.message().contains("not found"),
            "{}",
            expired.message()
        );
    }

    #[tokio::test]
    async fn subscribe_blocks_skips_unsent_tip_instead_of_dropping() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
        let (svc, tip_tx) = test_service(Arc::clone(&cache));
        let notice = Arc::clone(&svc.tip_notice);

        let mut stream = DarkFiLightWallet::subscribe_blocks(&svc, Request::new(proto::Empty {}))
            .await
            .unwrap()
            .into_inner();

        cache.insert_compact_block(&test_block(1, 0x11)).unwrap();
        tip_tx.send(1).unwrap();
        tokio::time::timeout(Duration::from_secs(2), notice.notified())
            .await
            .expect("first tip notice blocked");

        // Client has not read. The one-slot buffer is full; this must not
        // wait 30s or close the subscription.
        cache.insert_compact_block(&test_block(2, 0x22)).unwrap();
        tip_tx.send(2).unwrap();
        tokio::time::timeout(Duration::from_secs(2), notice.notified())
            .await
            .expect("slow client caused a 30s drop or a blocked send");

        use tokio_stream::StreamExt;
        let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("subscription closed")
            .expect("subscription ended")
            .unwrap();
        assert_eq!(first.height, 1);
        assert_eq!(first.prev_hash, vec![0x11; 32]);
        assert_eq!(first.hash, test_block(1, 0x11).hash.to_vec());

        cache.insert_compact_block(&test_block(3, 0x33)).unwrap();
        tip_tx.send(3).unwrap();
        let third = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("subscription dropped after a skipped tip")
            .expect("subscription ended")
            .unwrap();
        assert_eq!(third.height, 3);
        assert_eq!(third.prev_hash, vec![0x33; 32]);
        assert_eq!(third.hash, test_block(3, 0x33).hash.to_vec());
    }

    #[tokio::test]
    async fn compact_output_bodies_are_one_per_output_in_a_padded_range() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
        let mut prev_hash = [0u8; 32];
        for height in 0u32..1023 {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&height.to_be_bytes());
            cache
                .insert_compact_block(&crate::compact_block::CompactBlock {
                    height,
                    hash,
                    prev_hash,
                    timestamp: height as u64,
                    txs: vec![],
                })
                .unwrap();
            prev_hash = hash;
        }
        let coin_a = [0x11u8; 32];
        let coin_b = [0x22u8; 32];
        let mut tip_hash = [0u8; 32];
        tip_hash[..4].copy_from_slice(&1023u32.to_be_bytes());
        cache
            .insert_compact_block(&crate::compact_block::CompactBlock {
                height: 1023,
                hash: tip_hash,
                prev_hash,
                timestamp: 1023,
                txs: vec![crate::compact_block::CompactTx {
                    tx_hash: [0x44; 32],
                    outputs: vec![
                        crate::compact_block::CompactOutput {
                            coin: coin_a,
                            encrypted_note: vec![1, 2],
                            value_commit: vec![3],
                            token_commit: [4; 32],
                            omr_clue: vec![5],
                            omr_metadata_enc: vec![6],
                        },
                        crate::compact_block::CompactOutput {
                            coin: coin_b,
                            encrypted_note: vec![7],
                            value_commit: vec![],
                            token_commit: [8; 32],
                            omr_clue: vec![],
                            omr_metadata_enc: vec![9, 9],
                        },
                    ],
                    nullifiers: vec![[0xAB; 32]],
                    fee: 7,
                }],
            })
            .unwrap();
        let (svc, _) = test_service(Arc::clone(&cache));

        let rejected = DarkFiLightWallet::get_compact_output_bodies(
            &svc,
            Request::new(proto::BlockRange {
                start_height: 0,
                end_height: 10,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(rejected.code(), tonic::Code::InvalidArgument);

        use tokio_stream::StreamExt;
        let mut stream = DarkFiLightWallet::get_compact_output_bodies(
            &svc,
            Request::new(proto::BlockRange {
                start_height: 0,
                end_height: 1023,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let mut bodies = Vec::new();
        while let Some(item) = stream.next().await {
            bodies.push(item.expect("connected padded range"));
        }
        assert_eq!(
            bodies.len(),
            2,
            "one message per output, nullifiers not included"
        );
        assert_eq!(bodies[0].height, 1023);
        assert_eq!(bodies[0].hash, tip_hash.to_vec());
        assert_eq!(bodies[0].prev_hash, prev_hash.to_vec());
        assert_eq!(bodies[0].coin, coin_a.to_vec());
        assert_eq!(bodies[0].encrypted_note, vec![1, 2]);
        assert_eq!(bodies[0].omr_clue, vec![5]);
        assert_eq!(bodies[0].omr_metadata_enc, vec![6]);
        assert_eq!(bodies[0].tx_hash, vec![0x44; 32]);
        assert_eq!(bodies[1].coin, coin_b.to_vec());
        assert_eq!(bodies[1].hash, tip_hash.to_vec());
        assert!(bodies[1].omr_clue.is_empty());
    }

    #[cfg(feature = "fhe-omr")]
    #[test]
    fn clue_window_cache_keeps_notes_not_digest_bytes() {
        let mut cache = ClueWindowCache::new();
        let notes = vec![(
            4u32,
            vec![crate::omr_detector::NoteForDetection {
                encrypted_note: vec![1, 2, 3],
                omr_clue: vec![9],
            }],
        )];
        let hash = [7u8; 32];
        cache.insert(0, 1023, hash, notes.clone());
        let hit = cache.get(0, 1023, hash).unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].0, 4);
        assert_eq!(hit[0].1[0].encrypted_note, notes[0].1[0].encrypted_note);
        assert_eq!(hit[0].1[0].omr_clue, notes[0].1[0].omr_clue);
        assert!(cache.get(0, 1023, [8u8; 32]).is_none());
    }
}
