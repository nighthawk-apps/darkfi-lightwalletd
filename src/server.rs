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
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};

use crate::{
    cache::Cache,
    proto::{self, dark_fi_light_wallet_server::DarkFiLightWallet},
    rate_limit::PeerRateLimiter,
    rpc_client::DarkfidRpcClient,
};

/// Maximum number of blocks allowed in a single range request.
/// Prevents DoS via unbounded range requests that would load
/// the entire cache into memory.
const MAX_BLOCKS_PER_REQUEST: u32 = 10_000;
/// Max heights in a sparse GetCompactBlocksAtHeights request.
const MAX_SPARSE_HEIGHTS: usize = 512;
/// Max serialized detection key size before parse (S24 / DoS).
/// UnifOMR GenDetKey is ~38MB at n=1024 (BFV CTs). Allow headroom.
const MAX_DETECTION_KEY_BYTES: usize = 48 * 1024 * 1024;
/// Cap on sum of all detection_keys lengths in one request.
const MAX_DETECTION_KEYS_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Concurrent FHE worker slots (GetUnifOmrDigest / FetchPirBatch).
const DEFAULT_FHE_PERMITS: usize = 2;
/// Max SealPIR stripe query ciphertexts (window ≤ stripes × BFV degree).
const MAX_PIR_STRIPES: usize = 8;
/// Max opaque recipient OMR metadata on SendTransaction.
const MAX_OMR_METADATA_ENC_BYTES: usize = 4096;

/// How long a SendTransaction peer binding remains valid for RegisterOmrClue (S12).
const SEND_PEER_BIND_TTL: Duration = Duration::from_secs(86_400);
/// Hard cap on `recent_send_peers` entries to prevent unbounded memory growth (M2).
const MAX_SEND_PEER_ENTRIES: usize = 100_000;

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
    /// Per-peer UnifOMR digest / PIR rate limiter (S6)
    omr_rate_limiter: Arc<PeerRateLimiter>,
    /// Per-peer RegisterOmrClue rate limiter (S12) — tighter than digest.
    clue_rate_limiter: Arc<PeerRateLimiter>,
    /// Recent SendTransaction peers keyed by tx hash (S12 peer bind).
    #[allow(clippy::type_complexity)]
    recent_send_peers: Arc<Mutex<HashMap<[u8; 32], (IpAddr, Instant)>>>,
    /// Tip height watch from the chain poller (wakes SubscribeBlocks).
    tip_notify: tokio::sync::watch::Receiver<u32>,
    /// Limits concurrent FHE `spawn_blocking` workers (CPU / RAM).
    fhe_permits: Arc<tokio::sync::Semaphore>,
}

impl LightWalletService {
    pub fn new(
        cache: Arc<Cache>,
        rpc_client: Arc<DarkfidRpcClient>,
        chain_name: String,
        network_byte: u8,
        tip_notify: tokio::sync::watch::Receiver<u32>,
    ) -> Self {
        Self::with_rate_limit(cache, rpc_client, chain_name, network_byte, 30, tip_notify)
    }

    /// Create a service with a custom per-minute UnifOMR rate limit.
    pub fn with_rate_limit(
        cache: Arc<Cache>,
        rpc_client: Arc<DarkfidRpcClient>,
        chain_name: String,
        network_byte: u8,
        omr_rate_limit_per_min: u32,
        tip_notify: tokio::sync::watch::Receiver<u32>,
    ) -> Self {
        Self {
            cache,
            rpc_client,
            version: env!("CARGO_PKG_VERSION").to_string(),
            chain_name,
            network_byte,
            omr_rate_limiter: Arc::new(PeerRateLimiter::new(
                omr_rate_limit_per_min,
                Duration::from_secs(60),
            )),
            clue_rate_limiter: Arc::new(PeerRateLimiter::new(32, Duration::from_secs(60))),
            recent_send_peers: Arc::new(Mutex::new(HashMap::new())),
            tip_notify,
            fhe_permits: Arc::new(tokio::sync::Semaphore::new(DEFAULT_FHE_PERMITS)),
        }
    }

    fn peer_ip<T>(request: &Request<T>) -> IpAddr {
        request
            .remote_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }

    fn remember_send_peer(&self, tx_hash: [u8; 32], peer: IpAddr) {
        if let Ok(mut map) = self.recent_send_peers.lock() {
            let now = Instant::now();
            map.retain(|_, (_, t)| now.duration_since(*t) < SEND_PEER_BIND_TTL);
            // M2: hard-cap to prevent unbounded growth under sustained traffic.
            if map.len() >= MAX_SEND_PEER_ENTRIES {
                // Evict oldest entries to make room.
                let mut entries: Vec<_> = map.iter()
                    .map(|(k, (_, t))| (*k, *t))
                    .collect();
                entries.sort_by_key(|(_, t)| *t);
                let evict_count = map.len().saturating_sub(MAX_SEND_PEER_ENTRIES) + 1;
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
    fn check_clue_rate_limit<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.clue_rate_limiter.check(Self::peer_ip(request)) {
            Ok(())
        } else {
            Err(Status::resource_exhausted(
                "OMR clue registration rate limit exceeded; retry later",
            ))
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
}

#[tonic::async_trait]
impl DarkFiLightWallet for LightWalletService {
    type GetBlockRangeStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactBlock, Status>>;

    /// Stream compact blocks in a height range.
    async fn get_block_range(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let range = request.into_inner();
        let start = range.start_height;
        let end = range.end_height;

        if start > end {
            return Err(Status::invalid_argument(format!(
                "Invalid block range: start={start} > end={end}"
            )));
        }

        // SECURITY: Enforce max range to prevent DoS via unbounded requests
        if end - start + 1 > MAX_BLOCKS_PER_REQUEST {
            return Err(Status::invalid_argument(format!(
                "Range too large: {} blocks requested, max is {MAX_BLOCKS_PER_REQUEST}",
                end - start + 1
            )));
        }

        let cache = Arc::clone(&self.cache);
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        // Spawn a task to stream blocks from the cache
        tokio::spawn(async move {
            match cache.get_compact_blocks_range(start, end) {
                Ok(blocks) => {
                    for block in blocks {
                        let proto_block = block.to_proto();
                        if tx.send(Ok(proto_block)).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("Cache error: {e}"))))
                        .await;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Get a single compact block by height.
    async fn get_block(
        &self,
        request: Request<proto::BlockHeight>,
    ) -> Result<Response<proto::CompactBlock>, Status> {
        let height = request.into_inner().height;

        match self.cache.get_compact_block(height) {
            Ok(Some(block)) => Ok(Response::new(block.to_proto())),
            Ok(None) => Err(Status::not_found(format!(
                "Block not found at height {height}"
            ))),
            Err(e) => Err(Status::internal(format!("Cache error: {e}"))),
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
                Err(e) => {
                    return Err(Status::internal(format!("Cache error: {e}")));
                }
            }
        }

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            for block in blocks {
                if tx.send(Ok(block.to_proto())).await.is_err() {
                    break; // Client disconnected
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
                let timestamp = self
                    .cache
                    .get_compact_block(height)
                    .map_err(|e| Status::internal(format!("Cache error: {e}")))?
                    .map(|b| b.timestamp)
                    .unwrap_or(0);

                let block_target = self.rpc_client.get_block_target().await.unwrap_or(0);

                Ok(Response::new(proto::ChainTip {
                    height,
                    hash: hash.to_vec(),
                    timestamp,
                    block_target,
                }))
            }
            Ok(None) => Err(Status::unavailable("No blocks cached yet")),
            Err(e) => Err(Status::internal(format!("Cache error: {e}"))),
        }
    }

    type SubscribeBlocksStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactBlock, Status>>;

    /// Subscribe to new blocks. Wakes when the chain poller advances the tip
    /// (poller interval latency), instead of a fixed 5s sleep.
    async fn subscribe_blocks(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<Response<Self::SubscribeBlocksStream>, Status> {
        let cache = Arc::clone(&self.cache);
        let mut tip_rx = self.tip_notify.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            let mut last_height = cache.get_tip().unwrap_or(None).map(|(h, _)| h).unwrap_or(0);

            loop {
                // Wait for tip notification (or spurious wake / lag).
                if tip_rx.changed().await.is_err() {
                    return; // sender dropped — shut down
                }
                let current_height = *tip_rx.borrow_and_update();

                if current_height > last_height {
                    if let Ok(blocks) =
                        cache.get_compact_blocks_range(last_height + 1, current_height)
                    {
                        for block in blocks {
                            let proto_block = block.to_proto();
                            // Backpressure: if the client can't keep up, drop the
                            // subscription rather than blocking the server task.
                            // Use a bounded send with timeout — if the client
                            // hasn't drained within 30s, they're too slow.
                            match tokio::time::timeout(
                                Duration::from_secs(30),
                                tx.send(Ok(proto_block)),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => return, // Client disconnected
                                Err(_) => {
                                    tracing::warn!(
                                        target: "lightwalletd::server",
                                        "SubscribeBlocks client too slow; dropping subscription"
                                    );
                                    return;
                                }
                            }
                        }
                        last_height = current_height;
                    }
                } else if current_height < last_height {
                    // Reorg / rewind: reset cursor; next advance streams from new tip path.
                    last_height = current_height;
                }
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
        let hash = request.into_inner().hash;
        let hash_hex = hex::encode(&hash);

        match self.rpc_client.get_tx(&hash_hex).await {
            Ok(tx_bytes) => Ok(Response::new(proto::RawTransaction {
                data: tx_bytes,
                omr_clue: vec![],
                omr_clue_output_index: 0,
                omr_metadata_enc: vec![],
            })),
            Err(e) => Err(Status::internal(format!(
                "Failed to fetch transaction: {e}"
            ))),
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
        let peer = Self::peer_ip(&request);
        let req = request.into_inner();
        let mut tx_data = req.data;
        let mut omr_clue = req.omr_clue;

        if let Some(env) = crate::omr_envelope::parse_envelope(&tx_data) {
            let raw_tx = env.raw_tx.to_vec();
            if omr_clue.is_empty() && !env.fhe_clue.is_empty() {
                omr_clue = env.fhe_clue.to_vec();
            }
            tx_data = raw_tx;
        }

        // Pre-compute tx hash so we can index the OMR clue before the block lands.
        let tx_hash_for_clue = darkfi_serial::deserialize::<darkfi::tx::Transaction>(&tx_data)
            .ok()
            .map(|tx| *tx.hash().inner());

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

                // S22: surface whether the attached clue was accepted (tx may still succeed).
                let mut clue_accepted = false;
                if !omr_clue.is_empty() {
                    // S12: validate on SendTransaction the same as RegisterOmrClue.
                    if let Err(e) = Self::validate_omr_clue(&omr_clue) {
                        tracing::warn!(
                            target: "lightwalletd::server",
                            "Rejecting OMR clue on SendTransaction: {e}"
                        );
                    } else if let Some(hash) = hash {
                        // S3: first-writer-wins — do not overwrite an existing clue.
                        if self.cache.has_omr_clue_hint(&hash).unwrap_or(false) {
                            tracing::info!(
                                target: "lightwalletd::server",
                                "OMR clue already present for tx; first-writer-wins, not overwriting"
                            );
                        } else {
                            match self.cache.store_omr_clue_hint(
                                &hash,
                                omr_clue,
                                Some(req.omr_clue_output_index),
                            ) {
                                Ok(()) => clue_accepted = true,
                                Err(e) => {
                                    tracing::warn!(
                                        target: "lightwalletd::server",
                                        "Failed to store OMR clue hint: {e}"
                                    );
                                }
                            }
                        }
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
                        if let Err(e) = self.cache.store_omr_metadata_enc(
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
        let range = request.into_inner();

        // SECURITY: Enforce max range
        if range.start_height > range.end_height {
            return Err(Status::invalid_argument("Invalid range: start > end"));
        }
        if range.end_height - range.start_height + 1 > MAX_BLOCKS_PER_REQUEST {
            return Err(Status::invalid_argument(format!(
                "Range too large: max is {MAX_BLOCKS_PER_REQUEST}"
            )));
        }

        let cache = Arc::clone(&self.cache);
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            match cache.get_coins_range(range.start_height, range.end_height) {
                Ok(entries) => {
                    for (height, coins) in entries {
                        let update = proto::NoteCommitmentUpdate {
                            height,
                            coins: coins.iter().map(|c| c.to_vec()).collect(),
                        };
                        if tx.send(Ok(update)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("Cache error: {e}"))))
                        .await;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type GetNullifiersStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::NullifierUpdate, Status>>;

    /// Get nullifiers for a block range.
    async fn get_nullifiers(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetNullifiersStream>, Status> {
        let range = request.into_inner();

        // SECURITY: Enforce max range
        if range.start_height > range.end_height {
            return Err(Status::invalid_argument("Invalid range: start > end"));
        }
        if range.end_height - range.start_height + 1 > MAX_BLOCKS_PER_REQUEST {
            return Err(Status::invalid_argument(format!(
                "Range too large: max is {MAX_BLOCKS_PER_REQUEST}"
            )));
        }

        let cache = Arc::clone(&self.cache);
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            match cache.get_nullifiers_range(range.start_height, range.end_height) {
                Ok(entries) => {
                    for (height, nullifiers) in entries {
                        let update = proto::NullifierUpdate {
                            height,
                            nullifiers: nullifiers.iter().map(|n| n.to_vec()).collect(),
                        };
                        if tx.send(Ok(update)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("Cache error: {e}"))))
                        .await;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Get Merkle tree state at a given height.
    ///
    /// MVP: tip-only. Historical / pruned heights return FAILED_PRECONDITION.
    async fn get_tree_state(
        &self,
        request: Request<proto::BlockHeight>,
    ) -> Result<Response<proto::TreeState>, Status> {
        let height = request.into_inner().height;
        let tip = self
            .cache
            .get_tip()
            .map_err(|e| Status::internal(format!("Cache error: {e}")))?
            .map(|(h, _)| h)
            .unwrap_or(0);

        if height != tip {
            return Err(Status::failed_precondition(format!(
                "GetTreeState is tip-only (requested {height}, tip {tip}); \
                 historical snapshots are not retained"
            )));
        }

        match self
            .cache
            .get_tip_tree_state()
            .map_err(|e| Status::internal(format!("Cache error: {e}")))?
        {
            Some((tree_height, tree_data)) if tree_height == tip => {
                Ok(Response::new(proto::TreeState {
                    height: tree_height,
                    tree_data,
                }))
            }
            Some((tree_height, _)) => Err(Status::failed_precondition(format!(
                "Tip Merkle tree height {tree_height} does not match tip {tip}; resync required"
            ))),
            None => {
                if tip == 0 {
                    // Empty chain: return empty tree.
                    let tree = darkfi_sdk::crypto::MerkleTree::new(100);
                    Ok(Response::new(proto::TreeState {
                        height: 0,
                        tree_data: darkfi_serial::serialize(&tree),
                    }))
                } else {
                    Err(Status::not_found(
                        "Tip Merkle tree not available yet; wait for chain poller to index blocks",
                    ))
                }
            }
        }
    }

    /// Lookup zkas bincodes for a contract.
    async fn lookup_zkas(
        &self,
        request: Request<proto::ContractId>,
    ) -> Result<Response<proto::ZkasResponse>, Status> {
        let contract_id = request.into_inner().id;

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
            Err(e) => Err(Status::internal(format!("Failed to lookup zkas: {e}"))),
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
            .map_err(|e| Status::internal(format!("Cache error: {e}")))?
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
            backend_version: format!("lightwalletd {}", env!("CARGO_PKG_VERSION")),
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
        let peer = Self::peer_ip(&request);

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

        if self.cache.has_omr_clue_hint(&hash).unwrap_or(false) {
            // S3: first-writer-wins — already have a clue; do not overwrite.
            tracing::info!(
                target: "lightwalletd::server",
                "OMR clue already present for RegisterOmrClue; first-writer-wins, not overwriting"
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
        request: Request<proto::OmrDigestRequest>,
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
            let peer = Self::peer_ip(&request);
            let req = request.into_inner();
            let start = req.start_height;
            let end = req.end_height;

            let mut keys: Vec<Vec<u8>> = req.detection_keys;
            if keys.is_empty() && !req.detection_key.is_empty() {
                keys.push(req.detection_key);
            }
            if keys.is_empty() {
                return Err(Status::invalid_argument(
                    "detection_key or detection_keys required",
                ));
            }
            if keys.len() > 16 {
                return Err(Status::invalid_argument(
                    "Too many UnifOMR detection_keys (max 16)",
                ));
            }
            for (i, k) in keys.iter().enumerate() {
                if k.len() > MAX_DETECTION_KEY_BYTES {
                    return Err(Status::invalid_argument(format!(
                        "UnifOMR detection key[{i}] too large: {} bytes",
                        k.len()
                    )));
                }
            }
            let total_key_bytes: usize = keys.iter().map(|k| k.len()).sum();
            if total_key_bytes > MAX_DETECTION_KEYS_TOTAL_BYTES {
                return Err(Status::invalid_argument(format!(
                    "UnifOMR detection_keys total size too large: {total_key_bytes} bytes \
                     (max {MAX_DETECTION_KEYS_TOTAL_BYTES})"
                )));
            }
            // Reject oversized multi-key payloads even when individual keys pass
            // (e.g. many near-max keys whose product of count×size is excessive).
            if let Some(max_len) = keys.iter().map(|k| k.len()).max() {
                if keys
                    .len()
                    .saturating_mul(max_len)
                    > MAX_DETECTION_KEYS_TOTAL_BYTES
                {
                    return Err(Status::invalid_argument(
                        "UnifOMR detection_keys count×size exceeds total size budget",
                    ));
                }
            }
            self.check_omr_rate_limit(peer, keys.len() as u32)?;

            if start > end {
                return Err(Status::invalid_argument(format!(
                    "Invalid height range: start={start} > end={end}"
                )));
            }
            if end - start + 1 > MAX_BLOCKS_PER_REQUEST {
                return Err(Status::invalid_argument(format!(
                    "UnifOMR range too large: {} blocks (max {MAX_BLOCKS_PER_REQUEST})",
                    end - start + 1
                )));
            }

            let tip_height = self
                .cache
                .get_tip()
                .map_err(|e| Status::internal(format!("Cache error: {e}")))?
                .map(|(h, _)| h)
                .unwrap_or(0);
            let mut complete = tip_height >= end;
            if complete {
                for h in start..=end {
                    match self.cache.get_block_hash(h) {
                        Ok(Some(_)) => {}
                        Ok(None) => {
                            complete = false;
                            break;
                        }
                        Err(e) => {
                            return Err(Status::internal(format!("Cache error: {e}")));
                        }
                    }
                }
            }

            let block_notes = self
                .cache
                .get_encrypted_notes_range(start, end)
                .map_err(|e| Status::internal(format!("Cache error: {e}")))?;

            let network_byte = self.network_byte;
            let _permit = self
                .fhe_permits
                .acquire()
                .await
                .map_err(|_| Status::resource_exhausted("FHE workers unavailable"))?;
            let encrypted_digest = tokio::task::spawn_blocking(move || {
                let detector = crate::unifomr::UnifOmrDetector::new(network_byte);
                let clue_notes = crate::unifomr::block_notes_from_detection(&block_notes);
                if keys.len() == 1 {
                    return crate::unifomr::evaluate_padded(&detector, &keys[0], &clue_notes)
                        .map_err(|e| e.to_string());
                }
                let mut out = Vec::new();
                for key in &keys {
                    let digest = crate::unifomr::evaluate_padded(&detector, key, &clue_notes)
                        .map_err(|e| e.to_string())?;
                    out.extend_from_slice(&(digest.len() as u32).to_le_bytes());
                    out.extend_from_slice(&digest);
                }
                Ok(out)
            })
            .await
            .map_err(|e| Status::internal(format!("UnifOMR worker join error: {e}")))?
            .map_err(|e| Status::invalid_argument(format!("UnifOMR detection error: {e}")))?;

            Ok(Response::new(proto::OmrDigestResponse {
                encrypted_digest,
                complete,
            }))
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
            let peer = Self::peer_ip(&request);
            self.check_omr_rate_limit(peer, 1)?;
            let req = request.into_inner();

            if req.query_ciphertexts.is_empty() {
                return Err(Status::invalid_argument("query_ciphertexts required"));
            }
            let start = req.start_height;
            let end = req.end_height;
            if start > end {
                return Err(Status::invalid_argument("invalid PIR height window"));
            }
            let window = (end - start + 1) as usize;
            if window > MAX_BLOCKS_PER_REQUEST as usize {
                return Err(Status::invalid_argument("PIR window too large"));
            }
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

            let blocks = self
                .cache
                .get_compact_blocks_range(start, end)
                .map_err(|e| Status::internal(format!("Cache error: {e}")))?;

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

            let limb_index = req.limb_index as usize;
            let db = crate::pir_server::limb_column(&payloads, limb_index);
            let queries = req.query_ciphertexts;

            let _permit = self
                .fhe_permits
                .acquire()
                .await
                .map_err(|_| Status::resource_exhausted("FHE workers unavailable"))?;
            let payload_ciphertexts = tokio::task::spawn_blocking(move || {
                let server = crate::pir_server::BatchPirServer::with_unifomr_params();
                server.evaluate_sealpir_stripes(&queries, &db, window)
            })
            .await
            .map_err(|e| Status::internal(format!("PIR worker join error: {e}")))?
            .map_err(|e| Status::invalid_argument(format!("PIR evaluation error: {e}")))?;

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
            .store_clue_public_key(&pk, &req.clue_public_key, req.key_version)
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

        #[cfg(feature = "fhe-omr")]
        let clue_public_key = {
            let registered = self
                .cache
                .get_clue_public_key(&pk)
                .map_err(|e| Status::internal(format!("Cache error: {e}")))?;
            match registered {
                Some(real) => real,
                None => {
                    let pepper = self
                        .cache
                        .get_or_create_clue_dir_pepper()
                        .map_err(|e| Status::internal(format!("Cache error: {e}")))?;
                    crate::unifomr::decoy_clue_public_key(&pk, &pepper)
                }
            }
        };
        #[cfg(not(feature = "fhe-omr"))]
        let clue_public_key = {
            self.cache
                .get_clue_public_key(&pk)
                .map_err(|e| Status::internal(format!("Cache error: {e}")))?
                .unwrap_or_default()
        };

        // Pad past worst-case decoy RLWE keygen (n=1024) so cache-hit vs decoy
        // is not distinguishable by latency.
        const MIN_CLUE_LOOKUP: Duration = Duration::from_millis(250);
        let elapsed = start.elapsed();
        if elapsed < MIN_CLUE_LOOKUP {
            tokio::time::sleep(MIN_CLUE_LOOKUP - elapsed).await;
        }

        // Always report found=true with a fixed-size valid key (real or decoy)
        // so the registration bit does not leak via the boolean or empty body.
        Ok(Response::new(proto::CluePublicKey {
            found: true,
            clue_public_key,
        }))
    }
}
