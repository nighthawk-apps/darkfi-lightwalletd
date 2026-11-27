use super::*;

/// Server state shared across all gRPC handlers.
pub struct LightWalletService {
    /// Local compact block cache
    pub(super) cache: Arc<Cache>,
    /// RPC client for proxying to darkfid
    pub(super) rpc_client: Arc<DarkfidRpcClient>,
    /// Server version string
    pub(super) version: String,
    /// Chain name
    pub(super) chain_name: String,
    /// UnifOMR wire network byte (`0x00` mainnet / `0x01` testnet)
    pub(super) network_byte: u8,
    /// Per-peer UnifOMR digest rate limiter (S6)
    pub(super) omr_rate_limiter: Arc<PeerRateLimiter>,
    /// Per-peer FetchPirBatch limiter (higher than digest — one window is many limbs)
    pub(super) pir_rate_limiter: Arc<PeerRateLimiter>,
    /// Per-peer RegisterOmrClue rate limiter (S12) — tighter than digest.
    pub(super) clue_rate_limiter: Arc<PeerRateLimiter>,
    /// Per-peer GetBlockRange / SendTransaction rate limiter.
    pub(super) rpc_rate_limiter: Arc<PeerRateLimiter>,
    /// Max raw transaction bytes after envelope strip.
    pub(super) max_tx_bytes: usize,
    /// Recent SendTransaction peers keyed by tx hash (S12 peer bind).
    pub(super) recent_send_peers: Arc<Mutex<SendPeerTable>>,
    /// Recently broadcast raw tx bytes held briefly while the tx is in darkfid's mempool.
    #[allow(clippy::type_complexity)]
    pub(super) recent_mempool_txs: Arc<Mutex<HashMap<[u8; 32], (Vec<u8>, Instant)>>>,
    /// Tip height watch from the chain poller (wakes SubscribeBlocks).
    pub(super) tip_notify: tokio::sync::watch::Receiver<u32>,
    /// In-flight block-range streams across every connection.
    pub(super) block_range_permits: Arc<tokio::sync::Semaphore>,
    /// Concurrent `SubscribeBlocks` streams across every connection.
    pub(super) subscribe_permits: Arc<tokio::sync::Semaphore>,
    /// Limits concurrent FHE digest/registration `spawn_blocking` workers.
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) fhe_permits: Arc<tokio::sync::Semaphore>,
    /// Separate permit pool for millisecond `FetchPirBatch` limbs so multi-second
    /// digests do not starve Round-2 PIR fetches.
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) pir_permits: Arc<tokio::sync::Semaphore>,
    /// Whole detection-key upload deadline (configurable for Tor/Nym links).
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) upload_deadline: Duration,
    /// TCP peers from which `X-Forwarded-For` is trusted (empty = ignore the header).
    pub(super) trusted_proxies: Vec<String>,
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) max_detection_key_bytes: usize,
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) max_detection_keys_total_bytes: usize,
    pub(super) max_send_peer_entries: usize,
    /// In-memory detection keys. Not persisted. Handles are never logged.
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) detection_pool: Arc<Mutex<DetectionKeyPool>>,
    /// Wakes tests observing SubscribeBlocks enqueue attempts.
    pub(super) tip_notice: Arc<tokio::sync::Notify>,
    /// Flattened clue/note lists keyed by evaluated `(start, end)`. Not digests.
    #[cfg(feature = "fhe-omr")]
    pub(super) clue_windows: Arc<Mutex<ClueWindowCache>>,
    /// Clue-stripped PIR payloads keyed by `(start, end)` plus end-block hash.
    #[cfg(feature = "fhe-omr")]
    pub(super) pir_windows: Arc<Mutex<PirWindowCache>>,
    /// Byte budget for in-flight detection-key uploads (one permit per byte).
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) upload_bytes: Arc<tokio::sync::Semaphore>,
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) upload_slots: Arc<Mutex<HashMap<IpAddr, usize>>>,
    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    pub(super) max_uploads_per_ip: usize,
    /// In-flight FetchPirBatch count per IP.
    #[cfg(feature = "fhe-omr")]
    pub(super) pir_inflight: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// Concurrent `SubscribeBlocks` streams per peer IP.
    pub(super) subscribe_slots: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// Block range permit pool.
    pub(super) tip_facts: Arc<Mutex<Option<CachedTipFacts>>>,
    /// Serializes the fallback darkfid read when the poller has not stored facts yet.
    pub(super) tip_fact_fetch: Arc<tokio::sync::Mutex<()>>,
    /// Cached 32-byte directory attestation public key (derived once from sled secret).
    pub(super) directory_attest_pubkey: std::sync::OnceLock<[u8; 32]>,
    /// Lock-free atomic metrics counters for periodic INFO summaries.
    pub(super) metrics: Arc<ServiceMetrics>,
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
    #[allow(clippy::too_many_arguments)]
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
        let directory_attest_pubkey = std::sync::OnceLock::new();
        if let Ok(pk) = cache.directory_attest_public_key() {
            let _ = directory_attest_pubkey.set(pk);
        }
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
            // 4096 covers a full MAX_PIR_LIMBS fan-out for one block per minute.
            pir_rate_limiter: Arc::new(PeerRateLimiter::new(
                PIR_RATE_LIMIT_PER_MIN,
                Duration::from_secs(60),
            )),
            clue_rate_limiter: Arc::new(PeerRateLimiter::new(32, Duration::from_secs(60))),
            rpc_rate_limiter: Arc::new(PeerRateLimiter::new(
                rpc_rate_limit_per_min,
                Duration::from_secs(60),
            )),
            max_tx_bytes,
            recent_send_peers: Arc::new(Mutex::new(SendPeerTable::new())),
            recent_mempool_txs: Arc::new(Mutex::new(HashMap::new())),
            tip_notify,
            block_range_permits: Arc::new(tokio::sync::Semaphore::new(MAX_BLOCK_RANGE_STREAMS)),
            subscribe_permits: Arc::new(tokio::sync::Semaphore::new(MAX_SUBSCRIBE_STREAMS)),
            fhe_permits: Arc::new(tokio::sync::Semaphore::new(DEFAULT_FHE_PERMITS)),
            pir_permits: Arc::new(tokio::sync::Semaphore::new(DEFAULT_FHE_PERMITS.max(4))),
            #[cfg(feature = "fhe-omr")]
            upload_deadline: UPLOAD_DEADLINE,
            #[cfg(not(feature = "fhe-omr"))]
            upload_deadline: Duration::from_secs(300),
            trusted_proxies,
            max_detection_key_bytes: MAX_DETECTION_KEY_BYTES,
            max_detection_keys_total_bytes: MAX_DETECTION_KEYS_TOTAL_BYTES,
            max_send_peer_entries: MAX_SEND_PEER_ENTRIES,
            detection_pool: Arc::new(Mutex::new(DetectionKeyPool::new())),
            tip_notice: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "fhe-omr")]
            clue_windows: Arc::new(Mutex::new(ClueWindowCache::new())),
            #[cfg(feature = "fhe-omr")]
            pir_windows: Arc::new(Mutex::new(PirWindowCache::new())),
            upload_bytes: Arc::new(tokio::sync::Semaphore::new(upload_budget_permits(
                DEFAULT_UPLOAD_BUDGET_MIB,
            ))),
            upload_slots: Arc::new(Mutex::new(HashMap::new())),
            max_uploads_per_ip: DEFAULT_MAX_UPLOADS_PER_IP,
            #[cfg(feature = "fhe-omr")]
            pir_inflight: Arc::new(Mutex::new(HashMap::new())),
            subscribe_slots: Arc::new(Mutex::new(HashMap::new())),
            tip_facts: Arc::new(Mutex::new(None)),
            tip_fact_fetch: Arc::new(tokio::sync::Mutex::new(())),
            directory_attest_pubkey,
            metrics: Arc::new(ServiceMetrics::new()),
        }
    }

    /// Lock-free atomic metrics counters shared with the periodic reporter task.
    pub fn metrics(&self) -> Arc<ServiceMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Override DoS caps from operator config (defaults stay conservative).
    pub fn apply_resource_caps(
        &mut self,
        max_detection_key_bytes: usize,
        max_send_peer_entries: usize,
        rate_limit_gc_threshold: usize,
        upload_budget_mib: usize,
        max_uploads_per_ip: usize,
    ) {
        self.max_detection_key_bytes = max_detection_key_bytes.max(1);
        self.max_detection_keys_total_bytes = max_detection_key_bytes.max(1);
        self.max_send_peer_entries = max_send_peer_entries.max(1);
        self.upload_bytes = Arc::new(tokio::sync::Semaphore::new(upload_budget_permits(
            upload_budget_mib,
        )));
        self.max_uploads_per_ip = max_uploads_per_ip.max(1);
        self.omr_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
        self.pir_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
        self.clue_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
        self.rpc_rate_limiter
            .set_gc_threshold(rate_limit_gc_threshold);
    }

    /// Override FHE worker concurrency, detection-key pool limits, and upload deadline.
    pub fn apply_fhe_pool_config(
        &mut self,
        fhe_workers: usize,
        detection_pool_handles: usize,
        detection_pool_mib: u64,
        upload_deadline_s: u64,
    ) {
        let workers = fhe_workers.max(1);
        self.fhe_permits = Arc::new(tokio::sync::Semaphore::new(workers));
        self.pir_permits = Arc::new(tokio::sync::Semaphore::new(workers.max(4)));
        let pool_bytes = detection_pool_mib.max(1).saturating_mul(1 << 20);
        self.detection_pool = Arc::new(Mutex::new(DetectionKeyPool::with_limits(
            detection_pool_handles.max(1),
            pool_bytes,
        )));
        self.upload_deadline = Duration::from_secs(upload_deadline_s.max(1));
    }

    pub(super) fn peer_ip<T>(&self, request: &Request<T>) -> IpAddr {
        let remote = request
            .remote_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        resolve_peer_ip(remote, request.metadata(), &self.trusted_proxies)
    }

    pub(super) fn peer_rate_ip<T>(&self, request: &Request<T>) -> IpAddr {
        rate_limit_ip(self.peer_ip(request))
    }

    pub(super) fn remember_send_peer(&self, tx_hash: [u8; 32], peer: IpAddr) {
        if let Ok(mut table) = self.recent_send_peers.lock() {
            let now = Instant::now();
            if now.duration_since(table.last_gc) >= SEND_PEER_GC_INTERVAL
                || table.entries.len() >= self.max_send_peer_entries
            {
                table
                    .entries
                    .retain(|_, (_, t)| now.duration_since(*t) < SEND_PEER_BIND_TTL);
                table.last_gc = now;
            }
            // M2: hard-cap to prevent unbounded growth under sustained traffic.
            if table.entries.len() >= self.max_send_peer_entries {
                // Evict oldest entries to make room.
                let mut entries: Vec<_> =
                    table.entries.iter().map(|(k, (_, t))| (*k, *t)).collect();
                entries.sort_by_key(|(_, t)| *t);
                let evict_count = table
                    .entries
                    .len()
                    .saturating_sub(self.max_send_peer_entries)
                    + 1;
                for (k, _) in entries.into_iter().take(evict_count) {
                    table.entries.remove(&k);
                }
            }
            table.entries.insert(tx_hash, (peer, now));
        }
    }

    pub(super) fn send_peer_matches(&self, tx_hash: &[u8; 32], peer: IpAddr) -> bool {
        let Ok(mut table) = self.recent_send_peers.lock() else {
            return false;
        };
        let now = Instant::now();
        if now.duration_since(table.last_gc) >= SEND_PEER_GC_INTERVAL {
            table
                .entries
                .retain(|_, (_, t)| now.duration_since(*t) < SEND_PEER_BIND_TTL);
            table.last_gc = now;
        }
        match table.entries.get(tx_hash).copied() {
            Some((bound, ts)) => {
                if now.duration_since(ts) >= SEND_PEER_BIND_TTL {
                    table.entries.remove(tx_hash);
                    false
                } else {
                    bound == peer
                }
            }
            None => false,
        }
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn directory_attest_pubkey(&self) -> Result<[u8; 32], Status> {
        if let Some(&pk) = self.directory_attest_pubkey.get() {
            return Ok(pk);
        }
        let pk = self
            .cache
            .directory_attest_public_key()
            .map_err(cache_status)?;
        let _ = self.directory_attest_pubkey.set(pk);
        Ok(*self.directory_attest_pubkey.get().unwrap_or(&pk))
    }

    pub(super) fn remember_mempool_tx(&self, tx_hash: [u8; 32], raw_tx: Vec<u8>) {
        if let Ok(mut map) = self.recent_mempool_txs.lock() {
            let now = Instant::now();
            map.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(1800));
            const MAX_MEMPOOL_TX_CACHE: usize = 512;
            if map.len() >= MAX_MEMPOOL_TX_CACHE {
                let mut entries: Vec<_> = map.iter().map(|(k, (_, t))| (*k, *t)).collect();
                entries.sort_by_key(|(_, t)| *t);
                let evict_count = map.len().saturating_sub(MAX_MEMPOOL_TX_CACHE) + 1;
                for (k, _) in entries.into_iter().take(evict_count) {
                    map.remove(&k);
                }
            }
            map.insert(tx_hash, (raw_tx, now));
        }
    }

    pub(super) fn cached_mempool_tx(&self, tx_hash: &[u8; 32]) -> Option<Vec<u8>> {
        let Ok(mut map) = self.recent_mempool_txs.lock() else {
            return None;
        };
        let now = Instant::now();
        map.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(1800));
        map.get(tx_hash).map(|(bytes, _)| bytes.clone())
    }

    pub(super) async fn confirm_tx_in_mempool_or_chain(
        &self,
        tx_hash_hex: &str,
    ) -> Result<bool, crate::error::LightWalletError> {
        let needle = tx_hash_hex.trim().to_ascii_lowercase();
        for attempt in 0..4 {
            match self.rpc_client.get_pending_tx_hashes().await {
                Ok(pending) if pending.iter().any(|h| h == &needle) => return Ok(true),
                Ok(_) => {}
                Err(e) if e.is_connection() => return Err(e),
                Err(_) => {}
            }
            if self.rpc_client.get_tx(&needle).await.is_ok() {
                return Ok(true);
            }
            if attempt < 3 {
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
        }
        Ok(false)
    }

    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    #[allow(clippy::result_large_err)]
    pub(super) fn check_omr_rate_limit(&self, peer: IpAddr, n: u32) -> Result<(), Status> {
        if self.omr_rate_limiter.check_n(peer, n.max(1)) {
            Ok(())
        } else {
            self.metrics.record_rate_limited();
            Err(Status::resource_exhausted(
                "OMR digest rate limit exceeded; retry later",
            ))
        }
    }

    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    #[allow(clippy::result_large_err)]
    pub(super) fn check_pir_rate_limit(&self, peer: IpAddr) -> Result<(), Status> {
        if self.pir_rate_limiter.check_n(peer, 1) {
            Ok(())
        } else {
            self.metrics.record_rate_limited();
            Err(Status::resource_exhausted(
                "PIR rate limit exceeded; retry later",
            ))
        }
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn check_clue_rate_limit<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.clue_rate_limiter.check(self.peer_rate_ip(request)) {
            Ok(())
        } else {
            self.metrics.record_rate_limited();
            Err(Status::resource_exhausted(
                "OMR clue registration rate limit exceeded; retry later",
            ))
        }
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn check_rpc_rate_limit<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.rpc_rate_limiter.check(self.peer_rate_ip(request)) {
            Ok(())
        } else {
            self.metrics.record_rate_limited();
            Err(Status::resource_exhausted(
                "RPC rate limit exceeded; retry later",
            ))
        }
    }

    /// Wait up to 10s for a process-wide block-range slot. The permit must
    /// live until the stream task finishes.
    #[allow(clippy::result_large_err)]
    pub(super) async fn acquire_block_range(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        let sem = Arc::clone(&self.block_range_permits);
        match tokio::time::timeout(BLOCK_RANGE_WAIT, sem.acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(Status::unavailable("block-range limiter closed")),
            Err(_) => {
                tracing::warn!(
                    target: "lightwalletd::server",
                    "block-range capacity full ({MAX_BLOCK_RANGE_STREAMS})"
                );
                Err(Status::unavailable(
                    "too many block-range streams; retry shortly",
                ))
            }
        }
    }

    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    #[allow(clippy::result_large_err)]
    pub(super) fn try_slot(
        slots: &Arc<Mutex<HashMap<IpAddr, usize>>>,
        peer: IpAddr,
        cap: usize,
    ) -> Result<SlotGuard, Status> {
        let mut map = slots.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.entry(peer).or_insert(0);
        if *n >= cap {
            return Err(Status::resource_exhausted(
                "too many concurrent requests from this address",
            ));
        }
        *n += 1;
        drop(map);
        Ok(SlotGuard {
            peer,
            slots: Arc::clone(slots),
        })
    }

    #[cfg(feature = "fhe-omr")]
    #[allow(clippy::result_large_err)]
    pub(super) fn reserve_upload(
        &self,
        peer: IpAddr,
        num_keys: u32,
    ) -> Result<UploadReservation, Status> {
        // Total buffered upload bytes are capped at `max_detection_keys_total_bytes`.
        let declared = (num_keys as usize)
            .saturating_mul(self.max_detection_key_bytes)
            .min(self.max_detection_keys_total_bytes);
        let declared = u32::try_from(declared).map_err(|_| {
            Status::resource_exhausted("detection-key upload exceeds the byte budget")
        })?;
        if declared == 0 {
            return Err(Status::resource_exhausted(
                "detection-key upload exceeds the byte budget",
            ));
        }
        let slot =
            Self::try_slot(&self.upload_slots, peer, self.max_uploads_per_ip).map_err(|_| {
                Status::resource_exhausted(
                    "too many concurrent detection-key uploads from this address",
                )
            })?;
        let bytes = Arc::clone(&self.upload_bytes)
            .try_acquire_many_owned(declared)
            .map_err(|_| {
                Status::resource_exhausted("detection-key upload byte budget exhausted")
            })?;
        Ok(UploadReservation {
            _bytes: bytes,
            _slot: slot,
        })
    }

    #[cfg(feature = "fhe-omr")]
    #[allow(clippy::result_large_err)]
    pub(super) async fn acquire_fhe_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        match tokio::time::timeout(
            FHE_PERMIT_WAIT,
            Arc::clone(&self.fhe_permits).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(Status::unavailable("FHE workers unavailable")),
            Err(_) => Err(Status::unavailable("timed out waiting for an FHE worker")),
        }
    }

    #[cfg(feature = "fhe-omr")]
    #[allow(clippy::result_large_err)]
    pub(super) async fn acquire_pir_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        match tokio::time::timeout(
            FHE_PERMIT_WAIT,
            Arc::clone(&self.pir_permits).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(Status::unavailable("PIR workers unavailable")),
            Err(_) => Err(Status::unavailable("timed out waiting for a PIR worker")),
        }
    }

    #[cfg(feature = "fhe-omr")]
    #[allow(clippy::result_large_err)]
    pub(super) fn begin_pir(&self, peer: IpAddr) -> Result<SlotGuard, Status> {
        Self::try_slot(&self.pir_inflight, peer, MAX_PIR_INFLIGHT_PER_IP).map_err(|_| {
            Status::resource_exhausted(
                "too many in-flight FetchPirBatch requests from this address",
            )
        })
    }

    pub(super) async fn block_target_for_tip(&self, height: u32, hash: [u8; 32]) -> u32 {
        block_target_from(
            &self.tip_facts,
            &self.cache,
            &self.tip_fact_fetch,
            &self.rpc_client,
            height,
            hash,
            Duration::from_secs(2),
        )
        .await
    }

    pub(super) async fn difficulty_for_tip(&self, height: u32, hash: [u8; 32]) -> String {
        match load_tip_fact(
            &self.tip_facts,
            &self.cache,
            &self.tip_fact_fetch,
            &self.rpc_client,
            (height, hash),
            TipFact::Difficulty,
            Duration::from_secs(2),
        )
        .await
        {
            TipFactValue::Difficulty(difficulty) => difficulty,
            TipFactValue::BlockTarget(_) => String::new(),
        }
    }

    /// Store a validated SendTransaction clue; `true` if this call stored it.
    ///
    /// S3: first-writer-wins — an existing hint is never overwritten.
    pub(super) fn store_send_clue_hint(
        &self,
        hash: &[u8; 32],
        clue: Vec<u8>,
        output_index: u32,
    ) -> bool {
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

    /// Store opaque recipient-encrypted OMR metadata; `true` if this call stored it.
    ///
    /// First-writer-wins — an existing metadata entry is never overwritten.
    pub(super) fn store_send_metadata_enc(
        &self,
        hash: &[u8; 32],
        metadata_enc: Vec<u8>,
        output_index: u32,
    ) -> bool {
        if self.cache.has_omr_metadata_enc(hash).unwrap_or(false) {
            tracing::info!(
                target: "lightwalletd::server",
                "OMR metadata_enc already present for tx; first-writer-wins, not overwriting"
            );
            return false;
        }
        match self
            .cache
            .store_omr_metadata_enc(hash, metadata_enc, Some(output_index))
        {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    target: "lightwalletd::server",
                    "Failed to store OMR metadata_enc: {e}"
                );
                false
            }
        }
    }

    /// Validate a sender-supplied UnifOMR clue (requires `fhe-omr`).
    pub(super) fn validate_omr_clue(omr_clue: &[u8]) -> Result<(), String> {
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

    #[cfg_attr(not(feature = "fhe-omr"), allow(dead_code))]
    #[allow(clippy::result_large_err)]
    pub(super) fn pool_lock(&self) -> Result<std::sync::MutexGuard<'_, DetectionKeyPool>, Status> {
        self.detection_pool
            .lock()
            .map_err(|_| Status::internal("detection key pool unavailable"))
    }

    #[cfg(feature = "fhe-omr")]
    #[allow(clippy::result_large_err)]
    pub(super) fn cached_flattened_clues_from(
        cache: &Cache,
        clue_windows: &Arc<Mutex<ClueWindowCache>>,
        start: u32,
        end: u32,
    ) -> Result<Arc<FlattenedClueWindow>, Status> {
        let end_hash = cache
            .get_block_hash(end)
            .map_err(cache_status)?
            .unwrap_or([0u8; 32]);
        if end_hash != [0u8; 32] {
            if let Ok(guard) = clue_windows.lock() {
                if let Some(hit) = guard.get(start, end, end_hash) {
                    return Ok(hit);
                }
            }
        }
        let notes = cache
            .get_encrypted_notes_range(start, end)
            .map_err(cache_status)?;
        let expected = (end.saturating_sub(start)).saturating_add(1) as usize;
        if notes.len() != expected
            || cache
                .get_compact_block(end)
                .map_err(cache_status)?
                .is_none()
        {
            return Err(Status::aborted("chain discontinuity during OMR clue read"));
        }
        let end_hash_after = cache
            .get_block_hash(end)
            .map_err(cache_status)?
            .unwrap_or([0u8; 32]);
        if end_hash != [0u8; 32] && end_hash != end_hash_after {
            return Err(Status::aborted("chain tip shifted during OMR clue read"));
        }
        let clue_notes = crate::unifomr::block_notes_from_detection(&notes);
        let (mut messages, mut slot_heights) = crate::unifomr::flatten_messages(&clue_notes);
        let truncated =
            crate::unifomr::cap_messages_to_whole_heights(&mut messages, &mut slot_heights);
        let slot_heights_wire = crate::unifomr::pack_slot_heights(&slot_heights);
        let window = Arc::new(FlattenedClueWindow {
            messages,
            slot_heights_wire,
            truncated,
        });
        if end_hash_after != [0u8; 32] {
            if let Ok(mut guard) = clue_windows.lock() {
                guard.insert(start, end, end_hash_after, Arc::clone(&window));
            }
        }
        Ok(window)
    }

    /// Same digest evaluator `GetUnifOmrDigest` uses after the key is in hand.
    ///
    /// Does not cache the ciphertext. The flattened clue list for `(start, eval_end)`
    /// is shared across handles via `Arc` without re-parsing or cloning clues.
    #[cfg(feature = "fhe-omr")]
    #[allow(clippy::result_large_err)]
    pub(super) async fn evaluate_detection_keys(
        &self,
        keys: Vec<Arc<Vec<u8>>>,
        start: u32,
        end: u32,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<proto::OmrDigestResponse, Status> {
        reject_oversized_window(start, end)?;
        let (eval_end, range_complete) = digest_evaluable_end(&self.cache, start, end)?;
        let cache = Arc::clone(&self.cache);
        let clue_windows = Arc::clone(&self.clue_windows);
        let network_byte = self.network_byte;
        let (encrypted_digest, truncated, slot_heights_wire) =
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let window = match eval_end {
                    Some(eval_end) => {
                        Self::cached_flattened_clues_from(&cache, &clue_windows, start, eval_end)
                            .map_err(|s| s.message().to_string())?
                    }
                    None => Arc::new(FlattenedClueWindow {
                        messages: Vec::new(),
                        slot_heights_wire: Vec::new(),
                        truncated: false,
                    }),
                };
                let detector = crate::unifomr::UnifOmrDetector::new(network_byte)
                    .map_err(|e| e.to_string())?;
                let digest = if keys.len() == 1 {
                    crate::unifomr::encode_messages_padded(&detector, &keys[0], &window.messages)
                        .map_err(|e| e.to_string())?
                } else {
                    let mut out = Vec::new();
                    for key in &keys {
                        let d = crate::unifomr::encode_messages_padded(
                            &detector,
                            key,
                            &window.messages,
                        )
                        .map_err(|e| e.to_string())?;
                        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
                        out.extend_from_slice(&d);
                    }
                    out
                };
                Ok::<_, String>((digest, window.truncated, window.slot_heights_wire.clone()))
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
    #[allow(clippy::result_large_err)]
    pub(super) async fn read_detection_key_upload(
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
        let mut current_key = Vec::new();
        let mut keys = Vec::new();
        let mut total_key_bytes = 0usize;
        let mut chunk_count = 0usize;
        const MAX_DETECTION_CHUNKS: usize = 4096;
        let mut reservation: Option<UploadReservation> = None;
        let upload_deadline_secs = self.upload_deadline.as_secs();
        let deadline = tokio::time::Instant::now() + self.upload_deadline;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Status::deadline_exceeded(format!(
                    "UnifOMR detection-key upload exceeded {upload_deadline_secs}s"
                )));
            }
            let wait = DETECTION_KEY_CHUNK_IDLE_TIMEOUT.min(remaining);
            let next = tokio::time::timeout(wait, stream.next())
                .await
                .map_err(|_| {
                    if wait < DETECTION_KEY_CHUNK_IDLE_TIMEOUT {
                        Status::deadline_exceeded(format!(
                            "UnifOMR detection-key upload exceeded {upload_deadline_secs}s"
                        ))
                    } else {
                        Status::deadline_exceeded("UnifOMR detection-key upload stalled")
                    }
                })?;
            let Some(chunk_res) = next else { break };
            let chunk = chunk_res?;
            chunk_count += 1;
            if chunk_count > MAX_DETECTION_CHUNKS {
                return Err(Status::invalid_argument(
                    "UnifOMR detection-key upload exceeded max chunk count",
                ));
            }

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
                reservation = Some(self.reserve_upload(peer, num_keys)?);
                keys.reserve(num_keys as usize);
            } else if chunk.data.is_empty() && !chunk.key_done {
                return Err(Status::invalid_argument(
                    "empty non-terminating detection key chunk not allowed",
                ));
            }

            total_key_bytes = total_key_bytes.saturating_add(chunk.data.len());
            if total_key_bytes > self.max_detection_keys_total_bytes {
                return Err(Status::invalid_argument(format!(
                    "UnifOMR detection_keys total size too large: {total_key_bytes} bytes \
                     (max {})",
                    self.max_detection_keys_total_bytes
                )));
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
                if current_key.is_empty() {
                    return Err(Status::invalid_argument("empty detection key not allowed"));
                }
                if keys.len() >= num_keys as usize {
                    return Err(Status::invalid_argument(format!(
                        "Received more than num_keys ({num_keys}) detection keys"
                    )));
                }
                keys.push(std::mem::take(&mut current_key));
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

        // The upload is network I/O. The FHE permit is taken by the caller
        // after this returns, so a slow body cannot pin a worker slot.
        // `reservation` is held by the caller until the buffered keys are done.
        let reservation = reservation.ok_or_else(|| Status::invalid_argument("Empty stream"))?;
        Ok(DetectionKeyUpload {
            start,
            end,
            keys,
            reservation,
        })
    }
}

#[cfg(feature = "fhe-omr")]
pub(super) struct DetectionKeyUpload {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) keys: Vec<Vec<u8>>,
    pub(super) reservation: UploadReservation,
}
