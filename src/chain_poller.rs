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

//! Chain poller: periodically syncs blocks from darkfid into the local cache.
//!
//! The poller runs an async loop that:
//! 1. Queries darkfid for the current chain tip
//! 2. Compares to our cached tip
//! 3. Fetches any new blocks, converts them to CompactBlock, and inserts into cache
//! 4. Detects reorgs by verifying prev_hash continuity
//! 5. Retries with exponential backoff on failures

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::{block_processor, cache::Cache, error::Result, rpc_client::DarkfidRpcClient};

/// Configuration for the chain poller.
pub struct ChainPollerConfig {
    /// Base poll interval in seconds
    pub poll_interval_secs: u64,
    /// Maximum backoff interval in seconds on consecutive failures
    pub max_backoff_secs: u64,
    /// Maximum number of blocks to fetch in a single poll cycle
    pub batch_size: u32,
    /// Cache retention window in blocks. Blocks older than this are pruned.
    /// Set to 0 to disable automatic pruning.
    pub retention_window: u32,
    /// Prune every N blocks processed.
    pub prune_interval_blocks: u32,
}

impl Default for ChainPollerConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 10,
            max_backoff_secs: 300,
            batch_size: 100,
            retention_window: 0,
            prune_interval_blocks: 10_000,
        }
    }
}

/// What the poller should do given cache vs darkfid tips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TipAction {
    Idle,
    Fetch { from: u32, to: u32 },
    HoldForBackendCatchup,
    ReorgFrom { height: u32 },
}

/// Classify cache vs remote without I/O.
///
/// `cached_hash_at_remote_height` is the hash we stored at `remote_height` (if any).
/// `remote_hash_at_cached_tip` is darkfid's hash for our cached tip height:
/// `Some` if the node served that height, `None` if it does not have it (IBD).
pub(crate) fn classify_tips(
    cached: Option<(u32, [u8; 32])>,
    remote_height: u32,
    remote_hash: [u8; 32],
    cached_hash_at_remote_height: Option<[u8; 32]>,
    remote_hash_at_cached_tip: Option<[u8; 32]>,
) -> TipAction {
    let Some((cached_height, cached_hash)) = cached else {
        return TipAction::Fetch {
            from: 0,
            to: remote_height,
        };
    };

    if remote_height < cached_height {
        if let Some(h) = remote_hash_at_cached_tip {
            if h == cached_hash {
                return TipAction::Idle;
            }
            return TipAction::ReorgFrom {
                height: cached_height,
            };
        }
        if cached_hash_at_remote_height == Some(remote_hash) {
            return TipAction::HoldForBackendCatchup;
        }
        return TipAction::ReorgFrom {
            height: remote_height.min(cached_height),
        };
    }

    if cached_height == remote_height {
        if cached_hash == remote_hash {
            return TipAction::Idle;
        }
        return TipAction::ReorgFrom {
            height: cached_height,
        };
    }

    if let Some(h) = remote_hash_at_cached_tip {
        if h != cached_hash {
            return TipAction::ReorgFrom {
                height: cached_height,
            };
        }
    }

    TipAction::Fetch {
        from: cached_height.saturating_add(1),
        to: remote_height,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Chain poller that syncs blocks from darkfid into the local sled cache.
pub struct ChainPoller {
    rpc_client: Arc<DarkfidRpcClient>,
    cache: Arc<Cache>,
    config: ChainPollerConfig,
    /// Notifies SubscribeBlocks (and other listeners) when cache tip advances.
    tip_notify: tokio::sync::watch::Sender<u32>,
}

impl ChainPoller {
    pub fn new(
        rpc_client: Arc<DarkfidRpcClient>,
        cache: Arc<Cache>,
        config: ChainPollerConfig,
        tip_notify: tokio::sync::watch::Sender<u32>,
    ) -> Self {
        Self {
            rpc_client,
            cache,
            config,
            tip_notify,
        }
    }

    /// One darkfid read of block target and difficulty, stored with the tip.
    ///
    /// zcash/lightwalletd serves chain metadata from the cache the ingestor
    /// just wrote. Doing that here keeps GetLightInfo from opening a darkfid
    /// connection per waiting client when the tip advances.
    async fn refresh_tip_chain_facts(&self) {
        let (height, hash) = match self.cache.get_tip() {
            Ok(Some(tip)) => tip,
            Ok(None) => return,
            Err(e) => {
                warn!(
                    target: "lightwalletd::chain_poller",
                    "tip read failed before chain-fact refresh: {e}"
                );
                return;
            }
        };
        let target = match self.rpc_client.get_block_target().await {
            Ok(target) => target,
            Err(e) => {
                warn!(
                    target: "lightwalletd::chain_poller",
                    "block target refresh failed: {e}"
                );
                return;
            }
        };
        let difficulty = match self.rpc_client.get_difficulty(height).await {
            Ok(difficulty) => difficulty,
            Err(e) => {
                warn!(
                    target: "lightwalletd::chain_poller",
                    "difficulty refresh failed: {e}"
                );
                return;
            }
        };
        match self.cache.get_tip() {
            Ok(Some((now_h, now_hash))) if now_h == height && now_hash == hash => {}
            Ok(_) => return,
            Err(e) => {
                warn!(
                    target: "lightwalletd::chain_poller",
                    "tip read failed after chain-fact refresh: {e}"
                );
                return;
            }
        }
        if let Err(e) = self
            .cache
            .set_tip_chain_facts(height, &hash, target, &difficulty)
        {
            warn!(
                target: "lightwalletd::chain_poller",
                "failed to store tip chain facts: {e}"
            );
        }
    }

    fn notify_tip(&self) {
        let tip = self
            .cache
            .get_tip()
            .ok()
            .flatten()
            .map(|(h, _)| h)
            .unwrap_or(0);
        let _ = self.tip_notify.send(tip);
    }

    /// Run the poll loop. This function never returns under normal operation.
    pub async fn run(&self) {
        let mut consecutive_failures: u32 = 0;
        let mut blocks_since_last_prune: u32 = 0;
        let mut last_ok = Instant::now();
        let mut logged_sustained = false;

        loop {
            match self.poll_once().await {
                Ok(blocks_processed) => {
                    if blocks_processed > 0 {
                        info!(
                            target: "lightwalletd::chain_poller",
                            "Processed {blocks_processed} new blocks"
                        );
                        blocks_since_last_prune += blocks_processed;
                    }
                    consecutive_failures = 0;
                    last_ok = Instant::now();
                    logged_sustained = false;

                    // Periodic cache pruning
                    if self.config.retention_window > 0
                        && blocks_since_last_prune >= self.config.prune_interval_blocks
                    {
                        match self
                            .cache
                            .prune_with_retention(self.config.retention_window)
                        {
                            Ok(_) => {
                                debug!(
                                    target: "lightwalletd::chain_poller",
                                    "Periodic cache pruning complete (retention={})",
                                    self.config.retention_window
                                );
                            }
                            Err(e) => {
                                warn!(
                                    target: "lightwalletd::chain_poller",
                                    "Cache pruning failed: {e}"
                                );
                            }
                        }
                        blocks_since_last_prune = 0;
                    }

                    // If we processed a full batch, immediately poll again
                    // (there may be more blocks to fetch)
                    if blocks_processed >= self.config.batch_size {
                        continue;
                    }
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    error!(
                        target: "lightwalletd::chain_poller",
                        "Poll failed (attempt {consecutive_failures}): {e}"
                    );
                    if !logged_sustained && last_ok.elapsed() >= Duration::from_secs(300) {
                        error!(
                            target: "lightwalletd::chain_poller",
                            "darkfid tip unreachable for 5 minutes"
                        );
                        logged_sustained = true;
                    }
                }
            }

            let sleep_secs = self.backoff_interval(consecutive_failures);
            debug!(
                target: "lightwalletd::chain_poller",
                "Sleeping {sleep_secs}s before next poll"
            );
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
        }
    }

    /// Perform a single poll cycle:
    /// 1. Get chain tip from darkfid
    /// 2. Compare to cached tip (IBD vs reorg vs fetch)
    /// 3. Fetch and process any new blocks
    /// 4. Detect reorgs via prev_hash and walk to the common ancestor
    ///
    /// Returns the number of blocks processed.
    async fn poll_once(&self) -> Result<u32> {
        let (remote_height, remote_hash) = self.rpc_client.get_last_confirmed_block().await?;
        if let Err(e) = self.cache.set_tip_fetched_unix(unix_now()) {
            warn!(
                target: "lightwalletd::chain_poller",
                "failed to record tip poll time: {e}"
            );
        }
        let remote_hash_bytes: [u8; 32] = match blake3::Hash::from_hex(&remote_hash) {
            Ok(h) => *h.as_bytes(),
            Err(e) => {
                return Err(crate::error::LightWalletError::RpcError(format!(
                    "invalid tip hash from darkfid: {e}"
                )));
            }
        };

        // A cache imported from an unpruned birthday / snapshot can have tip > 0 while
        // height 0 is absent. Skip backfill once pruning has occurred.
        if self.cache.pruned_below_height()? == 0
            && self.cache.get_compact_block(0)?.is_none()
            && self.cache.get_compact_block(1)?.is_some()
        {
            info!(
                target: "lightwalletd::chain_poller",
                "Height 0 missing from unpruned cache; backfilling genesis compact block"
            );
            return self.fetch_range(0, 0).await;
        }

        let cached_tip = self.cache.get_tip()?;
        let cached_hash_at_remote = self.cache.get_block_hash(remote_height)?;
        let remote_hash_at_cached_tip = match cached_tip {
            Some((h, _)) if h == remote_height => Some(remote_hash_bytes),
            Some((h, _)) => match self.rpc_client.get_block(h).await {
                Ok(block) => Some(*block.hash().inner()),
                // When darkfid is behind our cached tip (IBD or shorter-chain reorg),
                // `-32121` ("Did not find block height") means darkfid does not have `h`,
                // not a transport failure. Let `classify_tips(..., None)` decide between
                // holding for catchup vs rewinding a shorter fork.
                Err(ref e) if remote_height < h && is_missing_block_height_error(e) => None,
                // zcash/lightwalletd BlockIngestor: transport/timeout/unexpected
                // getblock errors are retried. They are not evidence of a fork.
                Err(e) => {
                    warn!(
                        target: "lightwalletd::chain_poller",
                        "RPC error fetching cached tip {h}: {e}; will retry"
                    );
                    return Err(e);
                }
            },
            None => None,
        };

        match classify_tips(
            cached_tip,
            remote_height,
            remote_hash_bytes,
            cached_hash_at_remote,
            remote_hash_at_cached_tip,
        ) {
            TipAction::Idle => Ok(0),
            TipAction::HoldForBackendCatchup => {
                debug!(
                    target: "lightwalletd::chain_poller",
                    "darkfid catching up (remote {remote_height} < cache); holding cache"
                );
                Ok(0)
            }
            TipAction::ReorgFrom { height } => self.rewind_to_common_ancestor(height).await,
            TipAction::Fetch { from, to } => self.fetch_range(from, to).await,
        }
    }

    async fn fetch_range(&self, start: u32, remote_end: u32) -> Result<u32> {
        let end = std::cmp::min(
            start.saturating_add(self.config.batch_size.saturating_sub(1)),
            remote_end,
        );
        debug!(
            target: "lightwalletd::chain_poller",
            "Fetching blocks {start}..={end} (remote tip: {remote_end})"
        );

        let mut blocks_processed: u32 = 0;
        for height in start..=end {
            let block_info = self.rpc_client.get_block(height).await?;

            if height > 0 {
                let prev_hash = *block_info.header.previous.inner();
                if let Some(cached_prev_hash) = self.cache.get_block_hash(height - 1)? {
                    if prev_hash != cached_prev_hash {
                        warn!(
                            target: "lightwalletd::chain_poller",
                            "Reorg detected at height {height} (prev_hash mismatch)"
                        );
                        return self
                            .rewind_to_common_ancestor(height.saturating_sub(1))
                            .await;
                    }
                }
            }

            let compact_block = block_processor::process_block(&block_info).await?;
            self.cache.insert_compact_block(&compact_block)?;
            blocks_processed += 1;
        }

        if blocks_processed > 0 {
            self.refresh_tip_chain_facts().await;
            self.cache.flush()?;
            self.notify_tip();
        }

        Ok(blocks_processed)
    }

    /// Walk backwards from `from` until cache and darkfid agree, then rewind once.
    async fn rewind_to_common_ancestor(&self, from: u32) -> Result<u32> {
        const MAX_WALK: u32 = 10_000;
        let mut h = from;
        let mut walked = 0u32;

        loop {
            if let Some(cached_hash) = self.cache.get_block_hash(h)? {
                match self.rpc_client.get_block(h).await {
                    Ok(block) => {
                        if *block.hash().inner() == cached_hash {
                            warn!(
                                target: "lightwalletd::chain_poller",
                                "Rewinding cache to common ancestor at height {h} (started at {from})"
                            );
                            self.cache.rewind_to_height(h)?;
                            self.refresh_tip_chain_facts().await;
                            self.notify_tip();
                            return Ok(0);
                        }
                    }
                    // Same rule as zcash/lightwalletd: only a block we actually
                    // received can justify walking further. An RPC, timeout, or
                    // decode error aborts the walk so a blip cannot wipe the cache.
                    Err(e) => {
                        warn!(
                            target: "lightwalletd::chain_poller",
                            "RPC error fetching block {h} during ancestor search: {e}; aborting walk"
                        );
                        return Err(e);
                    }
                }
            }

            if h == 0 || walked >= MAX_WALK {
                warn!(
                    target: "lightwalletd::chain_poller",
                    "No common ancestor at or above height {h}; clearing derived block cache"
                );
                if h == 0 {
                    self.cache.clear_derived_block_cache()?;
                } else {
                    self.cache.rewind_to_height(h)?;
                }
                self.refresh_tip_chain_facts().await;
                self.notify_tip();
                return Ok(0);
            }
            h -= 1;
            walked += 1;
        }
    }

    /// Calculate backoff interval with exponential growth, capped cleanly at `max_backoff_secs`.
    fn backoff_interval(&self, failures: u32) -> u64 {
        if failures == 0 {
            return self.config.poll_interval_secs;
        }

        let shift = failures.min(6);
        let backoff = self.config.poll_interval_secs.saturating_mul(1u64 << shift);
        backoff.min(self.config.max_backoff_secs)
    }
}

fn is_missing_block_height_error(err: &crate::error::LightWalletError) -> bool {
    if err.is_not_found() {
        return true;
    }
    match err {
        crate::error::LightWalletError::RpcError(msg) => {
            msg.contains("-32121") || msg.contains("Did not find block height")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_interval() {
        let config = ChainPollerConfig {
            poll_interval_secs: 10,
            max_backoff_secs: 300,
            batch_size: 100,
            retention_window: 100_000,
            prune_interval_blocks: 10_000,
        };
        let dir = tempfile::tempdir().unwrap();
        let (tip_tx, _) = tokio::sync::watch::channel(0u32);
        let poller = ChainPoller {
            rpc_client: Arc::new(DarkfidRpcClient::new_simple(
                url::Url::parse("tcp://127.0.0.1:8340").unwrap(),
            )),
            cache: Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap()),
            config,
            tip_notify: tip_tx,
        };

        assert_eq!(poller.backoff_interval(0), 10);
        assert_eq!(poller.backoff_interval(1), 20);
        assert_eq!(poller.backoff_interval(2), 40);
        assert_eq!(poller.backoff_interval(3), 80);
        assert_eq!(poller.backoff_interval(4), 160);
        assert_eq!(poller.backoff_interval(5), 300); // capped
        assert_eq!(poller.backoff_interval(10), 300); // still capped
        assert_eq!(poller.backoff_interval(u32::MAX), 300); // never overflows

        let huge_poller = ChainPoller {
            rpc_client: Arc::clone(&poller.rpc_client),
            cache: Arc::clone(&poller.cache),
            config: ChainPollerConfig {
                poll_interval_secs: u64::MAX / 2,
                max_backoff_secs: 300,
                ..ChainPollerConfig::default()
            },
            tip_notify: poller.tip_notify.clone(),
        };
        assert_eq!(huge_poller.backoff_interval(6), 300);
    }

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn classify_ibd_holds_cache() {
        let action = classify_tips(Some((1000, h(1))), 50, h(5), Some(h(5)), None);
        assert_eq!(action, TipAction::HoldForBackendCatchup);
    }

    #[test]
    fn classify_reorg_at_equal_height() {
        let action = classify_tips(Some((10, h(1))), 10, h(2), Some(h(1)), Some(h(2)));
        assert_eq!(action, TipAction::ReorgFrom { height: 10 });
    }

    #[test]
    fn classify_reorg_while_down_when_remote_ahead() {
        let action = classify_tips(Some((10, h(1))), 20, h(9), None, Some(h(8)));
        assert_eq!(action, TipAction::ReorgFrom { height: 10 });
    }

    #[test]
    fn classify_fetch_when_same_chain_ahead() {
        let action = classify_tips(Some((10, h(1))), 20, h(9), None, Some(h(1)));
        assert_eq!(action, TipAction::Fetch { from: 11, to: 20 });
    }

    #[test]
    fn classify_empty_cache_fetches_from_genesis() {
        let action = classify_tips(None, 5, h(1), None, None);
        assert_eq!(action, TipAction::Fetch { from: 0, to: 5 });
    }

    #[test]
    fn classify_in_sync() {
        let action = classify_tips(Some((10, h(1))), 10, h(1), Some(h(1)), Some(h(1)));
        assert_eq!(action, TipAction::Idle);
    }

    fn make_mock_block_info(height: u32, prev: [u8; 32], ts: u64) -> darkfi::blockchain::BlockInfo {
        use darkfi::blockchain::{BlockInfo, Header, HeaderHash};
        use darkfi::util::time::Timestamp;
        use darkfi_sdk::crypto::schnorr::Signature;
        BlockInfo {
            header: Header::new(HeaderHash::new(prev), height, 0, Timestamp::from_u64(ts)),
            txs: vec![],
            signature: Signature::dummy(),
        }
    }

    async fn spawn_mock_poller_darkfid(
        remote_tip: (u32, String),
        blocks: std::collections::HashMap<u32, Option<String>>,
        drop_get_block_height: Option<u32>,
    ) -> String {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let remote_tip = remote_tip.clone();
                let blocks = blocks.clone();
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut reader = BufReader::new(r);
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let parsed: tinyjson::JsonValue = line.parse().unwrap();
                    let obj = parsed
                        .get::<std::collections::HashMap<String, tinyjson::JsonValue>>()
                        .unwrap();
                    let method = obj
                        .get("method")
                        .and_then(|v| v.get::<String>())
                        .cloned()
                        .unwrap_or_default();
                    let id = obj
                        .get("id")
                        .and_then(|v| v.get::<f64>())
                        .copied()
                        .unwrap_or(1.0) as i64;
                    let resp = match method.as_str() {
                        "blockchain.last_confirmed_block" => {
                            format!(
                                r#"{{"jsonrpc":"2.0","result":[{},"{}"],"id":{id}}}"#,
                                remote_tip.0, remote_tip.1
                            ) + "\n"
                        }
                        "blockchain.get_block" => {
                            let req_h = obj
                                .get("params")
                                .and_then(|v| v.get::<Vec<tinyjson::JsonValue>>())
                                .and_then(|p| p.first())
                                .and_then(|v| v.get::<f64>())
                                .copied()
                                .unwrap_or(0.0) as u32;
                            if drop_get_block_height == Some(req_h) {
                                // Simulate transport drop without response.
                                return;
                            }
                            match blocks.get(&req_h) {
                                Some(Some(b64)) => {
                                    format!(r#"{{"jsonrpc":"2.0","result":"{b64}","id":{id}}}"#)
                                        + "\n"
                                }
                                _ => {
                                    format!(
                                        r#"{{"jsonrpc":"2.0","error":{{"code":-32121,"message":"Did not find block height"}},"id":{id}}}"#
                                    ) + "\n"
                                }
                            }
                        }
                        "blockchain.block_target" => {
                            format!(r#"{{"jsonrpc":"2.0","result":20,"id":{id}}}"#) + "\n"
                        }
                        "blockchain.get_difficulty" => {
                            format!(r#"{{"jsonrpc":"2.0","result":[100,200],"id":{id}}}"#) + "\n"
                        }
                        _ => format!(r#"{{"jsonrpc":"2.0","result":null,"id":{id}}}"#) + "\n",
                    };
                    let _ = w.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("tcp://{addr}")
    }

    #[tokio::test]
    async fn poll_once_holds_cache_during_ibd_on_32121() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());

        // Populate cache heights 0..=4 on chain A.
        let mut prev = [0u8; 32];
        let mut chain_a_hashes = Vec::new();
        for height in 0..=4u32 {
            let blk = make_mock_block_info(height, prev, 1000 + height as u64);
            let compact = block_processor::process_block(&blk).await.unwrap();
            prev = compact.hash;
            chain_a_hashes.push(compact.hash);
            cache.insert_compact_block(&compact).unwrap();
        }

        // Backend is at height 2 with the SAME hash (IBD catchup), and returns -32121 for height 4.
        let remote_hash_hex = blake3::Hash::from(chain_a_hashes[2]).to_hex().to_string();
        let url_str =
            spawn_mock_poller_darkfid((2, remote_hash_hex), Default::default(), None).await;
        let (tip_tx, _) = tokio::sync::watch::channel(4u32);
        let poller = ChainPoller::new(
            Arc::new(DarkfidRpcClient::new_simple(
                url::Url::parse(&url_str).unwrap(),
            )),
            Arc::clone(&cache),
            ChainPollerConfig::default(),
            tip_tx,
        );

        let processed = poller.poll_once().await.unwrap();
        assert_eq!(processed, 0);
        // Cache tip must remain held at height 4 (not rewound or wedged).
        assert_eq!(cache.get_tip().unwrap().unwrap().0, 4);
    }

    #[tokio::test]
    async fn poll_once_rewinds_shorter_chain_reorg_on_32121() {
        use darkfi::util::encoding::base64;
        use darkfi_serial::serialize_async;

        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());

        // Populate cache heights 0..=4 on chain A.
        let mut prev = [0u8; 32];
        let mut chain_a_blocks = Vec::new();
        for height in 0..=4u32 {
            let blk = make_mock_block_info(height, prev, 1000 + height as u64);
            let compact = block_processor::process_block(&blk).await.unwrap();
            prev = compact.hash;
            chain_a_blocks.push(blk);
            cache.insert_compact_block(&compact).unwrap();
        }

        // Fork at height 2: backend has chain A for 0..=1, and a different block at height 2 (tip=2 < 4).
        let fork_b2 = make_mock_block_info(2, *chain_a_blocks[1].hash().inner(), 9999);
        let fork_b2_hash_hex = blake3::Hash::from(*fork_b2.hash().inner())
            .to_hex()
            .to_string();

        let mut remote_blocks = std::collections::HashMap::new();
        remote_blocks.insert(
            0,
            Some(base64::encode(&serialize_async(&chain_a_blocks[0]).await).to_string()),
        );
        remote_blocks.insert(
            1,
            Some(base64::encode(&serialize_async(&chain_a_blocks[1]).await).to_string()),
        );
        remote_blocks.insert(
            2,
            Some(base64::encode(&serialize_async(&fork_b2).await).to_string()),
        );

        let url_str = spawn_mock_poller_darkfid((2, fork_b2_hash_hex), remote_blocks, None).await;
        let (tip_tx, _) = tokio::sync::watch::channel(4u32);
        let poller = ChainPoller::new(
            Arc::new(DarkfidRpcClient::new_simple(
                url::Url::parse(&url_str).unwrap(),
            )),
            Arc::clone(&cache),
            ChainPollerConfig::default(),
            tip_tx,
        );

        let processed = poller.poll_once().await.unwrap();
        assert_eq!(processed, 0);
        // Must rewind to common ancestor height 1.
        assert_eq!(cache.get_tip().unwrap().unwrap().0, 1);
        assert!(cache.get_compact_block(2).unwrap().is_none());
        assert!(cache.get_compact_block(4).unwrap().is_none());
    }

    #[tokio::test]
    async fn poll_once_keeps_transport_error_as_err_when_remote_shorter() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());

        let mut prev = [0u8; 32];
        let mut chain_a_hashes = Vec::new();
        for height in 0..=4u32 {
            let blk = make_mock_block_info(height, prev, 1000 + height as u64);
            let compact = block_processor::process_block(&blk).await.unwrap();
            prev = compact.hash;
            chain_a_hashes.push(compact.hash);
            cache.insert_compact_block(&compact).unwrap();
        }

        // Backend drops connection when asked for height 4 -> must error, NOT treat as None.
        let remote_hash_hex = blake3::Hash::from(chain_a_hashes[2]).to_hex().to_string();
        let url_str =
            spawn_mock_poller_darkfid((2, remote_hash_hex), Default::default(), Some(4)).await;
        let (tip_tx, _) = tokio::sync::watch::channel(4u32);
        let poller = ChainPoller::new(
            Arc::new(DarkfidRpcClient::new_simple(
                url::Url::parse(&url_str).unwrap(),
            )),
            Arc::clone(&cache),
            ChainPollerConfig::default(),
            tip_tx,
        );

        let err = poller.poll_once().await.unwrap_err();
        assert!(err.is_connection(), "expected connection error, got {err}");
        assert_eq!(cache.get_tip().unwrap().unwrap().0, 4);
    }
}
