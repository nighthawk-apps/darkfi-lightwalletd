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
use std::time::Duration;

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
            retention_window: 100_000,
            prune_interval_blocks: 10_000,
        }
    }
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
                    consecutive_failures += 1;
                    error!(
                        target: "lightwalletd::chain_poller",
                        "Poll failed (attempt {consecutive_failures}): {e}"
                    );
                }
            }

            let sleep_secs = self.backoff_interval(consecutive_failures);
            debug!(
                target: "lightwalletd::chain_poller",
                "Sleeping {sleep_secs}s before next poll"
            );
            smol::Timer::after(Duration::from_secs(sleep_secs)).await;
        }
    }

    /// Perform a single poll cycle:
    /// 1. Get chain tip from darkfid
    /// 2. Compare to cached tip
    /// 3. Fetch and process any new blocks
    /// 4. Detect reorgs
    ///
    /// Returns the number of blocks processed.
    async fn poll_once(&self) -> Result<u32> {
        // Get current chain tip from darkfid
        let (remote_height, remote_hash) = self.rpc_client.get_last_confirmed_block().await?;

        // Get our cached tip
        let cached_tip = self.cache.get_tip()?;
        let cached_height = cached_tip.map(|(h, _)| h).unwrap_or(0);

        // darkfid restarted on fresh DB, wrong network, or operator reset:
        // remote tip can be *below* our cache — must rewind or clients see a stale tip.
        if remote_height < cached_height {
            warn!(
                target: "lightwalletd::chain_poller",
                "Tip regression: darkfid tip {remote_height} < cache tip {cached_height}; rewinding cache"
            );
            return self.handle_reorg(remote_height).await;
        }

        if cached_height >= remote_height {
            // Check for reorg at tip
            if let Some((_, cached_hash)) = cached_tip {
                let remote_hash_bytes: [u8; 32] = match blake3::Hash::from_hex(&remote_hash) {
                    Ok(h) => *h.as_bytes(),
                    Err(e) => {
                        return Err(crate::error::LightWalletError::RpcError(format!(
                            "invalid tip hash from darkfid: {e}"
                        )));
                    }
                };
                if cached_hash != remote_hash_bytes && cached_height == remote_height {
                    warn!(
                        target: "lightwalletd::chain_poller",
                        "Reorg detected at height {cached_height}: hash mismatch"
                    );
                    return self.handle_reorg(cached_height).await;
                }
            }
            return Ok(0);
        }

        // Fetch new blocks from cached_height+1 to remote_height (capped by batch_size)
        let start = cached_height + 1;
        let end = std::cmp::min(start + self.config.batch_size - 1, remote_height);

        debug!(
            target: "lightwalletd::chain_poller",
            "Fetching blocks {start}..={end} (remote tip: {remote_height})"
        );

        let mut blocks_processed: u32 = 0;

        for height in start..=end {
            let block_info = self.rpc_client.get_block(height).await?;

            // Verify chain continuity (reorg detection)
            if height > 0 {
                let prev_hash = *block_info.header.previous.inner();
                if let Some(cached_prev_hash) = self.cache.get_block_hash(height - 1)? {
                    if prev_hash != cached_prev_hash {
                        warn!(
                            target: "lightwalletd::chain_poller",
                            "Reorg detected at height {height}: prev_hash mismatch"
                        );
                        return self.handle_reorg(height - 1).await;
                    }
                }
            }

            // Process block into compact format
            let compact_block = block_processor::process_block(&block_info).await?;

            // Insert into cache
            self.cache.insert_compact_block(&compact_block)?;

            blocks_processed += 1;
        }

        // Flush cache to disk after each batch
        if blocks_processed > 0 {
            self.cache.flush()?;
            self.notify_tip();
        }

        Ok(blocks_processed)
    }

    /// Handle a chain reorganization.
    ///
    /// Strategy: walk backwards from the reorg point to find the common ancestor,
    /// then rewind the cache and re-sync.
    async fn handle_reorg(&self, reorg_height: u32) -> Result<u32> {
        // Simple strategy: rewind to the block before the reorg point
        // and let the next poll cycle re-fetch.
        let rewind_to = reorg_height.saturating_sub(10);

        warn!(
            target: "lightwalletd::chain_poller",
            "Rewinding cache from {reorg_height} to {rewind_to}"
        );

        self.cache.rewind_to_height(rewind_to)?;
        self.notify_tip();

        // Return 0 to trigger re-poll on next cycle
        Ok(0)
    }

    /// Calculate backoff interval with exponential growth.
    fn backoff_interval(&self, failures: u32) -> u64 {
        if failures == 0 {
            return self.config.poll_interval_secs;
        }

        let backoff = self.config.poll_interval_secs * 2u64.pow(failures.min(6));
        backoff.min(self.config.max_backoff_secs)
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
        let (tip_tx, _) = tokio::sync::watch::channel(0u32);
        let poller = ChainPoller {
            rpc_client: Arc::new(DarkfidRpcClient::new_simple(
                url::Url::parse("tcp://127.0.0.1:8340").unwrap(),
            )),
            cache: Arc::new(Cache::new("/tmp/test_poller_cache").unwrap()),
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
    }
}
