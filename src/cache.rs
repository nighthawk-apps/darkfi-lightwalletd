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

//! Cache layer for the lightwallet server.
//!
//! Uses sled 0.34 to store:
//! - Compact blocks indexed by height
//! - Block hash ↔ height bidirectional index
//! - Money-tree snapshots (`merkle_snapshots`): one serialized tree every
//!   1024 blocks, plus the current tip. Prune does not delete these.
//! - Server metadata (chain tip, version)
//!
//! All data in this cache is derived from the darkfid full node and can
//! be rebuilt from scratch if corrupted or deleted.
//!
//! sled is unmaintained. A store swap (redb / kvdb-overlay) is a
//! `CACHE_FORMAT_VERSION` bump that wipes on-disk caches — operators
//! resync from darkfid. Keep sled for 0.2.1 so existing deployments
//! do not rebuild on this pin bump.

// Using bincode for compact block serialization (serde-based) to avoid
// lifetime issues with darkfi_serial's async derive macros.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::{debug, error, info, warn};

use crate::{
    compact_block::CompactBlock,
    error::{LightWalletError, Result},
};

// sled tree names
const META_TREE: &str = "lightwalletd_meta";
const COMPACT_BLOCKS_TREE: &str = "lightwalletd_compact_blocks";
const BLOCK_HASHES_TREE: &str = "lightwalletd_block_hashes";
const HASH_TO_HEIGHT_TREE: &str = "lightwalletd_hash_to_height";
const NULLIFIERS_TREE: &str = "lightwalletd_nullifiers";
const COINS_TREE: &str = "lightwalletd_coins";
/// Height (u32 big-endian) → serialized `MerkleTree`.
///
/// Disk: one tree per [`MERKLE_SNAPSHOT_INTERVAL`] blocks, plus the current
/// tip. A non-aligned previous tip is replaced when the chain advances.
const MERKLE_SNAPSHOTS_TREE: &str = "lightwalletd_merkle_snapshots";
const OMR_CLUE_HINTS_TREE: &str = "lightwalletd_omr_clue_hints";
const OMR_CLUE_HINT_META_TREE: &str = "lightwalletd_omr_clue_hint_meta";
const OMR_CLUE_PUBKEYS_TREE: &str = "lightwalletd_omr_clue_pubkeys";
const OMR_METADATA_ENC_TREE: &str = "lightwalletd_omr_metadata_enc";

/// On-disk cache layout version. Bump when compact-block bincode or tree
/// names change incompatibly. Missing key is treated as a pre-versioned
/// store and stamped in place (no wipe). A mismatch clears derived block
/// rows so the poller rebuilds them from darkfid; clue keys are kept.
///
/// 2: `CompactOutput.func_code`, DAO calls, and auth-token events.
const CACHE_FORMAT_VERSION: u32 = 2;

/// OMR clue hints expire this many seconds after they were stored (S21).
///
/// Hints are not consumed on merge, so this bounds both slow confirms and the
/// reorg window in which a rewound block can get its clue re-merged.
pub const OMR_CLUE_HINT_TTL_SECS: u64 = 86_400;
/// Full hint-meta scan period. A single expired key is still dropped on read.
const OMR_CLUE_HINT_SWEEP_SECS: u64 = 60;
/// Max opaque recipient OMR metadata size (DoS / cache bloat).
pub const MAX_OMR_METADATA_ENC_BYTES: usize = 4096;

// Meta keys
const META_TIP_HEIGHT: &[u8] = b"tip_height";
const META_TIP_HASH: &[u8] = b"tip_hash";
const META_TIP_MERKLE_TREE: &[u8] = b"tip_merkle_tree";
const META_TIP_MERKLE_HEIGHT: &[u8] = b"tip_merkle_height";
const META_CACHE_FORMAT: &[u8] = b"cache_format";
const META_CLUE_DIR_PEPPER: &[u8] = b"unifomr_clue_dir_pepper";
const META_CLUE_DIR_PEPPER_ANCHOR: &[u8] = b"unifomr_clue_dir_pepper_anchor";
const META_TIP_FETCHED_UNIX: &[u8] = b"tip_fetched_unix";
/// Height the in-progress rewind must reach. Cleared only after the tip matches.
const META_REWINDING_TO: &[u8] = b"rewinding_to";
/// `height || hash || block_target || difficulty` for the tip those facts describe.
const META_TIP_CHAIN_FACTS: &[u8] = b"tip_chain_facts";

/// Checkpoints retained in the tip Money Merkle tree (matches wallet clients).
const TIP_TREE_CHECKPOINTS: usize = 100;

/// Write a Money-tree snapshot every this many blocks, and always at the tip.
///
/// Matches the client's minimum padded bucket. Disk cost is one serialized
/// `MerkleTree` per 1024 blocks, plus the current tip (replaced in place when
/// the tip is not itself a 1024 boundary).
pub const MERKLE_SNAPSHOT_INTERVAL: u32 = 1024;

/// In-memory tip Money tree. `height` is the block this tree already includes.
struct LiveTipTree {
    height: Option<u32>,
    tree: darkfi_sdk::crypto::MerkleTree,
    /// Persisted bytes did not deserialize. The next append rebuilds from coins.
    load_failed: bool,
}

/// Cache layer backed by sled, storing compact blocks and indices.
pub struct Cache {
    /// The sled database
    db: sled::Db,
    /// Compact blocks: height (u32 big-endian) → serialized CompactBlock
    compact_blocks: sled::Tree,
    /// Block hashes: height (u32 big-endian) → hash ([u8; 32])
    block_hashes: sled::Tree,
    /// Reverse index: hash ([u8; 32]) → height (u32 big-endian)
    hash_to_height: sled::Tree,
    /// Nullifiers per height: height (u32 big-endian) → serialized Vec<[u8; 32]>
    nullifiers: sled::Tree,
    /// Coin commitments per height: height (u32 big-endian) → serialized Vec<[u8; 32]>
    coins: sled::Tree,
    /// Money-tree snapshots: height (u32 big-endian) → serialized MerkleTree.
    /// Not deleted by [`Cache::prune_below_height`].
    merkle_snapshots: sled::Tree,
    /// Pending OMR clues keyed by tx hash (32 bytes) → clue bytes
    omr_clue_hints: sled::Tree,
    /// Parallel tree: tx_hash → u64 LE unix timestamp when the hint was stored (S21).
    omr_clue_hint_meta: sled::Tree,
    /// UnifOMR clue public keys: payment_pubkey (32) → serialized pk_clue
    omr_clue_pubkeys: sled::Tree,
    /// Pending recipient-encrypted OMR metadata: tx_hash (32) → [output_index:u32 LE] || enc_bytes
    omr_metadata_enc: sled::Tree,
    /// Server metadata
    meta: sled::Tree,
    /// Live tip Money tree. Loaded from sled on open; appends mutate this
    /// instead of deserializing the tip on every block.
    tip_tree: Mutex<LiveTipTree>,
    /// Unix seconds of the last full OMR clue-hint meta scan.
    omr_hint_sweep_unix: AtomicU64,
}

impl Cache {
    /// Open or create a cache database at the given path.
    pub fn new(path: &str) -> Result<Self> {
        info!(target: "lightwalletd::cache", "Opening cache database at {path}");

        let db = sled::open(path).map_err(|e| {
            LightWalletError::CacheError(format!("Failed to open sled database at {path}: {e}"))
        })?;

        let compact_blocks = db.open_tree(COMPACT_BLOCKS_TREE)?;
        let block_hashes = db.open_tree(BLOCK_HASHES_TREE)?;
        let hash_to_height = db.open_tree(HASH_TO_HEIGHT_TREE)?;
        let nullifiers = db.open_tree(NULLIFIERS_TREE)?;
        let coins = db.open_tree(COINS_TREE)?;
        let merkle_snapshots = db.open_tree(MERKLE_SNAPSHOTS_TREE)?;
        let omr_clue_hints = db.open_tree(OMR_CLUE_HINTS_TREE)?;
        let omr_clue_hint_meta = db.open_tree(OMR_CLUE_HINT_META_TREE)?;
        let omr_clue_pubkeys = db.open_tree(OMR_CLUE_PUBKEYS_TREE)?;
        let omr_metadata_enc = db.open_tree(OMR_METADATA_ENC_TREE)?;
        let meta = db.open_tree(META_TREE)?;

        let cache = Self {
            db,
            compact_blocks,
            block_hashes,
            hash_to_height,
            nullifiers,
            coins,
            merkle_snapshots,
            omr_clue_hints,
            omr_clue_hint_meta,
            omr_clue_pubkeys,
            omr_metadata_enc,
            meta,
            tip_tree: Mutex::new(LiveTipTree {
                height: None,
                tree: Self::empty_tip_tree(),
                load_failed: false,
            }),
            omr_hint_sweep_unix: AtomicU64::new(0),
        };
        cache.retire_obsolete_names()?;
        cache.ensure_cache_format()?;
        cache.verify_tip_readable()?;
        // Old caches have the tip tree only in META. Index it so checkpoint
        // reads see a snapshot before the next block arrives. Missing interval
        // rows appear as later heights are appended or the tip is rebuilt.
        cache.index_existing_tip_snapshot()?;
        // Restart must append to the persisted tip, not an empty sentinel.
        cache.load_live_tip_from_disk()?;
        // Best-effort prune of orphan hints left from previous runs (S21).
        let _ = cache.prune_expired_omr_clue_hints();
        Ok(cache)
    }

    /// Drop sled names left behind when trees and meta keys lost their
    /// `_v1` / `_v2` suffixes. The weak Pcg32 attestation key is deleted.
    /// The CSPRNG attestation key and the decoy pepper are copied forward
    /// once, then the old rows are removed. Safe to run on every open.
    fn retire_obsolete_names(&self) -> Result<()> {
        const OLD_ATTEST_V1: &[u8] = b"unifomr_dir_attest_sk_v1";
        const OLD_ATTEST_V2: &[u8] = b"unifomr_dir_attest_sk_v2";
        const ATTEST: &[u8] = b"unifomr_dir_attest_sk";
        const OLD_PEPPER: &[u8] = b"unifomr_clue_dir_pepper_v1";
        const OLD_CLUE_TREE: &str = "lightwalletd_omr_clue_pubkeys_v2";
        const OLD_CLUE_TREE_V1: &str = "lightwalletd_omr_clue_pubkeys_v1";

        let attest_missing = match self.meta.get(ATTEST)? {
            Some(bytes) if bytes.len() == 32 => false,
            _ => true,
        };
        if attest_missing {
            if let Some(old) = self.meta.get(OLD_ATTEST_V2)? {
                if old.len() == 32 {
                    self.meta.insert(ATTEST, old.as_ref())?;
                }
            }
        }
        self.meta.remove(OLD_ATTEST_V1)?;
        self.meta.remove(OLD_ATTEST_V2)?;

        let pepper_missing = match self.meta.get(META_CLUE_DIR_PEPPER)? {
            Some(bytes) if bytes.len() == 32 => false,
            _ => true,
        };
        if pepper_missing {
            if let Some(old) = self.meta.get(OLD_PEPPER)? {
                if old.len() == 32 {
                    self.meta.insert(META_CLUE_DIR_PEPPER, old.as_ref())?;
                }
            }
        }
        self.meta.remove(OLD_PEPPER)?;
        self.meta.remove(META_CLUE_DIR_PEPPER_ANCHOR)?;
        self.meta.remove(b"unifomr_clue_dir_pepper_anchor_v1")?;

        if self.tree_exists(OLD_CLUE_TREE) {
            let old = self.db.open_tree(OLD_CLUE_TREE)?;
            for item in old.iter() {
                let (key, value) = item?;
                if self.omr_clue_pubkeys.get(key.as_ref())?.is_none() {
                    self.omr_clue_pubkeys.insert(key, value)?;
                }
            }
            drop(old);
            self.db.drop_tree(OLD_CLUE_TREE)?;
        }
        if self.tree_exists(OLD_CLUE_TREE_V1) {
            self.db.drop_tree(OLD_CLUE_TREE_V1)?;
        }
        Ok(())
    }

    fn tree_exists(&self, name: &str) -> bool {
        self.db
            .tree_names()
            .iter()
            .any(|existing| existing.as_ref() == name.as_bytes())
    }

    /// Drop compact blocks and the indexes rebuilt from them.
    ///
    /// Clue registrations and the directory attestation key stay. The poller
    /// refills blocks from darkfid.
    fn clear_derived_block_cache(&self) -> Result<()> {
        use darkfi_sdk::crypto::MerkleTree;
        fn io(e: sled::Error) -> LightWalletError {
            LightWalletError::CacheError(format!("clear derived cache: {e}"))
        }
        self.compact_blocks.clear().map_err(io)?;
        self.block_hashes.clear().map_err(io)?;
        self.hash_to_height.clear().map_err(io)?;
        self.nullifiers.clear().map_err(io)?;
        self.coins.clear().map_err(io)?;
        self.merkle_snapshots.clear().map_err(io)?;
        self.meta.remove(META_TIP_HEIGHT).map_err(io)?;
        self.meta.remove(META_TIP_HASH).map_err(io)?;
        self.meta.remove(META_TIP_MERKLE_TREE).map_err(io)?;
        self.meta.remove(META_TIP_MERKLE_HEIGHT).map_err(io)?;
        if let Ok(mut tip) = self.tip_tree.lock() {
            tip.height = None;
            tip.tree = MerkleTree::new(TIP_TREE_CHECKPOINTS);
            tip.load_failed = false;
        }
        Ok(())
    }

    fn ensure_cache_format(&self) -> Result<()> {
        match self.meta.get(META_CACHE_FORMAT)? {
            None => {
                self.meta
                    .insert(META_CACHE_FORMAT, &CACHE_FORMAT_VERSION.to_be_bytes())?;
                Ok(())
            }
            Some(bytes) => {
                let found = if bytes.len() == 4 {
                    u32::from_be_bytes(bytes.as_ref().try_into().unwrap_or([0; 4]))
                } else {
                    0
                };
                if found != CACHE_FORMAT_VERSION {
                    warn!(
                        target: "lightwalletd::cache",
                        "Cache format {found} != {CACHE_FORMAT_VERSION}; clearing derived \
                         compact blocks so they rebuild with DAO calls and func_code"
                    );
                    self.clear_derived_block_cache()?;
                    self.meta
                        .insert(META_CACHE_FORMAT, &CACHE_FORMAT_VERSION.to_be_bytes())?;
                }
                Ok(())
            }
        }
    }

    fn verify_tip_readable(&self) -> Result<()> {
        // zcash/lightwalletd applies a reorg inside one database transaction.
        // Sled writes here span trees, so a crash mid-rewind leaves a marker
        // and the next open finishes the same rewind.
        if let Some(target) = self.rewind_marker()? {
            warn!(
                target: "lightwalletd::cache",
                "Resuming interrupted rewind to height {target}"
            );
            return self.rewind_to_height(target);
        }
        let Some((height, _)) = self.get_tip()? else {
            return Ok(());
        };
        match self.get_compact_block(height) {
            Ok(Some(_)) => Ok(()),
            Ok(None) => {
                warn!(
                    target: "lightwalletd::cache",
                    "Tip height {height} has no compact block; repairing tip"
                );
                self.repair_missing_tip(height)
            }
            Err(e) => {
                error!(
                    target: "lightwalletd::cache",
                    "Tip compact block at {height} is unreadable; delete the cache directory and resync"
                );
                Err(e)
            }
        }
    }

    fn rewind_marker(&self) -> Result<Option<u32>> {
        let Some(bytes) = self.meta.get(META_REWINDING_TO)? else {
            return Ok(None);
        };
        if bytes.len() != 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_be_bytes(bytes.as_ref().try_into().unwrap())))
    }

    /// Point the tip at the highest compact block that is still on disk.
    fn repair_missing_tip(&self, recorded: u32) -> Result<()> {
        let end = recorded.to_be_bytes();
        let highest = self.compact_blocks.range(..=end).next_back().transpose()?;
        if let Some((key, _)) = highest {
            if key.len() == 4 {
                let height = u32::from_be_bytes(key.as_ref().try_into().unwrap());
                return self.rewind_to_height(height);
            }
        }
        self.meta.remove(META_TIP_HEIGHT)?;
        self.meta.remove(META_TIP_HASH)?;
        self.meta.remove(META_REWINDING_TO)?;
        self.db.flush()?;
        Ok(())
    }

    /// Insert a compact block into the cache.
    ///
    /// Also updates:
    /// - block_hashes: height → hash
    /// - hash_to_height: hash → height
    /// - nullifiers: height → nullifiers in this block
    /// - coins: height → coin commitments in this block
    /// - meta: tip_height, tip_hash
    ///
    /// Sender-registered FHE OMR clues (keyed by tx hash) are merged into
    /// `CompactOutput.omr_clue` before persistence.
    pub fn insert_compact_block(&self, block: &CompactBlock) -> Result<()> {
        let mut block = block.clone();
        self.apply_omr_clue_hints(&mut block)?;

        let height_key = block.height.to_be_bytes();

        // Store the compact block
        self.compact_blocks.insert(
            height_key,
            bincode::serialize(&block).map_err(|e| {
                LightWalletError::SerializationError(format!(
                    "Failed to serialize compact block: {e}"
                ))
            })?,
        )?;

        // Store height → hash
        self.block_hashes.insert(height_key, &block.hash)?;

        // Store hash → height
        self.hash_to_height
            .insert(block.hash, height_key.as_ref())?;

        // Extract and store nullifiers
        let all_nullifiers: Vec<[u8; 32]> = block
            .txs
            .iter()
            .flat_map(|tx| tx.nullifiers.iter().copied())
            .collect();
        if !all_nullifiers.is_empty() {
            self.nullifiers.insert(
                height_key,
                bincode::serialize(&all_nullifiers).map_err(|e| {
                    LightWalletError::SerializationError(format!(
                        "Failed to serialize nullifiers: {e}"
                    ))
                })?,
            )?;
        }

        // Extract and store coin commitments
        let all_coins: Vec<[u8; 32]> = block
            .txs
            .iter()
            .flat_map(|tx| tx.outputs.iter().map(|o| o.coin))
            .collect();
        if !all_coins.is_empty() {
            self.coins.insert(
                height_key,
                bincode::serialize(&all_coins).map_err(|e| {
                    LightWalletError::SerializationError(format!("Failed to serialize coins: {e}"))
                })?,
            )?;
        }

        // Historical backfill (e.g. missing genesis after a birthday import)
        // must not rewind META_TIP or append coins at the end of the live tree.
        if let Some((tip_h, _)) = self.get_tip()? {
            if block.height < tip_h {
                debug!(
                    target: "lightwalletd::cache",
                    "Cached historical compact block at height {} (tip stays {tip_h})",
                    block.height
                );
                // Snapshots at or above this height were built without these coins.
                self.delete_snapshots_at_or_above(block.height)?;
                self.rebuild_tip_merkle_tree(tip_h)?;
                return Ok(());
            }
        }

        // Update chain tip
        self.meta.insert(META_TIP_HEIGHT, &height_key)?;
        self.meta.insert(META_TIP_HASH, &block.hash)?;

        // Append coins to tip Merkle tree (tx / output order).
        self.append_coins_to_tip_tree(block.height, &all_coins)?;

        debug!(
            target: "lightwalletd::cache",
            "Cached compact block at height {} ({} txs, {} outputs, {} nullifiers)",
            block.height,
            block.txs.len(),
            all_coins.len(),
            all_nullifiers.len(),
        );

        Ok(())
    }

    /// Store a sender-supplied FHE OMR clue for a pending transaction.
    ///
    /// Optional `output_index`: when `Some(i)`, the clue is applied only to
    /// output `i` of the matching tx (S20). When `None`, it applies to the
    /// first empty output only (not every empty output).
    pub fn store_omr_clue_hint(
        &self,
        tx_hash: &[u8; 32],
        clue: Vec<u8>,
        output_index: Option<u32>,
    ) -> Result<()> {
        if clue.is_empty() {
            return Ok(());
        }
        self.prune_expired_omr_clue_hints()?;
        self.drop_omr_clue_hint_if_expired(tx_hash)?;

        let mut clues = match self.omr_clue_hints.get(tx_hash.as_slice())? {
            Some(bytes) => decode_omr_clue_hints(&bytes),
            None => Vec::new(),
        };
        // First writer wins per output index. A second clue for the same
        // index is ignored so a payment clue cannot be replaced by change.
        if clues.iter().any(|(idx, _)| *idx == output_index) {
            return Ok(());
        }
        clues.push((output_index, clue.clone()));
        let stored = encode_omr_clue_hints(&clues);
        self.omr_clue_hints
            .insert(tx_hash.as_slice(), stored.as_slice())?;
        let now = omr_hint_unix_now();
        self.omr_clue_hint_meta
            .insert(tx_hash.as_slice(), &now.to_le_bytes())?;
        // Avoid per-hint sled.flush (P8); callers / insert_compact_block flush.
        debug!(
            target: "lightwalletd::cache",
            "Stored OMR clue hint for tx {} ({} bytes, output_index={:?})",
            hex::encode(tx_hash),
            clue.len(),
            output_index,
        );
        Ok(())
    }

    /// Store recipient-encrypted OMR metadata for a pending transaction.
    ///
    /// Uses the same output_index + data wire format as `store_omr_clue_hint`.
    /// LWD cannot decrypt this — it's encrypted with the recipient's pubkey.
    pub fn store_omr_metadata_enc(
        &self,
        tx_hash: &[u8; 32],
        metadata_enc: Vec<u8>,
        output_index: Option<u32>,
    ) -> Result<()> {
        if metadata_enc.is_empty() {
            return Ok(());
        }
        if metadata_enc.len() > MAX_OMR_METADATA_ENC_BYTES {
            return Err(LightWalletError::CacheError(format!(
                "omr_metadata_enc too large: {} bytes (max {MAX_OMR_METADATA_ENC_BYTES})",
                metadata_enc.len()
            )));
        }
        let mut stored = Vec::with_capacity(4 + metadata_enc.len());
        let idx = output_index.unwrap_or(u32::MAX);
        stored.extend_from_slice(&idx.to_le_bytes());
        stored.extend_from_slice(&metadata_enc);
        self.omr_metadata_enc
            .insert(tx_hash.as_slice(), stored.as_slice())?;
        debug!(
            target: "lightwalletd::cache",
            "Stored OMR metadata_enc for tx {} ({} bytes, output_index={:?})",
            hex::encode(tx_hash),
            metadata_enc.len(),
            output_index,
        );
        Ok(())
    }

    /// True if recipient-encrypted OMR metadata is already stored for this tx.
    pub fn has_omr_metadata_enc(&self, tx_hash: &[u8; 32]) -> Result<bool> {
        Ok(self.omr_metadata_enc.contains_key(tx_hash.as_slice())?)
    }

    /// True if a clue hint is already stored for this tx (e.g. from SendTransaction).
    ///
    /// The full meta scan is throttled. This key is still dropped if it is expired.
    pub fn has_omr_clue_hint(&self, tx_hash: &[u8; 32]) -> Result<bool> {
        self.prune_expired_omr_clue_hints()?;
        if self.drop_omr_clue_hint_if_expired(tx_hash)? {
            return Ok(false);
        }
        Ok(self.omr_clue_hints.contains_key(tx_hash.as_slice())?)
    }

    /// True when a clue is already stored for this tx and output index.
    pub fn omr_clue_index_taken(&self, tx_hash: &[u8; 32], output_index: u32) -> Result<bool> {
        self.prune_expired_omr_clue_hints()?;
        if self.drop_omr_clue_hint_if_expired(tx_hash)? {
            return Ok(false);
        }
        let Some(bytes) = self.omr_clue_hints.get(tx_hash.as_slice())? else {
            return Ok(false);
        };
        Ok(decode_omr_clue_hints(&bytes)
            .into_iter()
            .any(|(idx, _)| idx == Some(output_index)))
    }

    /// Drop a clue hint (e.g. its transaction was rejected by darkfid).
    pub fn remove_omr_clue_hint(&self, tx_hash: &[u8; 32]) -> Result<()> {
        self.omr_clue_hints.remove(tx_hash.as_slice())?;
        self.omr_clue_hint_meta.remove(tx_hash.as_slice())?;
        Ok(())
    }

    /// Store UnifOMR clue public key + ownership proof for a payment pubkey.
    ///
    /// Value: `key_version u64 LE || proof_len u32 LE || ownership_proof || clue_pk`.
    ///
    /// Monotonic anti-replay: a lower `key_version` is rejected. An equal
    /// version replaces the proof only when the clue public key is unchanged
    /// (Schnorr proofs are randomized). A different clue key at the same
    /// version is rejected. A higher version replaces the row. `0` is rejected.
    pub fn store_clue_public_key(
        &self,
        payment_pubkey: &[u8; 32],
        clue_pk: &[u8],
        key_version: u64,
        ownership_proof: &[u8],
    ) -> Result<()> {
        // n=1024 → 4 + 16*1024 = 16388 bytes; leave headroom for future params.
        if clue_pk.is_empty() || clue_pk.len() > 65_536 {
            return Err(LightWalletError::CacheError(
                "invalid clue public key size".into(),
            ));
        }
        if ownership_proof.is_empty() || ownership_proof.len() > 65_536 {
            return Err(LightWalletError::CacheError(
                "invalid ownership proof size".into(),
            ));
        }
        if key_version == 0 {
            return Err(LightWalletError::CacheError(
                "clue key_version 0 is rejected".into(),
            ));
        }
        if let Some(existing) = self.omr_clue_pubkeys.get(payment_pubkey.as_slice())? {
            if let Some((stored_version, _stored_proof, stored_clue)) =
                Self::parse_clue_pubkey_value(&existing)
            {
                if key_version < stored_version {
                    return Err(LightWalletError::CacheError(format!(
                        "stale clue registration: key_version {key_version} < registered {stored_version}"
                    )));
                }
                if key_version == stored_version && stored_clue.as_slice() != clue_pk {
                    return Err(LightWalletError::CacheError(
                        "clue public key already registered at this key_version".into(),
                    ));
                }
            }
        }
        let mut value = Vec::with_capacity(8 + 4 + ownership_proof.len() + clue_pk.len());
        value.extend_from_slice(&key_version.to_le_bytes());
        value.extend_from_slice(&(ownership_proof.len() as u32).to_le_bytes());
        value.extend_from_slice(ownership_proof);
        value.extend_from_slice(clue_pk);
        self.omr_clue_pubkeys
            .insert(payment_pubkey.as_slice(), value)?;
        Ok(())
    }

    /// Parse stored clue-directory value → `(key_version, ownership_proof, clue_pk)`.
    ///
    /// Format: `key_version u64 LE || proof_len u32 LE || proof || clue_pk`.
    /// Older rows may start with the `b"v3"` tag; those bytes are skipped.
    fn parse_clue_pubkey_value(v: &[u8]) -> Option<(u64, Vec<u8>, Vec<u8>)> {
        let v = if v.len() >= 2 && &v[..2] == b"v3" {
            &v[2..]
        } else {
            v
        };
        if v.len() < 8 + 4 {
            return None;
        }
        let key_version = u64::from_le_bytes(v[0..8].try_into().ok()?);
        let proof_len = u32::from_le_bytes(v[8..12].try_into().ok()?) as usize;
        if 12 + proof_len > v.len() {
            return None;
        }
        let proof = v[12..12 + proof_len].to_vec();
        let clue = v[12 + proof_len..].to_vec();
        if clue.is_empty() || proof.is_empty() {
            return None;
        }
        Some((key_version, proof, clue))
    }

    /// Lookup UnifOMR clue public key by payment pubkey.
    pub fn get_clue_public_key(&self, payment_pubkey: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .omr_clue_pubkeys
            .get(payment_pubkey.as_slice())?
            .and_then(|v| Self::parse_clue_pubkey_value(&v).map(|(_, _, clue)| clue)))
    }

    /// Lookup clue PK + ownership proof + key_version.
    pub fn get_clue_public_key_entry(
        &self,
        payment_pubkey: &[u8; 32],
    ) -> Result<Option<(u64, Vec<u8>, Vec<u8>)>> {
        Ok(self
            .omr_clue_pubkeys
            .get(payment_pubkey.as_slice())?
            .and_then(|v| Self::parse_clue_pubkey_value(&v)))
    }

    /// Stable server pepper for clue-directory decoys (hides registration bit).
    pub fn get_or_create_clue_dir_pepper(&self) -> Result<[u8; 32]> {
        if let Some(existing) = self.meta.get(META_CLUE_DIR_PEPPER)? {
            if existing.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&existing);
                return Ok(out);
            }
        }
        let mut pepper = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut pepper);
        let current = self.meta.get(META_CLUE_DIR_PEPPER)?;
        match self
            .meta
            .compare_and_swap(META_CLUE_DIR_PEPPER, current, Some(pepper.as_slice()))?
        {
            Ok(()) => Ok(pepper),
            // A concurrent first lookup won; use its pepper.
            Err(_) => self.get_or_create_clue_dir_pepper(),
        }
    }

    /// Stable lightwalletd SecretKey used to attest `GetCluePublicKey` entries.
    ///
    /// Persisted in sled meta so a restart does not rotate the advertised
    /// `GetLightInfo.directory_attest_pubkey`. Real and decoy lookups are
    /// signed with the same key so Schnorr-verify does not leak registration.
    pub fn get_or_create_directory_attest_secret(&self) -> Result<darkfi_sdk::crypto::SecretKey> {
        use darkfi_sdk::crypto::SecretKey;
        use darkfi_sdk::pasta::group::ff::PrimeField;
        const KEY: &[u8] = b"unifomr_dir_attest_sk";
        let current = self.meta.get(KEY)?;
        if let Some(existing) = current.as_ref() {
            if existing.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(existing);
                return SecretKey::from_bytes(out).map_err(|e| {
                    LightWalletError::CacheError(format!("invalid directory attest secret: {e}"))
                });
            }
        }
        let sk = loop {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
            if let Ok(sk) = SecretKey::from_bytes(bytes) {
                break sk;
            }
        };
        // Same compare-and-swap as the clue-directory pepper: two cold starts
        // must not each publish a different attestation key.
        let repr = sk.inner().to_repr();
        match self
            .meta
            .compare_and_swap(KEY, current, Some(repr.as_slice()))?
        {
            Ok(()) => Ok(sk),
            Err(_) => self.get_or_create_directory_attest_secret(),
        }
    }

    /// 32-byte directory attest public key advertised in `GetLightInfo`.
    pub fn directory_attest_public_key(&self) -> Result<[u8; 32]> {
        let sk = self.get_or_create_directory_attest_secret()?;
        Ok(darkfi_sdk::crypto::PublicKey::from_secret(sk).to_bytes())
    }

    /// Drop orphan OMR clue hints older than [`OMR_CLUE_HINT_TTL_SECS`] (S21).
    ///
    /// The full meta-tree scan runs at most once per 60s. A read of one tx
    /// hash still drops that entry when it is expired.
    pub fn prune_expired_omr_clue_hints(&self) -> Result<()> {
        let now = omr_hint_unix_now();
        let prev = self.omr_hint_sweep_unix.load(Ordering::Relaxed);
        if prev != 0 && now.saturating_sub(prev) < OMR_CLUE_HINT_SWEEP_SECS {
            return Ok(());
        }
        if self
            .omr_hint_sweep_unix
            .compare_exchange(prev, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return Ok(());
        }
        if let Err(e) = self.sweep_expired_omr_clue_hints_at(now) {
            let _ = self.omr_hint_sweep_unix.compare_exchange(
                now,
                prev,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
            return Err(e);
        }
        Ok(())
    }

    fn sweep_expired_omr_clue_hints_at(&self, now: u64) -> Result<()> {
        let mut expired = Vec::new();
        for item in self.omr_clue_hint_meta.iter() {
            let (key, value) = item?;
            if omr_hint_meta_expired(value.as_ref(), now) {
                expired.push(key.to_vec());
            }
        }
        for key in expired {
            self.omr_clue_hints.remove(key.as_slice())?;
            self.omr_clue_hint_meta.remove(key.as_slice())?;
        }
        Ok(())
    }

    /// Drop this tx's hint when its meta row is expired. Does not scan the tree.
    fn drop_omr_clue_hint_if_expired(&self, tx_hash: &[u8; 32]) -> Result<bool> {
        let Some(value) = self.omr_clue_hint_meta.get(tx_hash.as_slice())? else {
            return Ok(false);
        };
        if !omr_hint_meta_expired(value.as_ref(), omr_hint_unix_now()) {
            return Ok(false);
        }
        self.omr_clue_hints.remove(tx_hash.as_slice())?;
        self.omr_clue_hint_meta.remove(tx_hash.as_slice())?;
        Ok(true)
    }

    /// Merge pending OMR clues into compact block outputs.
    ///
    /// S20: apply each stored clue to the output index it names.
    ///
    /// Hints are kept until [`OMR_CLUE_HINT_TTL_SECS`] expiry rather than
    /// consumed: a reorg rewinds the block and darkfid re-serves it with empty
    /// clues, so the hint must still be there to re-merge. Merging is
    /// idempotent per output. Named indexes each receive their hint, even when
    /// the ciphertext bytes match (change and fee clues are the same RLWE
    /// public key). An unindexed hint still fills only the first empty output.
    pub fn apply_omr_clue_hints(&self, block: &mut CompactBlock) -> Result<()> {
        for tx in &mut block.txs {
            let tx_hash: [u8; 32] = tx.tx_hash;

            // Merge FHE clues, one per output index. An expired hint for this
            // tx is dropped here without scanning the rest of the meta tree.
            if !self.drop_omr_clue_hint_if_expired(&tx_hash)? {
                if let Some(stored_bytes) = self.omr_clue_hints.get(tx_hash.as_slice())? {
                    let clues = decode_omr_clue_hints(&stored_bytes);
                    if clues.is_empty() || clues.iter().all(|(_, c)| c.is_empty()) {
                        self.omr_clue_hints.remove(tx_hash.as_slice())?;
                        self.omr_clue_hint_meta.remove(tx_hash.as_slice())?;
                    } else {
                        for (output_index, clue) in clues {
                            if clue.is_empty() {
                                continue;
                            }
                            // Unindexed hints must not be stamped onto every
                            // empty output. Named indexes are independent:
                            // identical clue bytes still belong on each one.
                            if output_index.is_none()
                                && tx.outputs.iter().any(|o| o.omr_clue == clue)
                            {
                                continue;
                            }
                            let target = match output_index {
                                Some(idx) => tx.outputs.get_mut(idx as usize),
                                None => tx.outputs.iter_mut().find(|o| o.omr_clue.is_empty()),
                            };
                            if let Some(output) = target {
                                if output.omr_clue.is_empty() {
                                    output.omr_clue = clue;
                                }
                            }
                        }
                    }
                }
            }

            // Merge recipient-encrypted OMR metadata (same index logic)
            if let Some(stored_meta) = self.omr_metadata_enc.get(tx_hash.as_slice())? {
                let (output_index, meta_enc) = parse_stored_omr_clue_hint(&stored_meta);
                if !meta_enc.is_empty() {
                    if let Some(idx) = output_index {
                        if let Some(output) = tx.outputs.get_mut(idx as usize) {
                            if output.omr_metadata_enc.is_empty() {
                                output.omr_metadata_enc = meta_enc;
                            }
                        }
                    } else {
                        if let Some(output) = tx
                            .outputs
                            .iter_mut()
                            .find(|o| o.omr_metadata_enc.is_empty())
                        {
                            output.omr_metadata_enc = meta_enc;
                        }
                    }
                }
                self.omr_metadata_enc.remove(tx_hash.as_slice())?;
            }
        }
        Ok(())
    }

    /// Retrieve a compact block by height.
    pub fn get_compact_block(&self, height: u32) -> Result<Option<CompactBlock>> {
        let height_key = height.to_be_bytes();
        match self.compact_blocks.get(height_key)? {
            Some(bytes) => {
                let block: CompactBlock = bincode::deserialize(&bytes).map_err(|e| {
                    LightWalletError::SerializationError(format!(
                        "Failed to deserialize compact block at {height}: {e}"
                    ))
                })?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Retrieve compact blocks for a range of heights [start, end] inclusive.
    pub fn get_compact_blocks_range(&self, start: u32, end: u32) -> Result<Vec<CompactBlock>> {
        if start > end {
            return Err(LightWalletError::InvalidBlockRange(start, end));
        }

        let span = ((end as u64).saturating_sub(start as u64).saturating_add(1)).min(10_000);
        let mut blocks = Vec::with_capacity(span as usize);
        let start_key = start.to_be_bytes();
        let end_key = end.to_be_bytes();

        for item in self.compact_blocks.range(start_key..=end_key) {
            let (_, value) = item?;
            let block: CompactBlock = bincode::deserialize(&value).map_err(|e| {
                LightWalletError::SerializationError(format!(
                    "Failed to deserialize compact block: {e}"
                ))
            })?;
            blocks.push(block);
        }

        Ok(blocks)
    }

    /// First height in `start..=last` that has no block hash.
    ///
    /// One ranged scan, not a point lookup per height. `None` means every
    /// height in the span is present.
    pub fn first_missing_hash(&self, start: u32, last: u32) -> Result<Option<u32>> {
        if start > last {
            return Ok(None);
        }
        let mut expect = start;
        for item in self
            .block_hashes
            .range(start.to_be_bytes()..=last.to_be_bytes())
        {
            let (key, _) = item?;
            if key.len() != 4 {
                continue;
            }
            let height = u32::from_be_bytes(key.as_ref().try_into().unwrap());
            if height != expect {
                return Ok(Some(expect));
            }
            if expect == u32::MAX {
                return Ok(None);
            }
            expect += 1;
        }
        if expect <= last {
            Ok(Some(expect))
        } else {
            Ok(None)
        }
    }

    /// Get the hash stored for a given block height.
    pub fn get_block_hash(&self, height: u32) -> Result<Option<[u8; 32]>> {
        let height_key = height.to_be_bytes();
        match self.block_hashes.get(height_key)? {
            Some(bytes) => {
                let hash: [u8; 32] = bytes.as_ref().try_into().map_err(|_| {
                    LightWalletError::CacheError(format!("Invalid hash length at height {height}"))
                })?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Get nullifiers for a range of heights [start, end] inclusive.
    pub fn get_nullifiers_range(&self, start: u32, end: u32) -> Result<Vec<(u32, Vec<[u8; 32]>)>> {
        if start > end {
            return Err(LightWalletError::InvalidBlockRange(start, end));
        }

        let mut result = Vec::new();
        let start_key = start.to_be_bytes();
        let end_key = end.to_be_bytes();

        for item in self.nullifiers.range(start_key..=end_key) {
            let (key, value) = item?;
            let key_bytes: [u8; 4] = key.as_ref().try_into().map_err(|_| {
                LightWalletError::CacheError("Invalid key length in nullifiers tree".to_string())
            })?;
            let height = u32::from_be_bytes(key_bytes);
            let nullifiers: Vec<[u8; 32]> = bincode::deserialize(&value).map_err(|e| {
                LightWalletError::SerializationError(format!(
                    "Failed to deserialize nullifiers at {height}: {e}"
                ))
            })?;
            result.push((height, nullifiers));
        }

        Ok(result)
    }

    /// Get coin commitments for a range of heights [start, end] inclusive.
    pub fn get_coins_range(&self, start: u32, end: u32) -> Result<Vec<(u32, Vec<[u8; 32]>)>> {
        if start > end {
            return Err(LightWalletError::InvalidBlockRange(start, end));
        }

        let mut result = Vec::new();
        let start_key = start.to_be_bytes();
        let end_key = end.to_be_bytes();

        for item in self.coins.range(start_key..=end_key) {
            let (key, value) = item?;
            let key_bytes: [u8; 4] = key.as_ref().try_into().map_err(|_| {
                LightWalletError::CacheError("Invalid key length in coins tree".to_string())
            })?;
            let height = u32::from_be_bytes(key_bytes);
            let coins: Vec<[u8; 32]> = bincode::deserialize(&value).map_err(|e| {
                LightWalletError::SerializationError(format!(
                    "Failed to deserialize coins at {height}: {e}"
                ))
            })?;
            result.push((height, coins));
        }

        Ok(result)
    }

    /// Get the current cached chain tip.
    pub fn get_tip(&self) -> Result<Option<(u32, [u8; 32])>> {
        let height = match self.meta.get(META_TIP_HEIGHT)? {
            Some(bytes) => {
                let key_bytes: [u8; 4] = bytes.as_ref().try_into().map_err(|_| {
                    LightWalletError::CacheError("Invalid tip height bytes".to_string())
                })?;
                u32::from_be_bytes(key_bytes)
            }
            None => return Ok(None),
        };

        let hash = match self.meta.get(META_TIP_HASH)? {
            Some(bytes) => {
                let hash: [u8; 32] = bytes.as_ref().try_into().map_err(|_| {
                    LightWalletError::CacheError("Invalid tip hash bytes".to_string())
                })?;
                hash
            }
            None => return Ok(None),
        };

        Ok(Some((height, hash)))
    }

    /// Unix seconds of the last successful darkfid tip poll. `0` if none yet.
    pub fn set_tip_fetched_unix(&self, unix: u64) -> Result<()> {
        self.meta
            .insert(META_TIP_FETCHED_UNIX, &unix.to_le_bytes())?;
        Ok(())
    }

    /// Block target and difficulty for one tip.
    ///
    /// One meta value, so a reader cannot pair this tip's target with the
    /// previous tip's difficulty. `GetLightInfo` uses it instead of fan-out
    /// to darkfid.
    pub fn set_tip_chain_facts(
        &self,
        height: u32,
        hash: &[u8; 32],
        block_target: u32,
        difficulty: &str,
    ) -> Result<()> {
        let diff = difficulty.as_bytes();
        let mut blob = Vec::with_capacity(40 + diff.len());
        blob.extend_from_slice(&height.to_be_bytes());
        blob.extend_from_slice(hash);
        blob.extend_from_slice(&block_target.to_le_bytes());
        blob.extend_from_slice(diff);
        self.meta.insert(META_TIP_CHAIN_FACTS, blob.as_slice())?;
        Ok(())
    }

    /// Facts stored for this exact tip. `None` if missing or written for another.
    pub fn tip_chain_facts_for(
        &self,
        height: u32,
        hash: &[u8; 32],
    ) -> Result<Option<(u32, String)>> {
        let Some(bytes) = self.meta.get(META_TIP_CHAIN_FACTS)? else {
            return Ok(None);
        };
        if bytes.len() < 40 {
            return Ok(None);
        }
        let stored_height = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if stored_height != height || bytes[4..36] != hash[..] {
            return Ok(None);
        }
        let target = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let difficulty = std::str::from_utf8(&bytes[40..]).unwrap_or("").to_string();
        Ok(Some((target, difficulty)))
    }

    /// Unix seconds of the last successful darkfid tip poll. `0` if none yet.
    pub fn tip_fetched_unix(&self) -> Result<u64> {
        let Some(bytes) = self.meta.get(META_TIP_FETCHED_UNIX)? else {
            return Ok(0);
        };
        if bytes.len() != 8 {
            return Ok(0);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(buf))
    }

    /// Rewind the cache to the given height (inclusive).
    ///
    /// Deletes all compact blocks, hashes, nullifiers, and coins above `height`.
    /// Used during reorg handling.
    pub fn rewind_to_height(&self, height: u32) -> Result<()> {
        warn!(
            target: "lightwalletd::cache",
            "Rewinding cache to height {height}"
        );

        // Durable intent first. A crash before the tip is updated resumes here.
        self.meta.insert(META_REWINDING_TO, &height.to_be_bytes())?;
        self.db.flush()?;

        let delete_from = (height + 1).to_be_bytes();

        // Delete compact blocks above height
        let to_delete: Vec<sled::IVec> = self
            .compact_blocks
            .range(delete_from..)
            .filter_map(|r| r.ok().map(|(k, _)| k))
            .collect();

        for key in &to_delete {
            self.compact_blocks.remove(key)?;

            // Also clean up the hash index
            if let Some(hash) = self.block_hashes.remove(key)? {
                self.hash_to_height.remove(hash.as_ref())?;
            }

            // Clean up nullifiers and coins
            self.nullifiers.remove(key)?;
            self.coins.remove(key)?;
        }

        // Update tip
        if let Some(block) = self.get_compact_block(height)? {
            self.meta.insert(META_TIP_HEIGHT, &height.to_be_bytes())?;
            self.meta.insert(META_TIP_HASH, &block.hash)?;
        } else if height == 0 {
            self.meta.remove(META_TIP_HEIGHT)?;
            self.meta.remove(META_TIP_HASH)?;
        } else {
            warn!(
                target: "lightwalletd::cache",
                "Rewind target {height} has no compact block; repairing to the highest block still on disk"
            );
            return self.repair_missing_tip(height);
        }

        // Drop snapshots above the rewind point, then rebuild the tip tree
        // (and any interval snapshots still covered) from the coins that remain.
        self.delete_snapshots_above(height)?;
        self.rebuild_tip_merkle_tree(height)?;

        self.meta.remove(META_REWINDING_TO)?;
        // Flush to disk
        self.db.flush()?;

        info!(
            target: "lightwalletd::cache",
            "Cache rewound to height {height}, deleted {} entries",
            to_delete.len()
        );

        Ok(())
    }

    /// Serialized tip Money Merkle tree + height it corresponds to.
    ///
    /// This is the latest snapshot (`META_TIP_MERKLE_*`). Interval history lives
    /// in [`Self::merkle_snapshot`].
    pub fn get_tip_tree_state(&self) -> Result<Option<(u32, Vec<u8>)>> {
        let Some(height_bytes) = self.meta.get(META_TIP_MERKLE_HEIGHT)? else {
            return Ok(None);
        };
        if height_bytes.len() != 4 {
            return Ok(None);
        }
        let height = u32::from_be_bytes(height_bytes.as_ref().try_into().unwrap());
        let Some(tree_data) = self.meta.get(META_TIP_MERKLE_TREE)? else {
            return Ok(None);
        };
        Ok(Some((height, tree_data.to_vec())))
    }

    fn empty_tip_tree() -> darkfi_sdk::crypto::MerkleTree {
        use darkfi_sdk::crypto::{MerkleNode, MerkleTree};
        use darkfi_sdk::pasta::group::ff::Field;
        use darkfi_sdk::pasta::pallas;
        let mut tree = MerkleTree::new(TIP_TREE_CHECKPOINTS);
        // On-chain Money tree starts with a dummy ZERO leaf. Clients that
        // rebuild from GetNoteCommitments do the same. Without this sentinel
        // GetTreeState roots never match coin_roots.
        tree.append(MerkleNode::from(pallas::Base::ZERO));
        let _ = tree.mark();
        tree
    }

    fn coin_to_merkle_node(coin: &[u8; 32]) -> Result<darkfi_sdk::crypto::MerkleNode> {
        darkfi_sdk::crypto::MerkleNode::from_bytes(*coin).ok_or_else(|| {
            LightWalletError::SerializationError(
                "coin bytes are not a canonical pallas::Base".into(),
            )
        })
    }

    fn lock_tip_tree(&self) -> std::sync::MutexGuard<'_, LiveTipTree> {
        self.tip_tree.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Copy `META_TIP_MERKLE_*` into the in-memory tree. Missing meta keeps
    /// the empty sentinel created in [`Cache::new`].
    fn load_live_tip_from_disk(&self) -> Result<()> {
        let Some((height, bytes)) = self.get_tip_tree_state()? else {
            return Ok(());
        };
        match darkfi_serial::deserialize(&bytes) {
            Ok(tree) => {
                let mut live = self.lock_tip_tree();
                live.height = Some(height);
                live.tree = tree;
                Ok(())
            }
            Err(e) => {
                warn!(
                    target: "lightwalletd::cache",
                    "Failed to deserialize tip Merkle tree ({e}); rebuilding before the next append"
                );
                let mut live = self.lock_tip_tree();
                live.height = None;
                live.tree = Self::empty_tip_tree();
                live.load_failed = true;
                Ok(())
            }
        }
    }

    fn store_tip_tree(
        &self,
        prev_height: Option<u32>,
        height: u32,
        tree: &darkfi_sdk::crypto::MerkleTree,
    ) -> Result<()> {
        let tree_data = darkfi_serial::serialize(tree);
        self.meta
            .insert(META_TIP_MERKLE_TREE, tree_data.as_slice())?;
        self.meta
            .insert(META_TIP_MERKLE_HEIGHT, &height.to_be_bytes())?;
        // The tip keys are the latest snapshot. Also index the row so checkpoint
        // scans and interval history share one tree.
        self.record_tree_snapshot(prev_height, height, &tree_data, true)
    }

    /// Persist `tree_data` when `height` is a 1024-block boundary or the tip.
    ///
    /// A previous tip that is not on an interval boundary is removed so disk
    /// stays one serialized tree per 1024 blocks, plus the current tip.
    fn record_tree_snapshot(
        &self,
        prev_height: Option<u32>,
        height: u32,
        tree_data: &[u8],
        is_tip: bool,
    ) -> Result<()> {
        if height % MERKLE_SNAPSHOT_INTERVAL == 0 || is_tip {
            self.merkle_snapshots
                .insert(&height.to_be_bytes(), tree_data)?;
        }
        if is_tip {
            self.drop_non_interval_snapshots_except(prev_height, height)?;
        }
        Ok(())
    }

    /// Remove the previous tip row when it is not an interval boundary.
    ///
    /// One key delete. Interval snapshots and `keep` stay.
    fn drop_non_interval_snapshots_except(&self, prev: Option<u32>, keep: u32) -> Result<()> {
        let Some(prev) = prev else {
            return Ok(());
        };
        if prev != keep && prev % MERKLE_SNAPSHOT_INTERVAL != 0 {
            self.merkle_snapshots.remove(&prev.to_be_bytes())?;
        }
        Ok(())
    }

    fn delete_snapshots_above(&self, height: u32) -> Result<()> {
        let Some(start) = height.checked_add(1) else {
            return Ok(());
        };
        self.delete_snapshots_at_or_above(start)
    }

    fn delete_snapshots_at_or_above(&self, height: u32) -> Result<()> {
        let keys: Vec<sled::IVec> = self
            .merkle_snapshots
            .range(height.to_be_bytes()..)
            .filter_map(|item| item.ok().map(|(key, _)| key))
            .collect();
        for key in keys {
            self.merkle_snapshots.remove(key)?;
        }
        Ok(())
    }

    fn clear_merkle_snapshots(&self) -> Result<()> {
        let keys: Vec<sled::IVec> = self
            .merkle_snapshots
            .iter()
            .filter_map(|item| item.ok().map(|(key, _)| key))
            .collect();
        for key in keys {
            self.merkle_snapshots.remove(key)?;
        }
        Ok(())
    }

    /// If META already holds a tip tree (pre-snapshot cache), index that one row.
    fn index_existing_tip_snapshot(&self) -> Result<()> {
        let Some((height, data)) = self.get_tip_tree_state()? else {
            return Ok(());
        };
        if self.merkle_snapshots.get(height.to_be_bytes())?.is_none() {
            self.merkle_snapshots
                .insert(&height.to_be_bytes(), data.as_slice())?;
        }
        Ok(())
    }

    /// Snapshot bytes at `height`, if that row was retained.
    pub fn merkle_snapshot(&self, height: u32) -> Result<Option<Vec<u8>>> {
        Ok(self
            .merkle_snapshots
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    /// Greatest retained snapshot with height <= `height`.
    pub fn greatest_snapshot_at_or_below(&self, height: u32) -> Result<Option<(u32, Vec<u8>)>> {
        let mut range = self.merkle_snapshots.range(..=height.to_be_bytes());
        let Some(item) = range.next_back() else {
            return Ok(None);
        };
        let (key, value) = item?;
        let Some(found) = height_from_snapshot_key(key.as_ref()) else {
            return Ok(None);
        };
        if found > height {
            return Ok(None);
        }
        Ok(Some((found, value.to_vec())))
    }

    /// Latest retained snapshot. Once blocks are indexed this is the tip.
    pub fn latest_snapshot(&self) -> Result<Option<(u32, Vec<u8>)>> {
        self.greatest_snapshot_at_or_below(u32::MAX)
    }

    #[cfg(test)]
    fn snapshot_heights(&self) -> Result<Vec<u32>> {
        let mut heights = Vec::new();
        for item in self.merkle_snapshots.iter() {
            let (key, _) = item?;
            if let Some(height) = height_from_snapshot_key(key.as_ref()) {
                heights.push(height);
            }
        }
        heights.sort_unstable();
        Ok(heights)
    }

    fn append_coins_to_tip_tree(&self, height: u32, coins: &[[u8; 32]]) -> Result<()> {
        let needs_rebuild = {
            let live = self.lock_tip_tree();
            live.load_failed
                || match live.height {
                    Some(prev) => height != prev.saturating_add(1),
                    None => false,
                }
        };
        if needs_rebuild {
            // Coins for `height` are already in the coins tree. Rebuilding
            // that height would include them, so rebuild the parent and append.
            if height == 0 {
                self.rebuild_tip_merkle_tree(0)?;
                return Ok(());
            }
            self.rebuild_tip_merkle_tree(height - 1)?;
        }
        let nodes = coins
            .iter()
            .map(|coin| Self::coin_to_merkle_node(coin))
            .collect::<Result<Vec<_>>>()?;
        let mut live = self.lock_tip_tree();
        let prev_height = live.height;
        for node in nodes {
            live.tree.append(node);
        }
        // The poller inserts one block at a time, so the tree is persisted
        // here. The previous non-interval tip is one key delete, not a scan.
        if let Err(e) = self.store_tip_tree(prev_height, height, &live.tree) {
            self.reload_live_tip_locked(&mut live);
            return Err(e);
        }
        live.height = Some(height);
        live.load_failed = false;
        Ok(())
    }

    fn reload_live_tip_locked(&self, live: &mut LiveTipTree) {
        if let Ok(Some((height, bytes))) = self.get_tip_tree_state() {
            if let Ok(tree) = darkfi_serial::deserialize(&bytes) {
                live.height = Some(height);
                live.tree = tree;
                live.load_failed = false;
                return;
            }
        }
        live.height = None;
        live.tree = Self::empty_tip_tree();
        live.load_failed = true;
    }

    fn rebuild_tip_merkle_tree(&self, tip_height: u32) -> Result<()> {
        let mut live = self.lock_tip_tree();
        if tip_height == 0 && self.get_compact_block(0)?.is_none() {
            self.meta.remove(META_TIP_MERKLE_TREE)?;
            self.meta.remove(META_TIP_MERKLE_HEIGHT)?;
            self.clear_merkle_snapshots()?;
            live.height = None;
            live.tree = Self::empty_tip_tree();
            live.load_failed = false;
            return Ok(());
        }

        self.delete_snapshots_above(tip_height)?;

        let seeded = match self.greatest_snapshot_at_or_below(tip_height)? {
            Some((height, bytes)) => match darkfi_serial::deserialize(&bytes) {
                Ok(tree) => Some((height, tree)),
                Err(e) => {
                    warn!(
                        target: "lightwalletd::cache",
                        "Snapshot at {height} failed to deserialize ({e}); replaying from the sentinel"
                    );
                    None
                }
            },
            None => None,
        };

        let (seed_height, mut tree) = match seeded {
            Some((height, tree)) if height >= tip_height => {
                self.store_tip_tree(Some(height), tip_height, &tree)?;
                live.height = Some(tip_height);
                live.tree = tree;
                live.load_failed = false;
                return Ok(());
            }
            Some((height, tree)) => (Some(height), tree),
            None => (None, Self::empty_tip_tree()),
        };

        let coin_from = match seed_height {
            Some(height) => height.saturating_add(1),
            None => 0,
        };
        let ranges = if coin_from > tip_height {
            Vec::new()
        } else {
            self.get_coins_range(coin_from, tip_height)?
        };

        let mut idx = 0usize;
        let mut boundary = seed_height.unwrap_or(0);
        let mut skipped_seed = seed_height.is_some();
        loop {
            if skipped_seed {
                skipped_seed = false;
            } else {
                while idx < ranges.len() && ranges[idx].0 <= boundary {
                    for coin in &ranges[idx].1 {
                        tree.append(Self::coin_to_merkle_node(coin)?);
                    }
                    idx += 1;
                }
                if boundary % MERKLE_SNAPSHOT_INTERVAL == 0 {
                    let tree_data = darkfi_serial::serialize(&tree);
                    self.merkle_snapshots
                        .insert(&boundary.to_be_bytes(), tree_data.as_slice())?;
                }
            }
            if boundary >= tip_height {
                break;
            }
            let next = if boundary % MERKLE_SNAPSHOT_INTERVAL == 0 {
                boundary.saturating_add(MERKLE_SNAPSHOT_INTERVAL)
            } else {
                let rem = boundary % MERKLE_SNAPSHOT_INTERVAL;
                boundary.saturating_add(MERKLE_SNAPSHOT_INTERVAL - rem)
            };
            boundary = if next > tip_height { tip_height } else { next };
        }
        while idx < ranges.len() {
            for coin in &ranges[idx].1 {
                tree.append(Self::coin_to_merkle_node(coin)?);
            }
            idx += 1;
        }
        self.store_tip_tree(seed_height, tip_height, &tree)?;
        live.height = Some(tip_height);
        live.tree = tree;
        live.load_failed = false;
        Ok(())
    }

    /// Get notes for OMR detection in a range of heights [start, end] inclusive.
    ///
    /// Returns `(height, Vec<NoteForDetection>)` for **every** height in
    /// `[start, end]`, including heights with no cached block or empty
    /// outputs (empty `Vec`). Clients map FHE SIMD slots as `start + i`, so
    /// omitting empty heights would desynchronize slot index from height (S19).
    ///
    /// PRIVACY: This method returns ALL notes in the range,
    /// not filtered by any key. The filtering is done by the OMR detector
    /// using the client's detection key.
    pub fn get_encrypted_notes_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<Vec<(u32, Vec<crate::omr_detector::NoteForDetection>)>> {
        use crate::omr_detector::NoteForDetection;

        if start > end {
            return Err(LightWalletError::InvalidBlockRange(start, end));
        }
        if (end as u64).saturating_sub(start as u64).saturating_add(1) > 10_000 {
            return Err(LightWalletError::InvalidBlockRange(start, end));
        }

        let mut by_height: std::collections::BTreeMap<u32, Vec<NoteForDetection>> =
            std::collections::BTreeMap::new();
        let start_key = start.to_be_bytes();
        let end_key = end.to_be_bytes();

        for item in self.compact_blocks.range(start_key..=end_key) {
            let (key, value) = item?;
            let key_bytes: [u8; 4] = key.as_ref().try_into().map_err(|_| {
                LightWalletError::CacheError(
                    "Invalid key length in compact_blocks tree".to_string(),
                )
            })?;
            let height = u32::from_be_bytes(key_bytes);
            let block: CompactBlock = bincode::deserialize(&value).map_err(|e| {
                LightWalletError::SerializationError(format!(
                    "Failed to deserialize compact block at {height}: {e}"
                ))
            })?;

            let notes: Vec<NoteForDetection> = block
                .txs
                .iter()
                .flat_map(|tx| {
                    tx.outputs.iter().map(|o| NoteForDetection {
                        // Prefer omr_clue when present; skip cloning ciphertext
                        // for UnifOMR evaluation when the clue alone is enough.
                        encrypted_note: if o.omr_clue.is_empty() {
                            o.encrypted_note.clone()
                        } else {
                            Vec::new()
                        },
                        omr_clue: o.omr_clue.clone(),
                    })
                })
                .collect();

            by_height.insert(height, notes);
        }

        // S19: emit a slot for every height so SIMD index == height - start.
        let span = ((end as u64).saturating_sub(start as u64).saturating_add(1)).min(10_000);
        let mut result = Vec::with_capacity(span as usize);
        for height in start..=end {
            result.push((height, by_height.remove(&height).unwrap_or_default()));
        }

        Ok(result)
    }

    /// Prune compact blocks, hashes, nullifiers, and coins below `min_height`.
    ///
    /// Does **not** delete Money-tree snapshots. A pruned server can still hand
    /// a wallet a tree. Disk cost of the rows that remain: one serialized
    /// `MerkleTree` per 1024 blocks, plus the current tip.
    ///
    /// The tip metadata is NOT modified — only historical block data is removed.
    /// Clients requesting pruned heights will receive empty block responses.
    pub fn prune_below_height(&self, min_height: u32) -> Result<()> {
        if min_height == 0 {
            return Ok(());
        }

        let end_key = (min_height - 1).to_be_bytes();
        let mut pruned_count: u64 = 0;

        // Collect keys to delete (range [0, min_height-1])
        let to_delete: Vec<sled::IVec> = self
            .compact_blocks
            .range(..=end_key)
            .filter_map(|r| r.ok().map(|(k, _)| k))
            .collect();

        for key in &to_delete {
            self.compact_blocks.remove(key)?;

            if let Some(hash) = self.block_hashes.remove(key)? {
                self.hash_to_height.remove(hash.as_ref())?;
            }

            self.nullifiers.remove(key)?;
            self.coins.remove(key)?;
            pruned_count += 1;
        }

        if pruned_count > 0 {
            self.db.flush()?;
            info!(
                target: "lightwalletd::cache",
                "Pruned {pruned_count} blocks below height {min_height}"
            );
        }

        Ok(())
    }

    /// Prune blocks older than `retention_window` blocks from the current tip.
    ///
    /// For example, with `retention_window = 100_000` and tip at height 500_000,
    /// all blocks below height 400_000 will be pruned.
    ///
    /// Returns the number of blocks pruned, or 0 if the tip is within the window.
    pub fn prune_with_retention(&self, retention_window: u32) -> Result<u64> {
        let tip_height = match self.get_tip()? {
            Some((h, _)) => h,
            None => return Ok(0),
        };

        if tip_height <= retention_window {
            return Ok(0);
        }

        let min_height = tip_height - retention_window;
        self.prune_below_height(min_height)?;
        Ok(min_height as u64) // approximate
    }

    /// Flush the database to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

fn omr_hint_unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn omr_hint_meta_expired(value: &[u8], now: u64) -> bool {
    if value.len() < 8 {
        return true;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&value[..8]);
    let stored_at = u64::from_le_bytes(buf);
    now.saturating_sub(stored_at) > OMR_CLUE_HINT_TTL_SECS
}

fn height_from_snapshot_key(key: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = key.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// Stored clue hints are an `MCL1` list of `(output_index, clue)`.
const OMR_CLUE_LIST_MAGIC: &[u8; 4] = b"MCL1";

/// Length-prefixed list of `(output_index, clue)`. `u32::MAX` means first empty.
fn encode_omr_clue_hints(clues: &[(Option<u32>, Vec<u8>)]) -> Vec<u8> {
    let mut out = OMR_CLUE_LIST_MAGIC.to_vec();
    for (idx, clue) in clues {
        let i = idx.unwrap_or(u32::MAX);
        let len = u32::try_from(clue.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&i.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        let n = len as usize;
        out.extend_from_slice(&clue[..n.min(clue.len())]);
    }
    out
}

fn decode_omr_clue_hints(stored: &[u8]) -> Vec<(Option<u32>, Vec<u8>)> {
    if !stored.starts_with(OMR_CLUE_LIST_MAGIC) {
        return Vec::new();
    }
    let mut rest = &stored[4..];
    let mut out = Vec::new();
    while rest.len() >= 8 {
        let idx = u32::from_le_bytes(rest[0..4].try_into().unwrap_or([0; 4]));
        let len = u32::from_le_bytes(rest[4..8].try_into().unwrap_or([0; 4])) as usize;
        if rest.len() < 8 + len {
            break;
        }
        let clue = rest[8..8 + len].to_vec();
        rest = &rest[8 + len..];
        let index = if idx == u32::MAX { None } else { Some(idx) };
        out.push((index, clue));
    }
    out
}

fn parse_stored_omr_clue_hint(stored: &[u8]) -> (Option<u32>, Vec<u8>) {
    if stored.len() < 4 {
        return (None, Vec::new());
    }
    let idx = u32::from_le_bytes(stored[..4].try_into().unwrap_or([0; 4]));
    let clue = stored[4..].to_vec();
    if idx == u32::MAX {
        (None, clue)
    } else {
        (Some(idx), clue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact_block::{CompactBlock, CompactOutput, CompactTx};

    /// sled's db flock is released when the last tree drops, which can lag
    /// a few milliseconds behind `drop` while other tests are saturating the
    /// machine. Retry only that contention.
    fn reopen_cache(path: &str) -> Cache {
        let mut last = None;
        for _ in 0..40 {
            match Cache::new(path) {
                Ok(cache) => return cache,
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("could not acquire lock") {
                        panic!("reopen {path}: {e}");
                    }
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
        panic!("sled lock not released for {path}: {last:?}");
    }

    /// Generate a deterministic 32-byte coin value that is always a valid
    /// canonical `pallas::Base` field element.  We hash the height with
    /// blake3 and clear the top two bits so the value is < p (the pallas
    /// base-field modulus is ~2^254, so clearing bits 255+254 is sufficient).
    fn make_valid_coin(height: u32) -> [u8; 32] {
        let mut coin = *blake3::hash(&height.to_le_bytes()).as_bytes();
        coin[31] &= 0x3F; // clear top 2 bits → value < 2^254 < p
        coin
    }

    fn make_test_block(height: u32) -> CompactBlock {
        CompactBlock {
            height,
            hash: [height as u8; 32],
            prev_hash: [height.wrapping_sub(1) as u8; 32],
            timestamp: 1000 + height as u64,
            txs: vec![CompactTx {
                tx_hash: [height as u8; 32],
                outputs: vec![CompactOutput {
                    coin: make_valid_coin(height),
                    encrypted_note: vec![0xAA; 100],
                    value_commit: vec![0xBB; 33],
                    token_commit: [0xCC; 32],
                    omr_clue: vec![],
                    omr_metadata_enc: vec![],
                    func_code: 0,
                }],
                nullifiers: vec![[height as u8; 32]],
                fee: 100,
            }],
            dao_calls: vec![],
            func_events: vec![],
        }
    }

    fn make_empty_block(height: u32) -> CompactBlock {
        CompactBlock {
            height,
            hash: [height as u8; 32],
            prev_hash: [height.wrapping_sub(1) as u8; 32],
            timestamp: 1000 + height as u64,
            txs: vec![],
            dao_calls: vec![],
            func_events: vec![],
        }
    }

    fn make_multi_output_block(height: u32, n_outputs: usize) -> CompactBlock {
        let outputs = (0..n_outputs)
            .map(|i| CompactOutput {
                coin: make_valid_coin(height.wrapping_add(i as u32).wrapping_mul(1000)),
                encrypted_note: vec![0xAA; 100],
                value_commit: vec![0xBB; 33],
                token_commit: [0xCC; 32],
                omr_clue: vec![],
                omr_metadata_enc: vec![],
                func_code: 0,
            })
            .collect();
        CompactBlock {
            height,
            hash: [height as u8; 32],
            prev_hash: [height.wrapping_sub(1) as u8; 32],
            timestamp: 1000 + height as u64,
            txs: vec![CompactTx {
                tx_hash: [height as u8; 32],
                outputs,
                nullifiers: vec![],
                fee: 100,
            }],
            dao_calls: vec![],
            func_events: vec![],
        }
    }

    #[test]
    fn missing_tip_block_is_repaired_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        {
            let cache = Cache::new(&path).unwrap();
            cache.insert_compact_block(&make_test_block(0)).unwrap();
            cache.insert_compact_block(&make_test_block(1)).unwrap();
            cache.insert_compact_block(&make_test_block(2)).unwrap();
            assert_eq!(cache.get_tip().unwrap().unwrap().0, 2);
        }
        {
            let db = sled::open(&path).unwrap();
            let blocks = db.open_tree("lightwalletd_compact_blocks").unwrap();
            blocks.remove(2u32.to_be_bytes()).unwrap();
            db.flush().unwrap();
        }
        let cache = Cache::new(&path).unwrap();
        let (height, _) = cache.get_tip().unwrap().unwrap();
        assert_eq!(height, 1);
        assert!(cache.get_compact_block(2).unwrap().is_none());
        assert!(cache.get_compact_block(1).unwrap().is_some());
    }

    #[test]
    fn tip_chain_facts_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
        let hash = [7u8; 32];
        assert!(cache.tip_chain_facts_for(1, &hash).unwrap().is_none());
        cache.set_tip_chain_facts(1, &hash, 20, "123").unwrap();
        assert_eq!(
            cache.tip_chain_facts_for(1, &hash).unwrap().unwrap(),
            (20, "123".into())
        );
        assert!(cache.tip_chain_facts_for(2, &hash).unwrap().is_none());
        assert!(cache.tip_chain_facts_for(1, &[8u8; 32]).unwrap().is_none());
    }

    #[test]
    fn interrupted_rewind_resumes_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        {
            let cache = Cache::new(&path).unwrap();
            cache.insert_compact_block(&make_test_block(0)).unwrap();
            cache.insert_compact_block(&make_test_block(1)).unwrap();
            cache.insert_compact_block(&make_test_block(2)).unwrap();
        }
        {
            let db = sled::open(&path).unwrap();
            let meta = db.open_tree(META_TREE).unwrap();
            meta.insert(META_REWINDING_TO, &1u32.to_be_bytes()).unwrap();
            db.flush().unwrap();
        }
        let cache = reopen_cache(&path);
        let (height, _) = cache.get_tip().unwrap().unwrap();
        assert_eq!(height, 1);
        assert!(cache.get_compact_block(2).unwrap().is_none());
        assert!(cache.get_compact_block(1).unwrap().is_some());
        assert!(cache.meta.get(META_REWINDING_TO).unwrap().is_none());
    }

    #[test]
    fn first_missing_hash_finds_a_hole() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
        cache.insert_compact_block(&make_test_block(0)).unwrap();
        cache.insert_compact_block(&make_test_block(1)).unwrap();
        cache.insert_compact_block(&make_test_block(3)).unwrap();
        assert_eq!(cache.first_missing_hash(0, 3).unwrap(), Some(2));
        assert_eq!(cache.first_missing_hash(0, 1).unwrap(), None);
    }

    #[test]
    fn tip_fetched_unix_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(cache.tip_fetched_unix().unwrap(), 0);
        cache.set_tip_fetched_unix(1_700_000_000).unwrap();
        assert_eq!(cache.tip_fetched_unix().unwrap(), 1_700_000_000);
    }

    #[test]
    fn test_notes_range_includes_empty_heights() {
        // S19: empty / missing heights must still occupy a slot.
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        cache.insert_compact_block(&make_test_block(10)).unwrap();
        cache.insert_compact_block(&make_empty_block(11)).unwrap();
        cache.insert_compact_block(&make_test_block(12)).unwrap();

        let notes = cache.get_encrypted_notes_range(10, 13).unwrap();
        assert_eq!(notes.len(), 4);
        assert_eq!(notes[0].0, 10);
        assert_eq!(notes[0].1.len(), 1);
        assert_eq!(notes[1].0, 11);
        assert!(notes[1].1.is_empty());
        assert_eq!(notes[2].0, 12);
        assert_eq!(notes[2].1.len(), 1);
        assert_eq!(notes[3].0, 13);
        assert!(notes[3].1.is_empty());
    }

    #[test]
    fn test_notes_range_skips_ciphertext_when_clue_present() {
        // P2: detector path only needs encrypted_note when omr_clue is empty.
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let mut with_clue = make_test_block(20);
        with_clue.txs[0].outputs[0].omr_clue = vec![0x11; 16];
        let mut no_clue = make_test_block(21);
        no_clue.txs[0].outputs[0].omr_clue.clear();

        cache.insert_compact_block(&with_clue).unwrap();
        cache.insert_compact_block(&no_clue).unwrap();

        let notes = cache.get_encrypted_notes_range(20, 21).unwrap();
        assert!(notes[0].1[0].encrypted_note.is_empty());
        assert!(!notes[0].1[0].omr_clue.is_empty());
        assert!(!notes[1].1[0].encrypted_note.is_empty());
        assert!(notes[1].1[0].omr_clue.is_empty());
    }

    #[test]
    fn test_omr_clue_hint_first_writer_wins() {
        // S3: existing clue must not be overwritten.
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let tx_hash = [9u8; 32];
        let first = vec![0xAAu8; 16];
        let second = vec![0xBBu8; 16];
        cache
            .store_omr_clue_hint(&tx_hash, first.clone(), None)
            .unwrap();
        assert!(cache.has_omr_clue_hint(&tx_hash).unwrap());

        // Simulate server first-writer-wins: skip store when hint exists.
        if !cache.has_omr_clue_hint(&tx_hash).unwrap() {
            cache
                .store_omr_clue_hint(&tx_hash, second.clone(), None)
                .unwrap();
        }

        // Apply to block and verify first clue was kept.
        let mut block = make_multi_output_block(1, 1);
        block.txs[0].tx_hash = tx_hash;
        cache.apply_omr_clue_hints(&mut block).unwrap();
        assert_eq!(block.txs[0].outputs[0].omr_clue, first);
        assert_ne!(block.txs[0].outputs[0].omr_clue, second);
    }

    #[test]
    fn test_omr_clue_hint_applies_to_first_empty_only() {
        // S20: one clue must not be copied onto every empty output.
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let clue = vec![0x42u8; 16];
        let tx_hash = [7u8; 32];
        cache
            .store_omr_clue_hint(&tx_hash, clue.clone(), None)
            .unwrap();

        let mut block = make_multi_output_block(1, 3);
        block.txs[0].tx_hash = tx_hash;
        cache.apply_omr_clue_hints(&mut block).unwrap();

        assert_eq!(block.txs[0].outputs[0].omr_clue, clue);
        assert!(block.txs[0].outputs[1].omr_clue.is_empty());
        assert!(block.txs[0].outputs[2].omr_clue.is_empty());
        assert!(
            cache.has_omr_clue_hint(&tx_hash).unwrap(),
            "hint kept until TTL"
        );

        // Re-applying to an already-merged block must not attach it again.
        cache.apply_omr_clue_hints(&mut block).unwrap();
        assert_eq!(block.txs[0].outputs[0].omr_clue, clue);
        assert!(block.txs[0].outputs[1].omr_clue.is_empty());
        assert!(block.txs[0].outputs[2].omr_clue.is_empty());
    }

    #[test]
    fn test_same_clue_bytes_apply_to_each_named_output() {
        // Change and fee hints are encryptions to the same key and may share
        // bytes. Each named output still needs its own copy or that output
        // is absent from the digest.
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let clue = vec![0x42u8; 16];
        let tx_hash = [8u8; 32];
        cache
            .store_omr_clue_hint(&tx_hash, clue.clone(), Some(1))
            .unwrap();
        cache
            .store_omr_clue_hint(&tx_hash, clue.clone(), Some(2))
            .unwrap();

        let mut block = make_multi_output_block(1, 3);
        block.txs[0].tx_hash = tx_hash;
        cache.apply_omr_clue_hints(&mut block).unwrap();

        assert!(block.txs[0].outputs[0].omr_clue.is_empty());
        assert_eq!(block.txs[0].outputs[1].omr_clue, clue);
        assert_eq!(block.txs[0].outputs[2].omr_clue, clue);
    }

    #[test]
    fn test_omr_clue_hint_survives_reorg() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        for h in 0..5 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }
        let clue = vec![0x5Au8; 16];
        let mut block = make_multi_output_block(5, 2);
        let tx_hash = [0xE5u8; 32];
        block.txs[0].tx_hash = tx_hash;
        cache
            .store_omr_clue_hint(&tx_hash, clue.clone(), None)
            .unwrap();

        cache.insert_compact_block(&block).unwrap();
        let stored = cache.get_compact_block(5).unwrap().unwrap();
        assert_eq!(stored.txs[0].outputs[0].omr_clue, clue);

        cache.rewind_to_height(4).unwrap();
        assert!(cache.get_compact_block(5).unwrap().is_none());

        // darkfid re-serves the block without clues.
        cache.insert_compact_block(&block).unwrap();
        let stored = cache.get_compact_block(5).unwrap().unwrap();
        assert_eq!(stored.txs[0].outputs[0].omr_clue, clue);
        assert!(stored.txs[0].outputs[1].omr_clue.is_empty());
    }

    #[test]
    fn test_omr_clue_hint_applies_to_explicit_output_index() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let clue = vec![0x99u8; 16];
        let tx_hash = [8u8; 32];
        cache
            .store_omr_clue_hint(&tx_hash, clue.clone(), Some(2))
            .unwrap();

        let mut block = make_multi_output_block(1, 3);
        block.txs[0].tx_hash = tx_hash;
        cache.apply_omr_clue_hints(&mut block).unwrap();

        assert!(block.txs[0].outputs[0].omr_clue.is_empty());
        assert!(block.txs[0].outputs[1].omr_clue.is_empty());
        assert_eq!(block.txs[0].outputs[2].omr_clue, clue);
    }

    #[test]
    fn test_cache_insert_and_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let block = make_test_block(42);
        cache.insert_compact_block(&block).unwrap();

        let retrieved = cache.get_compact_block(42).unwrap().unwrap();
        assert_eq!(retrieved.height, 42);
        assert_eq!(retrieved.hash, block.hash);
        assert_eq!(retrieved.txs.len(), 1);

        let tip = cache.get_tip().unwrap().unwrap();
        assert_eq!(tip.0, 42);
        assert_eq!(tip.1, block.hash);
    }

    #[test]
    fn test_cache_range_query() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        for h in 0..10 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }

        let range = cache.get_compact_blocks_range(3, 7).unwrap();
        assert_eq!(range.len(), 5);
        assert_eq!(range[0].height, 3);
        assert_eq!(range[4].height, 7);
    }

    #[test]
    fn test_cache_rewind() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        for h in 0..10 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }

        cache.rewind_to_height(5).unwrap();

        // Blocks 0-5 should exist
        assert!(cache.get_compact_block(5).unwrap().is_some());
        // Blocks 6-9 should be deleted
        assert!(cache.get_compact_block(6).unwrap().is_none());
        assert!(cache.get_compact_block(9).unwrap().is_none());

        let tip = cache.get_tip().unwrap().unwrap();
        assert_eq!(tip.0, 5);
    }

    #[test]
    fn historical_genesis_insert_does_not_rewind_tip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
        cache.insert_compact_block(&make_test_block(1)).unwrap();
        cache.insert_compact_block(&make_test_block(2)).unwrap();
        assert_eq!(cache.get_tip().unwrap().unwrap().0, 2);

        cache.insert_compact_block(&make_test_block(0)).unwrap();
        assert_eq!(
            cache.get_tip().unwrap().unwrap().0,
            2,
            "backfilling height 0 must not rewind tip"
        );
        assert!(cache.get_compact_block(0).unwrap().is_some());
        let backfilled = cache.get_tip_tree_state().unwrap().unwrap().1;

        let dir_seq = tempfile::tempdir().unwrap();
        let sequential = Cache::new(dir_seq.path().to_str().unwrap()).unwrap();
        for h in 0..3 {
            sequential
                .insert_compact_block(&make_test_block(h))
                .unwrap();
        }
        assert_eq!(
            sequential.get_tip_tree_state().unwrap().unwrap().1,
            backfilled,
            "backfill must replay coins after the surviving snapshot"
        );
    }

    #[test]
    fn test_cache_prune_below_height() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        for h in 0..20 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }

        // Prune blocks below height 10
        cache.prune_below_height(10).unwrap();

        // Blocks 0-9 should be deleted
        for h in 0..10 {
            assert!(
                cache.get_compact_block(h).unwrap().is_none(),
                "Block {h} should have been pruned"
            );
        }

        // Blocks 10-19 should still exist
        for h in 10..20 {
            assert!(
                cache.get_compact_block(h).unwrap().is_some(),
                "Block {h} should still exist"
            );
        }

        // Tip should be unchanged
        let tip = cache.get_tip().unwrap().unwrap();
        assert_eq!(tip.0, 19);
    }

    #[test]
    fn test_cache_prune_with_retention() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        for h in 0..100 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }

        // Prune with retention window of 50 (tip=99, prune below 49)
        cache.prune_with_retention(50).unwrap();

        // Block 48 should be pruned
        assert!(cache.get_compact_block(48).unwrap().is_none());
        // Block 49 should still exist
        assert!(cache.get_compact_block(49).unwrap().is_some());
        // Block 99 should still exist
        assert!(cache.get_compact_block(99).unwrap().is_some());
    }

    #[test]
    fn snapshot_retained_on_interval_and_tip_rewind_drops_higher_prune_keeps() {
        // CompactBlock does not carry the block header's money-tree root, so
        // snapshot state_root stays blake3(tree_data). See the server snapshot
        // test — do not invent a second root here.
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        for h in 0..=(MERKLE_SNAPSHOT_INTERVAL + 1) {
            cache.insert_compact_block(&make_empty_block(h)).unwrap();
        }
        let tip = MERKLE_SNAPSHOT_INTERVAL + 1;
        assert_eq!(cache.get_tip().unwrap().unwrap().0, tip);
        assert_eq!(
            cache.snapshot_heights().unwrap(),
            vec![0, MERKLE_SNAPSHOT_INTERVAL, tip],
            "interval boundary and the current tip, not every height"
        );
        let (meta_h, meta_tree) = cache.get_tip_tree_state().unwrap().unwrap();
        assert_eq!(meta_h, tip);
        assert_eq!(cache.merkle_snapshot(tip).unwrap().unwrap(), meta_tree);

        cache.rewind_to_height(1000).unwrap();
        assert_eq!(cache.get_tip().unwrap().unwrap().0, 1000);
        assert!(cache.get_compact_block(tip).unwrap().is_none());
        assert!(cache
            .merkle_snapshot(MERKLE_SNAPSHOT_INTERVAL)
            .unwrap()
            .is_none());
        assert!(cache.merkle_snapshot(tip).unwrap().is_none());
        assert_eq!(cache.snapshot_heights().unwrap(), vec![0, 1000]);
        assert!(cache.merkle_snapshot(0).unwrap().is_some());

        cache.prune_below_height(10).unwrap();
        assert!(
            cache.get_compact_block(0).unwrap().is_none(),
            "prune drops the compact block"
        );
        assert!(
            cache.merkle_snapshot(0).unwrap().is_some(),
            "prune keeps the snapshot"
        );
        assert!(cache.merkle_snapshot(1000).unwrap().is_some());
        assert_eq!(cache.snapshot_heights().unwrap(), vec![0, 1000]);
    }

    #[test]
    fn test_cache_prune_zero_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        cache.insert_compact_block(&make_test_block(0)).unwrap();
        cache.prune_below_height(0).unwrap();

        // Block 0 should still exist
        assert!(cache.get_compact_block(0).unwrap().is_some());
    }

    #[test]
    fn test_cache_overwrite_same_height() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let block_v1 = make_test_block(100);
        cache.insert_compact_block(&block_v1).unwrap();

        // Insert a different block at the same height (simulate reorg)
        let mut block_v2 = make_test_block(100);
        block_v2.hash = [0xFF; 32]; // different hash
        cache.insert_compact_block(&block_v2).unwrap();

        let retrieved = cache.get_compact_block(100).unwrap().unwrap();
        assert_eq!(retrieved.hash, [0xFF; 32], "latest insert should win");
    }

    #[test]
    fn test_cache_range_ordering_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        // Insert out of order
        for h in [5u32, 3, 1, 4, 2] {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }

        let range = cache.get_compact_blocks_range(1, 5).unwrap();
        assert_eq!(range.len(), 5);
        for (i, block) in range.iter().enumerate() {
            assert_eq!(
                block.height,
                (i + 1) as u32,
                "blocks should be in ascending order"
            );
        }
    }

    #[test]
    fn test_clue_public_key_roundtrip_strips_u64_version() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

        let payment_pk = [0x11u8; 32];
        // Realistic UnifOMR wire length (n=1024 → 4 + 16*1024); pattern must
        // not accidentally equal a 4-byte-strip mis-read of version||key.
        let clue_pk: Vec<u8> = (0..16_388u32).map(|i| (i % 251) as u8).collect();
        let key_version = 1_785_630_000u64; // LE: low 4 nonzero, high 4 zero
        let proof = vec![0xABu8; 64];

        cache
            .store_clue_public_key(&payment_pk, &clue_pk, key_version, &proof)
            .unwrap();
        let got = cache.get_clue_public_key(&payment_pk).unwrap().unwrap();
        assert_eq!(got, clue_pk, "must return clue_pk without framing");

        let (ver, got_proof, got_clue) = cache
            .get_clue_public_key_entry(&payment_pk)
            .unwrap()
            .unwrap();
        assert_eq!(ver, key_version);
        assert_eq!(got_proof, proof);
        assert_eq!(got_clue, clue_pk);

        // Same version + same key is idempotent.
        cache
            .store_clue_public_key(&payment_pk, &clue_pk, key_version, &proof)
            .unwrap();
        assert_eq!(
            cache.get_clue_public_key(&payment_pk).unwrap().unwrap(),
            clue_pk
        );
    }

    #[test]
    fn empty_tip_tree_matches_wallet_zero_sentinel() {
        use darkfi_sdk::crypto::{MerkleNode, MerkleTree};
        use darkfi_sdk::pasta::group::ff::Field;
        use darkfi_sdk::pasta::pallas;
        let tip = Cache::empty_tip_tree();
        let mut wallet = MerkleTree::new(u32::MAX as usize);
        wallet.append(MerkleNode::from(pallas::Base::ZERO));
        assert_eq!(tip.root(0).unwrap(), wallet.root(0).unwrap());
    }

    #[test]
    fn coin_to_merkle_node_accepts_canonical_bytes() {
        let coin = make_valid_coin(7);
        assert!(Cache::coin_to_merkle_node(&coin).is_ok());
        let mut bad = [0xFFu8; 32];
        bad[31] = 0xFF;
        // All-0xFF is not a canonical pallas::Base.
        assert!(Cache::coin_to_merkle_node(&bad).is_err());
    }

    #[test]
    fn tip_merkle_reloads_across_restart() {
        let dir_fresh = tempfile::tempdir().unwrap();
        let dir_restart = tempfile::tempdir().unwrap();
        let fresh = Cache::new(dir_fresh.path().to_str().unwrap()).unwrap();
        for h in 0..6 {
            fresh.insert_compact_block(&make_test_block(h)).unwrap();
        }
        {
            let cache = Cache::new(dir_restart.path().to_str().unwrap()).unwrap();
            for h in 0..3 {
                cache.insert_compact_block(&make_test_block(h)).unwrap();
            }
            cache.flush().unwrap();
        }
        let restarted = reopen_cache(dir_restart.path().to_str().unwrap());
        for h in 3..6 {
            restarted.insert_compact_block(&make_test_block(h)).unwrap();
        }
        assert_eq!(
            fresh.get_tip_tree_state().unwrap(),
            restarted.get_tip_tree_state().unwrap()
        );
    }

    #[test]
    fn expired_omr_clue_hint_dropped_on_read_without_full_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
        let tx_hash = [0x42u8; 32];
        cache
            .store_omr_clue_hint(&tx_hash, vec![1, 2, 3], Some(0))
            .unwrap();
        assert!(cache.has_omr_clue_hint(&tx_hash).unwrap());
        cache.omr_hint_sweep_unix.store(u64::MAX, Ordering::Relaxed);
        cache
            .omr_clue_hint_meta
            .insert(tx_hash.as_slice(), &0u64.to_le_bytes())
            .unwrap();
        assert!(!cache.has_omr_clue_hint(&tx_hash).unwrap());
        assert!(!cache
            .omr_clue_hints
            .contains_key(tx_hash.as_slice())
            .unwrap());
        assert!(!cache.omr_clue_index_taken(&tx_hash, 0).unwrap());
    }

    #[test]
    fn cache_format_stamped_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cache = Cache::new(path).unwrap();
        let raw = cache
            .meta
            .get(META_CACHE_FORMAT)
            .unwrap()
            .expect("format key");
        let ver = u32::from_be_bytes(raw.as_ref().try_into().unwrap());
        assert_eq!(ver, CACHE_FORMAT_VERSION);
        drop(cache);
        let _reopen = reopen_cache(path);
    }

    #[test]
    fn clue_key_version_one_replaces_proof_and_rejects_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
        let payment_pk = [0x22u8; 32];
        let clue = vec![1u8, 2, 3, 4];
        assert!(cache
            .store_clue_public_key(&payment_pk, &clue, 0, &[1])
            .is_err());
        cache
            .store_clue_public_key(&payment_pk, &clue, 1, &[9])
            .unwrap();
        cache
            .store_clue_public_key(&payment_pk, &clue, 1, &[8, 8])
            .unwrap();
        let (ver, proof, got) = cache
            .get_clue_public_key_entry(&payment_pk)
            .unwrap()
            .unwrap();
        assert_eq!(ver, 1);
        assert_eq!(proof, vec![8, 8]);
        assert_eq!(got, clue);
        assert!(cache
            .store_clue_public_key(&payment_pk, &[9], 1, &[1])
            .is_err());
        cache
            .store_clue_public_key(&payment_pk, &[7], 2, &[3])
            .unwrap();
        let (ver, _, got) = cache
            .get_clue_public_key_entry(&payment_pk)
            .unwrap()
            .unwrap();
        assert_eq!(ver, 2);
        assert_eq!(got, vec![7]);
        assert!(cache
            .store_clue_public_key(&payment_pk, &[7], 1, &[3])
            .is_err());
    }

    #[test]
    fn obsolete_v1_attest_key_is_deleted_and_v2_rows_move() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        {
            let db = sled::open(path).unwrap();
            let meta = db.open_tree(META_TREE).unwrap();
            meta.insert(b"unifomr_dir_attest_sk_v1", &[9u8; 32])
                .unwrap();
            meta.insert(b"unifomr_dir_attest_sk_v2", &[3u8; 32])
                .unwrap();
            meta.insert(b"unifomr_clue_dir_pepper_v1", &[4u8; 32])
                .unwrap();
            meta.insert(b"unifomr_clue_dir_pepper_anchor_v1", &1u64.to_le_bytes())
                .unwrap();
            let old = db.open_tree("lightwalletd_omr_clue_pubkeys_v2").unwrap();
            let mut value = Vec::new();
            value.extend_from_slice(b"v3");
            value.extend_from_slice(&1u64.to_le_bytes());
            value.extend_from_slice(&1u32.to_le_bytes());
            value.push(0xAB);
            value.push(0xCD);
            old.insert(&[1u8; 32], value).unwrap();
            db.flush().unwrap();
        }
        let cache = reopen_cache(path);
        assert!(cache
            .meta
            .get(b"unifomr_dir_attest_sk_v1")
            .unwrap()
            .is_none());
        assert!(cache
            .meta
            .get(b"unifomr_dir_attest_sk_v2")
            .unwrap()
            .is_none());
        assert_eq!(
            cache
                .meta
                .get(b"unifomr_dir_attest_sk")
                .unwrap()
                .unwrap()
                .as_ref(),
            &[3u8; 32]
        );
        assert_eq!(
            cache
                .meta
                .get(META_CLUE_DIR_PEPPER)
                .unwrap()
                .unwrap()
                .as_ref(),
            &[4u8; 32]
        );
        assert!(cache
            .meta
            .get(b"unifomr_clue_dir_pepper_anchor_v1")
            .unwrap()
            .is_none());
        assert!(!cache.tree_exists("lightwalletd_omr_clue_pubkeys_v2"));
        let (ver, proof, clue) = cache
            .get_clue_public_key_entry(&[1u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(ver, 1);
        assert_eq!(proof, vec![0xAB]);
        assert_eq!(clue, vec![0xCD]);
        drop(cache);
        let again = reopen_cache(path);
        assert_eq!(
            again
                .meta
                .get(b"unifomr_dir_attest_sk")
                .unwrap()
                .unwrap()
                .as_ref(),
            &[3u8; 32]
        );
    }

    #[test]
    fn same_height_overwrite_does_not_duplicate_merkle_leaves() {
        let once_dir = tempfile::tempdir().unwrap();
        let twice_dir = tempfile::tempdir().unwrap();
        let once = Cache::new(once_dir.path().to_str().unwrap()).unwrap();
        once.insert_compact_block(&make_test_block(0)).unwrap();
        let twice = Cache::new(twice_dir.path().to_str().unwrap()).unwrap();
        twice.insert_compact_block(&make_test_block(0)).unwrap();
        let mut again = make_test_block(0);
        again.hash = [0xAB; 32];
        twice.insert_compact_block(&again).unwrap();
        assert_eq!(
            once.get_tip_tree_state().unwrap(),
            twice.get_tip_tree_state().unwrap()
        );
    }

    #[test]
    fn corrupt_tip_tree_is_rebuilt_before_append() {
        let broken_dir = tempfile::tempdir().unwrap();
        let fresh_dir = tempfile::tempdir().unwrap();
        let broken_path = broken_dir.path().to_str().unwrap();
        {
            let cache = Cache::new(broken_path).unwrap();
            for h in 0..4 {
                cache.insert_compact_block(&make_test_block(h)).unwrap();
            }
            cache
                .meta
                .insert(META_TIP_MERKLE_TREE, b"not-a-tree")
                .unwrap();
            cache.flush().unwrap();
        }
        let cache = reopen_cache(broken_path);
        cache.insert_compact_block(&make_test_block(4)).unwrap();
        let fresh = Cache::new(fresh_dir.path().to_str().unwrap()).unwrap();
        for h in 0..5 {
            fresh.insert_compact_block(&make_test_block(h)).unwrap();
        }
        assert_eq!(
            cache.get_tip_tree_state().unwrap(),
            fresh.get_tip_tree_state().unwrap()
        );
    }
}
