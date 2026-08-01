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
//! Uses sled to store:
//! - Compact blocks indexed by height
//! - Block hash ↔ height bidirectional index
//! - Server metadata (chain tip, version)
//!
//! All data in this cache is derived from the darkfid full node and can
//! be rebuilt from scratch if corrupted or deleted.

// Using bincode for compact block serialization (serde-based) to avoid
// lifetime issues with darkfi_serial's async derive macros.
use tracing::{debug, info, warn};

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
const OMR_CLUE_HINTS_TREE: &str = "lightwalletd_omr_clue_hints";
const OMR_CLUE_HINT_META_TREE: &str = "lightwalletd_omr_clue_hint_meta";
// v2: values are `[key_version u64 LE || clue_pk]` (monotonic anti-replay).
const OMR_CLUE_PUBKEYS_TREE: &str = "lightwalletd_omr_clue_pubkeys_v2";
const OMR_METADATA_ENC_TREE: &str = "lightwalletd_omr_metadata_enc";

/// Orphan OMR clue hints expire after this many seconds if the tx never confirms (S21).
/// Orphan clue hints must outlive slow localnet / congested confirms.
/// 24h keeps SendTransaction clues available until the tx is indexed.
pub const OMR_CLUE_HINT_TTL_SECS: u64 = 86_400;
/// Max opaque recipient OMR metadata size (DoS / cache bloat).
pub const MAX_OMR_METADATA_ENC_BYTES: usize = 4096;

// Meta keys
const META_TIP_HEIGHT: &[u8] = b"tip_height";
const META_TIP_HASH: &[u8] = b"tip_hash";
const META_TIP_MERKLE_TREE: &[u8] = b"tip_merkle_tree";
const META_TIP_MERKLE_HEIGHT: &[u8] = b"tip_merkle_height";

/// Checkpoints retained in the tip Money Merkle tree (matches wallet clients).
const TIP_TREE_CHECKPOINTS: usize = 100;

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
            omr_clue_hints,
            omr_clue_hint_meta,
            omr_clue_pubkeys,
            omr_metadata_enc,
            meta,
        };
        // Best-effort prune of orphan hints left from previous runs (S21).
        let _ = cache.prune_expired_omr_clue_hints();
        Ok(cache)
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
        self.hash_to_height.insert(block.hash, height_key.as_ref())?;

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

        // Wire format: [output_index:u32 LE | 0xFFFF_FFFF = first-empty] || clue
        let mut stored = Vec::with_capacity(4 + clue.len());
        let idx = output_index.unwrap_or(u32::MAX);
        stored.extend_from_slice(&idx.to_le_bytes());
        stored.extend_from_slice(&clue);

        self.omr_clue_hints
            .insert(tx_hash.as_slice(), stored.as_slice())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
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

    /// True if a clue hint is already stored for this tx (e.g. from SendTransaction).
    ///
    /// Prunes expired hints first so TTL is observed (S21).
    pub fn has_omr_clue_hint(&self, tx_hash: &[u8; 32]) -> Result<bool> {
        self.prune_expired_omr_clue_hints()?;
        Ok(self.omr_clue_hints.contains_key(tx_hash.as_slice())?)
    }

    /// Store UnifOMR clue public key for a payment pubkey (32 bytes).
    ///
    /// Monotonic anti-replay: an existing registration is only replaced when
    /// `key_version` is strictly greater (signed key rotation). Replaying an
    /// old registration (lower/equal version) cannot overwrite a newer one;
    /// re-registering the identical key at the same version is idempotent.
    pub fn store_clue_public_key(
        &self,
        payment_pubkey: &[u8; 32],
        clue_pk: &[u8],
        key_version: u64,
    ) -> Result<()> {
        // n=1024 → 4 + 16*1024 = 16388 bytes; leave headroom for future params.
        if clue_pk.is_empty() || clue_pk.len() > 65_536 {
            return Err(LightWalletError::CacheError(
                "invalid clue public key size".into(),
            ));
        }
        if let Some(existing) = self.omr_clue_pubkeys.get(payment_pubkey.as_slice())? {
            if existing.len() >= 8 {
                let stored_version =
                    u64::from_le_bytes(existing[..8].try_into().expect("8-byte prefix"));
                if key_version < stored_version {
                    return Err(LightWalletError::CacheError(format!(
                        "stale clue registration: key_version {key_version} < registered {stored_version}"
                    )));
                }
                if key_version == stored_version {
                    if &existing[8..] == clue_pk {
                        return Ok(());
                    }
                    return Err(LightWalletError::CacheError(
                        "clue public key already registered at this key_version".into(),
                    ));
                }
                // key_version > stored_version: signed rotation, fall through.
            }
        }
        let mut value = Vec::with_capacity(8 + clue_pk.len());
        value.extend_from_slice(&key_version.to_le_bytes());
        value.extend_from_slice(clue_pk);
        self.omr_clue_pubkeys
            .insert(payment_pubkey.as_slice(), value)?;
        Ok(())
    }

    /// Lookup UnifOMR clue public key by payment pubkey.
    pub fn get_clue_public_key(&self, payment_pubkey: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .omr_clue_pubkeys
            .get(payment_pubkey.as_slice())?
            .and_then(|v| (v.len() > 4).then(|| v[4..].to_vec())))
    }

    /// Stable server pepper for clue-directory decoys (hides registration bit).
    pub fn get_or_create_clue_dir_pepper(&self) -> Result<[u8; 32]> {
        const KEY: &[u8] = b"unifomr_clue_dir_pepper_v1";
        if let Some(existing) = self.meta.get(KEY)? {
            if existing.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&existing);
                return Ok(out);
            }
        }
        let mut pepper = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut pepper);
        self.meta.insert(KEY, pepper.as_slice())?;
        Ok(pepper)
    }

    /// Drop orphan OMR clue hints older than [`OMR_CLUE_HINT_TTL_SECS`] (S21).
    pub fn prune_expired_omr_clue_hints(&self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut expired = Vec::new();
        for item in self.omr_clue_hint_meta.iter() {
            let (key, value) = item?;
            if value.len() < 8 {
                expired.push(key.to_vec());
                continue;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&value[..8]);
            let stored_at = u64::from_le_bytes(buf);
            if now.saturating_sub(stored_at) > OMR_CLUE_HINT_TTL_SECS {
                expired.push(key.to_vec());
            }
        }
        for key in expired {
            self.omr_clue_hints.remove(key.as_slice())?;
            self.omr_clue_hint_meta.remove(key.as_slice())?;
        }
        Ok(())
    }

    /// Merge pending OMR clues into compact block outputs, then remove consumed hints.
    ///
    /// S20: apply to a single output — either the stored index, or the first
    /// empty output when the index is `u32::MAX` / raw clue bytes.
    pub fn apply_omr_clue_hints(&self, block: &mut CompactBlock) -> Result<()> {
        for tx in &mut block.txs {
            let tx_hash: [u8; 32] = tx.tx_hash;

            // Merge FHE clue
            if let Some(stored_bytes) = self.omr_clue_hints.get(tx_hash.as_slice())? {
                let (output_index, clue) = parse_stored_omr_clue_hint(&stored_bytes);
                if clue.is_empty() {
                    self.omr_clue_hints.remove(tx_hash.as_slice())?;
                    self.omr_clue_hint_meta.remove(tx_hash.as_slice())?;
                } else {
                    if let Some(idx) = output_index {
                        if let Some(output) = tx.outputs.get_mut(idx as usize) {
                            if output.omr_clue.is_empty() {
                                output.omr_clue = clue;
                            }
                        }
                    } else {
                        if let Some(output) = tx.outputs.iter_mut().find(|o| o.omr_clue.is_empty())
                        {
                            output.omr_clue = clue;
                        }
                    }
                    self.omr_clue_hints.remove(tx_hash.as_slice())?;
                    self.omr_clue_hint_meta.remove(tx_hash.as_slice())?;
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

        let mut blocks = Vec::with_capacity((end - start + 1) as usize);
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

    /// Rewind the cache to the given height (inclusive).
    ///
    /// Deletes all compact blocks, hashes, nullifiers, and coins above `height`.
    /// Used during reorg handling.
    pub fn rewind_to_height(&self, height: u32) -> Result<()> {
        warn!(
            target: "lightwalletd::cache",
            "Rewinding cache to height {height}"
        );

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
        }

        // Rebuild tip Merkle tree through the new tip (honest tip-only snapshot).
        self.rebuild_tip_merkle_tree(height)?;

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
    /// Historical heights are not retained; callers should only request tip.
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

    fn load_or_empty_tip_tree(&self) -> Result<darkfi_sdk::crypto::MerkleTree> {
        if let Some(bytes) = self.meta.get(META_TIP_MERKLE_TREE)? {
            match darkfi_serial::deserialize(&bytes) {
                Ok(tree) => return Ok(tree),
                Err(e) => {
                    warn!(
                        target: "lightwalletd::cache",
                        "Failed to deserialize tip Merkle tree ({e}); rebuilding"
                    );
                }
            }
        }
        Ok(darkfi_sdk::crypto::MerkleTree::new(TIP_TREE_CHECKPOINTS))
    }

    fn store_tip_tree(&self, height: u32, tree: &darkfi_sdk::crypto::MerkleTree) -> Result<()> {
        let tree_data = darkfi_serial::serialize(tree);
        self.meta
            .insert(META_TIP_MERKLE_TREE, tree_data.as_slice())?;
        self.meta
            .insert(META_TIP_MERKLE_HEIGHT, &height.to_be_bytes())?;
        Ok(())
    }

    fn append_coins_to_tip_tree(&self, height: u32, coins: &[[u8; 32]]) -> Result<()> {
        let mut tree = self.load_or_empty_tip_tree()?;
        for coin in coins {
            let node: darkfi_sdk::crypto::MerkleNode =
                darkfi_serial::deserialize(coin).map_err(|e| {
                    LightWalletError::SerializationError(format!(
                        "Invalid coin bytes for Merkle append: {e}"
                    ))
                })?;
            tree.append(node);
        }
        self.store_tip_tree(height, &tree)
    }

    fn rebuild_tip_merkle_tree(&self, tip_height: u32) -> Result<()> {
        let mut tree = darkfi_sdk::crypto::MerkleTree::new(TIP_TREE_CHECKPOINTS);
        if tip_height == 0 && self.get_compact_block(0)?.is_none() {
            self.meta.remove(META_TIP_MERKLE_TREE)?;
            self.meta.remove(META_TIP_MERKLE_HEIGHT)?;
            return Ok(());
        }
        let ranges = self.get_coins_range(0, tip_height)?;
        for (_h, coins) in ranges {
            for coin in coins {
                let node: darkfi_sdk::crypto::MerkleNode = darkfi_serial::deserialize(&coin)
                    .map_err(|e| {
                        LightWalletError::SerializationError(format!(
                            "Invalid coin bytes during tip tree rebuild: {e}"
                        ))
                    })?;
                tree.append(node);
            }
        }
        self.store_tip_tree(tip_height, &tree)
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
        let mut result = Vec::with_capacity((end - start + 1) as usize);
        for height in start..=end {
            result.push((height, by_height.remove(&height).unwrap_or_default()));
        }

        Ok(result)
    }

    /// Prune all cached data below the given height.
    ///
    /// Removes compact blocks, block hashes, nullifiers, and coins for all
    /// heights strictly below `min_height`. Used to prevent unbounded disk
    /// growth on long-running servers.
    ///
    /// The tip metadata is NOT modified — only historical data is removed.
    /// Clients requesting pruned heights will receive empty responses.
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

/// Parse stored hint bytes into `(explicit_output_index, clue)`.
///
/// New format: 4-byte LE index (`u32::MAX` = first empty) + clue.
/// Fallback format: raw clue bytes (treated as first-empty).
fn parse_stored_omr_clue_hint(stored: &[u8]) -> (Option<u32>, Vec<u8>) {
    if stored.len() >= 4 {
        let mut idx_buf = [0u8; 4];
        idx_buf.copy_from_slice(&stored[..4]);
        let idx = u32::from_le_bytes(idx_buf);
        let clue = stored[4..].to_vec();
        if idx == u32::MAX {
            (None, clue)
        } else {
            (Some(idx), clue)
        }
    } else {
        // Fallback: entire blob is the clue → first empty output.
        (None, stored.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact_block::{CompactBlock, CompactOutput, CompactTx};

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
                }],
                nullifiers: vec![[height as u8; 32]],
                fee: 100,
            }],
        }
    }

    fn make_empty_block(height: u32) -> CompactBlock {
        CompactBlock {
            height,
            hash: [height as u8; 32],
            prev_hash: [height.wrapping_sub(1) as u8; 32],
            timestamp: 1000 + height as u64,
            txs: vec![],
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
        }
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
        assert!(!cache.has_omr_clue_hint(&tx_hash).unwrap());
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
            assert_eq!(block.height, (i + 1) as u32, "blocks should be in ascending order");
        }
    }
}

