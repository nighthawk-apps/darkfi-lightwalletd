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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use tracing::{debug, error, info, warn};

use crate::{
    compact_block::CompactBlock,
    error::{LightWalletError, Result},
};

mod blocks;
mod omr;
#[allow(unused_imports)]
use omr::*;
#[cfg(test)]
mod tests;

// sled tree names
pub(super) const META_TREE: &str = "lightwalletd_meta";
pub(super) const COMPACT_BLOCKS_TREE: &str = "lightwalletd_compact_blocks";
pub(super) const BLOCK_HASHES_TREE: &str = "lightwalletd_block_hashes";
pub(super) const HASH_TO_HEIGHT_TREE: &str = "lightwalletd_hash_to_height";
pub(super) const NULLIFIERS_TREE: &str = "lightwalletd_nullifiers";
pub(super) const COINS_TREE: &str = "lightwalletd_coins";
/// Height (u32 big-endian) → serialized `MerkleTree`.
///
/// Disk: one tree per [`MERKLE_SNAPSHOT_INTERVAL`] blocks, plus the current
/// tip. A non-aligned previous tip is replaced when the chain advances.
pub(super) const MERKLE_SNAPSHOTS_TREE: &str = "lightwalletd_merkle_snapshots";
pub(super) const OMR_CLUE_HINTS_TREE: &str = "lightwalletd_omr_clue_hints";
pub(super) const OMR_CLUE_HINT_META_TREE: &str = "lightwalletd_omr_clue_hint_meta";
pub(super) const OMR_CLUE_PUBKEYS_TREE: &str = "lightwalletd_omr_clue_pubkeys";
pub(super) const OMR_METADATA_ENC_TREE: &str = "lightwalletd_omr_metadata_enc";
pub(super) const OMR_METADATA_ENC_META_TREE: &str = "lightwalletd_omr_metadata_enc_meta";

/// Stored clue public key registry entry: `(key_version, ownership_proof, clue_pk)`.
pub type CluePublicKeyEntry = (u64, Vec<u8>, Vec<u8>);

/// Hard cap on registered entries in `omr_clue_pubkeys` to bound sled disk growth.
pub const MAX_CLUE_PUBKEY_ENTRIES: usize = 100_000;

/// Hard cap on pending `omr_metadata_enc` rows. Same order as
/// [`MAX_CLUE_PUBKEY_ENTRIES`]. A new tx hash is refused when the registry is
/// full; an existing hash may still be replaced.
pub const MAX_OMR_METADATA_ENC_ENTRIES: usize = 100_000;

/// On-disk cache layout version. Bump when compact-block bincode or tree
/// names change incompatibly. Missing key is treated as a pre-versioned
/// store and stamped in place (no wipe). A mismatch clears derived block
/// rows so the poller rebuilds them from darkfid; clue keys are kept.
///
/// 2: `CompactOutput.func_code`, DAO calls, and auth-token events.
pub(super) const CACHE_FORMAT_VERSION: u32 = 2;

/// OMR clue hints expire this many seconds after they were stored (S21).
///
/// Hints are not consumed on merge, so this bounds both slow confirms and the
/// reorg window in which a rewound block can get its clue re-merged.
pub const OMR_CLUE_HINT_TTL_SECS: u64 = 86_400;
/// Full hint-meta scan period. A single expired key is still dropped on read.
pub(super) const OMR_CLUE_HINT_SWEEP_SECS: u64 = 60;
/// Max opaque recipient OMR metadata size (DoS / cache bloat).
pub const MAX_OMR_METADATA_ENC_BYTES: usize = 4096;

// Meta keys
pub(super) const META_TIP_HEIGHT: &[u8] = b"tip_height";
pub(super) const META_TIP_HASH: &[u8] = b"tip_hash";
pub(super) const META_TIP_MERKLE_TREE: &[u8] = b"tip_merkle_tree";
pub(super) const META_TIP_MERKLE_HEIGHT: &[u8] = b"tip_merkle_height";
pub(super) const META_CACHE_FORMAT: &[u8] = b"cache_format";
pub(super) const META_CLUE_DIR_PEPPER: &[u8] = b"unifomr_clue_dir_pepper";
pub(super) const META_CLUE_DIR_PEPPER_ANCHOR: &[u8] = b"unifomr_clue_dir_pepper_anchor";
pub(super) const META_TIP_FETCHED_UNIX: &[u8] = b"tip_fetched_unix";
/// Height the in-progress rewind must reach. Cleared only after the tip matches.
pub(super) const META_REWINDING_TO: &[u8] = b"rewinding_to";
/// `height || hash || block_target || difficulty` for the tip those facts describe.
pub(super) const META_TIP_CHAIN_FACTS: &[u8] = b"tip_chain_facts";
pub(super) const META_PRUNED_BELOW_HEIGHT: &[u8] = b"pruned_below_height";

/// Checkpoints retained in the tip Money Merkle tree (matches wallet clients).
pub(super) const TIP_TREE_CHECKPOINTS: usize = 100;

/// Write a Money-tree snapshot every this many blocks, and always at the tip.
///
/// Matches the client's minimum padded bucket. Disk cost is one serialized
/// `MerkleTree` per 1024 blocks, plus the current tip (replaced in place when
/// the tip is not itself a 1024 boundary).
pub const MERKLE_SNAPSHOT_INTERVAL: u32 = 1024;

/// In-memory tip Money tree. `height` is the block this tree already includes.
pub(super) struct LiveTipTree {
    pub(super) height: Option<u32>,
    pub(super) tree: darkfi_sdk::crypto::MerkleTree,
    /// Persisted bytes did not deserialize. The next append rebuilds from coins.
    pub(super) load_failed: bool,
}

/// Cache layer backed by sled, storing compact blocks and indices.
pub struct Cache {
    /// The sled database
    pub(super) db: sled::Db,
    /// Compact blocks: height (u32 big-endian) → serialized CompactBlock
    pub(super) compact_blocks: sled::Tree,
    /// Block hashes: height (u32 big-endian) → hash ([u8; 32])
    pub(super) block_hashes: sled::Tree,
    /// Reverse index: hash ([u8; 32]) → height (u32 big-endian)
    pub(super) hash_to_height: sled::Tree,
    /// Nullifiers per height: height (u32 big-endian) → serialized Vec<[u8; 32]>
    pub(super) nullifiers: sled::Tree,
    /// Coin commitments per height: height (u32 big-endian) → serialized Vec<[u8; 32]>
    pub(super) coins: sled::Tree,
    /// Money-tree snapshots: height (u32 big-endian) → serialized MerkleTree.
    /// Not deleted by [`Cache::prune_below_height`].
    pub(super) merkle_snapshots: sled::Tree,
    /// Pending OMR clues keyed by tx hash (32 bytes) → clue bytes
    pub(super) omr_clue_hints: sled::Tree,
    /// Parallel tree: tx_hash → u64 LE unix timestamp when the hint was stored (S21).
    pub(super) omr_clue_hint_meta: sled::Tree,
    /// UnifOMR clue public keys: payment_pubkey (32) → serialized pk_clue
    pub(super) omr_clue_pubkeys: sled::Tree,
    /// Pending recipient-encrypted OMR metadata: tx_hash (32) → [output_index:u32 LE] || enc_bytes
    pub(super) omr_metadata_enc: sled::Tree,
    /// Parallel tree: tx_hash → u64 LE unix timestamp when `omr_metadata_enc` was stored.
    pub(super) omr_metadata_enc_meta: sled::Tree,
    /// Server metadata
    pub(super) meta: sled::Tree,
    /// Live tip Money tree. Loaded from sled on open; appends mutate this
    /// instead of deserializing the tip on every block.
    pub(super) tip_tree: Mutex<LiveTipTree>,
    /// Unix seconds of the last full OMR clue-hint meta scan.
    pub(super) omr_hint_sweep_unix: AtomicU64,
    /// Approximate live entry count in `omr_clue_pubkeys` (avoids O(N) sled scans on insert).
    pub(super) clue_pubkey_count: AtomicUsize,
    /// Maximum number of distinct payment pubkeys permitted in `omr_clue_pubkeys`.
    pub(super) max_clue_pubkey_entries: AtomicUsize,
    /// Approximate live entry count in `omr_metadata_enc`.
    pub(super) omr_metadata_enc_count: AtomicUsize,
    /// Maximum number of distinct tx hashes permitted in `omr_metadata_enc`.
    pub(super) max_omr_metadata_enc_entries: AtomicUsize,
}
