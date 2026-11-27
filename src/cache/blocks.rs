use super::*;

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
        let omr_metadata_enc_meta = db.open_tree(OMR_METADATA_ENC_META_TREE)?;
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
            omr_metadata_enc_meta,
            meta,
            tip_tree: Mutex::new(LiveTipTree {
                height: None,
                tree: Self::empty_tip_tree(),
                load_failed: false,
            }),
            omr_hint_sweep_unix: AtomicU64::new(0),
            clue_pubkey_count: AtomicUsize::new(0),
            max_clue_pubkey_entries: AtomicUsize::new(MAX_CLUE_PUBKEY_ENTRIES),
            omr_metadata_enc_count: AtomicUsize::new(0),
            max_omr_metadata_enc_entries: AtomicUsize::new(MAX_OMR_METADATA_ENC_ENTRIES),
        };
        cache.retire_obsolete_names()?;
        cache
            .clue_pubkey_count
            .store(cache.omr_clue_pubkeys.len(), Ordering::Relaxed);
        cache.ensure_cache_format()?;
        cache.verify_tip_readable()?;
        cache.reconcile_tip_merkle()?;
        // Old caches have the tip tree only in META. Index it so checkpoint
        // reads see a snapshot before the next block arrives. Missing interval
        // rows appear as later heights are appended or the tip is rebuilt.
        cache.index_existing_tip_snapshot()?;
        // Restart must append to the persisted tip, not an empty sentinel.
        cache.load_live_tip_from_disk()?;
        // Count ciphertext rows before the startup sweep decrements for each delete.
        cache
            .omr_metadata_enc_count
            .store(cache.omr_metadata_enc.len(), Ordering::Relaxed);
        // Best-effort prune of orphan hints left from previous runs (S21).
        // Also drops legacy omr_metadata_enc rows that have no TTL meta.
        let _ = cache.prune_expired_omr_clue_hints();
        Ok(cache)
    }

    /// Drop sled names left behind when trees and meta keys lost their
    /// `_v1` / `_v2` suffixes. The weak Pcg32 attestation key is deleted.
    /// The CSPRNG attestation key and the decoy pepper are copied forward
    /// once, then the old rows are removed. Safe to run on every open.
    pub(super) fn retire_obsolete_names(&self) -> Result<()> {
        const OLD_ATTEST_V1: &[u8] = b"unifomr_dir_attest_sk_v1";
        const OLD_ATTEST_V2: &[u8] = b"unifomr_dir_attest_sk_v2";
        const ATTEST: &[u8] = b"unifomr_dir_attest_sk";
        const OLD_PEPPER: &[u8] = b"unifomr_clue_dir_pepper_v1";
        const OLD_CLUE_TREE: &str = "lightwalletd_omr_clue_pubkeys_v2";
        const OLD_CLUE_TREE_V1: &str = "lightwalletd_omr_clue_pubkeys_v1";

        let attest_missing = !matches!(self.meta.get(ATTEST)?, Some(bytes) if bytes.len() == 32);
        if attest_missing {
            if let Some(old) = self.meta.get(OLD_ATTEST_V2)? {
                if old.len() == 32 {
                    self.meta.insert(ATTEST, old.as_ref())?;
                }
            }
        }
        self.meta.remove(OLD_ATTEST_V1)?;
        self.meta.remove(OLD_ATTEST_V2)?;

        let pepper_missing =
            !matches!(self.meta.get(META_CLUE_DIR_PEPPER)?, Some(bytes) if bytes.len() == 32);
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

    pub(super) fn tree_exists(&self, name: &str) -> bool {
        self.db
            .tree_names()
            .iter()
            .any(|existing| existing.as_ref() == name.as_bytes())
    }

    /// Drop compact blocks and the indexes rebuilt from them.
    ///
    /// Clue registrations and the directory attestation key stay. The poller
    /// refills blocks from darkfid.
    pub fn clear_derived_block_cache(&self) -> Result<()> {
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
        self.meta.remove(META_TIP_CHAIN_FACTS).map_err(io)?;
        if let Ok(mut tip) = self.tip_tree.lock() {
            tip.height = None;
            tip.tree = Self::empty_tip_tree();
            tip.load_failed = false;
        }
        Ok(())
    }

    pub(super) fn ensure_cache_format(&self) -> Result<()> {
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

    pub(super) fn verify_tip_readable(&self) -> Result<()> {
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

    pub(super) fn rewind_marker(&self) -> Result<Option<u32>> {
        let Some(bytes) = self.meta.get(META_REWINDING_TO)? else {
            return Ok(None);
        };
        if bytes.len() != 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_be_bytes(bytes.as_ref().try_into().unwrap())))
    }

    /// Reconcile `META_TIP_HEIGHT` and `META_TIP_MERKLE_HEIGHT` on startup.
    ///
    /// A crash between writing the tip height and persisting the updated tip
    /// Merkle tree can leave `tip_height != tip_merkle_height`, or leave stale
    /// Merkle metadata after an empty reset. Rebuild or clear immediately so
    /// `GetTreeState` does not stay wedged until the next block arrives.
    pub(super) fn reconcile_tip_merkle(&self) -> Result<()> {
        match self.get_tip()? {
            None => {
                let has_merkle_meta = self.meta.get(META_TIP_MERKLE_HEIGHT)?.is_some()
                    || self.meta.get(META_TIP_MERKLE_TREE)?.is_some()
                    || !self.merkle_snapshots.is_empty();
                if has_merkle_meta {
                    warn!(
                        target: "lightwalletd::cache",
                        "Cache has no tip but retained Merkle metadata/snapshots; clearing"
                    );
                    self.reset_tip_merkle_state()?;
                    self.db.flush()?;
                }
                Ok(())
            }
            Some((tip_height, _)) => {
                let merkle_height = self.get_tip_tree_state()?.map(|(h, _)| h);
                if merkle_height != Some(tip_height) {
                    warn!(
                        target: "lightwalletd::cache",
                        "Tip height {tip_height} != tip Merkle height {merkle_height:?}; rebuilding tip Merkle tree"
                    );
                    self.rebuild_tip_merkle_tree(tip_height)?;
                    self.db.flush()?;
                }
                Ok(())
            }
        }
    }

    pub(super) fn reset_tip_merkle_state(&self) -> Result<()> {
        self.meta.remove(META_TIP_MERKLE_TREE)?;
        self.meta.remove(META_TIP_MERKLE_HEIGHT)?;
        self.clear_merkle_snapshots()?;
        let mut live = self.lock_tip_tree();
        live.height = None;
        live.tree = Self::empty_tip_tree();
        live.load_failed = false;
        Ok(())
    }

    /// Point the tip at the highest compact block that is still on disk.
    pub(super) fn repair_missing_tip(&self, recorded: u32) -> Result<()> {
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
        self.meta.remove(META_TIP_CHAIN_FACTS)?;
        self.meta.remove(META_REWINDING_TO)?;
        self.reset_tip_merkle_state()?;
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

        // Store height → hash, cleaning stale reverse index when overwriting a different hash
        if let Some(old_hash) = self.block_hashes.insert(height_key, &block.hash)? {
            if old_hash.as_ref() != block.hash.as_slice()
                && self
                    .hash_to_height
                    .get(old_hash.as_ref())?
                    .is_some_and(|v| v.as_ref() == height_key.as_slice())
            {
                self.hash_to_height.remove(old_hash.as_ref())?;
            }
        }

        // Store hash → height
        self.hash_to_height
            .insert(block.hash, height_key.as_ref())?;

        // Extract and store nullifiers (remove stale key when overwriting with empty set)
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
        } else {
            self.nullifiers.remove(height_key)?;
        }

        // Extract and store coin commitments (remove stale key when overwriting with empty set)
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
        } else {
            self.coins.remove(height_key)?;
        }

        // Historical backfill (e.g. missing genesis after a birthday import)
        // must not rewind META_TIP or append coins at the end of the live tree.
        if let Some((tip_h, _)) = self.get_tip()? {
            if block.height < tip_h {
                if self.pruned_below_height()? > block.height {
                    return Ok(());
                }
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

        let existing = self.omr_clue_hints.get(tx_hash.as_slice())?;
        if existing.is_none() && self.omr_clue_hints.len() >= MAX_OMR_METADATA_ENC_ENTRIES {
            return Err(LightWalletError::CacheError(
                "omr clue hint registry is full".into(),
            ));
        }
        let mut clues = match existing {
            Some(bytes) => decode_omr_clue_hints(&bytes),
            None => Vec::new(),
        };
        const MAX_CLUE_HINTS_PER_TX: usize = 65;
        if clues.len() >= MAX_CLUE_HINTS_PER_TX {
            return Err(LightWalletError::CacheError(
                "per-tx OMR clue hint limit exceeded".into(),
            ));
        }
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
            "Stored OMR clue hint ({} bytes, output_index={:?})",
            clue.len(),
            output_index,
        );
        Ok(())
    }

    /// Store recipient-encrypted OMR metadata for a pending transaction.
    ///
    /// Uses the same output_index + data wire format as `store_omr_clue_hint`
    /// and shares its 24h TTL (`OMR_CLUE_HINT_TTL_SECS`) so memos survive reorgs
    /// without unbounded growth. LWD cannot decrypt this — it's encrypted with
    /// the recipient's pubkey.
    ///
    /// New tx hashes are refused once [`MAX_OMR_METADATA_ENC_ENTRIES`] live rows
    /// exist, matching clue-pubkey admission. Replacing an existing hash does
    /// not consume another slot.
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
        self.prune_expired_omr_clue_hints()?;
        self.drop_omr_metadata_enc_if_expired(tx_hash)?;

        let existing = self.omr_metadata_enc.get(tx_hash.as_slice())?;
        let mut reserved_slot = false;
        if existing.is_none() {
            self.reserve_omr_metadata_enc_slot()?;
            reserved_slot = true;
        }

        let now = omr_hint_unix_now();
        // TTL meta is written before ciphertext so a concurrent sweep cannot
        // treat this insert as a legacy row that has no TTL.
        if let Err(e) = self
            .omr_metadata_enc_meta
            .insert(tx_hash.as_slice(), &now.to_le_bytes())
        {
            if reserved_slot {
                self.release_omr_metadata_enc_slot();
            }
            return Err(e.into());
        }

        let mut stored = Vec::with_capacity(4 + metadata_enc.len());
        let idx = output_index.unwrap_or(u32::MAX);
        stored.extend_from_slice(&idx.to_le_bytes());
        stored.extend_from_slice(&metadata_enc);
        let prev = match self
            .omr_metadata_enc
            .insert(tx_hash.as_slice(), stored.as_slice())
        {
            Ok(prev) => prev,
            Err(e) => {
                if reserved_slot {
                    let _ = self.omr_metadata_enc_meta.remove(tx_hash.as_slice());
                    self.release_omr_metadata_enc_slot();
                }
                return Err(e.into());
            }
        };
        if reserved_slot && prev.is_some() {
            // Raced with a concurrent insert of the same key; release our extra count.
            self.release_omr_metadata_enc_slot();
        } else if !reserved_slot && prev.is_none() {
            self.omr_metadata_enc_count.fetch_add(1, Ordering::AcqRel);
        }
        debug!(
            target: "lightwalletd::cache",
            "Stored OMR metadata_enc ({} bytes, output_index={:?})",
            metadata_enc.len(),
            output_index,
        );
        Ok(())
    }

    /// Reserve one `omr_metadata_enc` slot. Same compare-exchange admission as
    /// [`Self::store_clue_public_key`].
    pub(super) fn reserve_omr_metadata_enc_slot(&self) -> Result<()> {
        let cap = self.max_omr_metadata_enc_entries.load(Ordering::Relaxed);
        let mut cur = self.omr_metadata_enc_count.load(Ordering::Acquire);
        loop {
            if cur >= cap {
                return Err(LightWalletError::CacheError(
                    "omr metadata registry is full".into(),
                ));
            }
            match self.omr_metadata_enc_count.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    pub(super) fn release_omr_metadata_enc_slot(&self) {
        // Saturating: a stale count must not wrap and lock the registry.
        // `try_update` is the newer name. This crate's MSRV is 1.88, which
        // still calls the operation `fetch_update`.
        #[allow(deprecated)]
        let _ =
            self.omr_metadata_enc_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                    cur.checked_sub(1)
                });
    }

    /// True if unexpired recipient-encrypted OMR metadata is already stored for this tx.
    pub fn has_omr_metadata_enc(&self, tx_hash: &[u8; 32]) -> Result<bool> {
        self.prune_expired_omr_clue_hints()?;
        if self.drop_omr_metadata_enc_if_expired(tx_hash)? {
            return Ok(false);
        }
        Ok(self.omr_metadata_enc.contains_key(tx_hash.as_slice())?)
    }

    /// Drop pending recipient-encrypted OMR metadata (e.g. its transaction was rejected).
    pub fn remove_omr_metadata_enc(&self, tx_hash: &[u8; 32]) -> Result<()> {
        self.delete_omr_metadata_enc(tx_hash.as_slice())?;
        Ok(())
    }

    /// Remove ciphertext and TTL meta. Returns whether a ciphertext row was present.
    pub(super) fn delete_omr_metadata_enc(&self, key: &[u8]) -> Result<bool> {
        let removed = self.omr_metadata_enc.remove(key)?;
        self.omr_metadata_enc_meta.remove(key)?;
        if removed.is_some() {
            self.release_omr_metadata_enc_slot();
            Ok(true)
        } else {
            Ok(false)
        }
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

    /// Remove only specific output indices inserted by one failed SendTransaction call,
    /// leaving pre-existing hints from other peers/calls intact.
    pub fn remove_omr_clue_hint_indices(&self, tx_hash: &[u8; 32], indices: &[u32]) -> Result<()> {
        if indices.is_empty() {
            return Ok(());
        }
        let Some(bytes) = self.omr_clue_hints.get(tx_hash.as_slice())? else {
            return Ok(());
        };
        let mut clues = decode_omr_clue_hints(&bytes);
        let orig_len = clues.len();
        clues.retain(|(idx, _)| !idx.is_some_and(|i| indices.contains(&i)));
        if clues.len() == orig_len {
            return Ok(());
        }
        if clues.is_empty() {
            return self.remove_omr_clue_hint(tx_hash);
        }
        let stored = encode_omr_clue_hints(&clues);
        self.omr_clue_hints
            .insert(tx_hash.as_slice(), stored.as_slice())?;
        Ok(())
    }
}

impl Cache {
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

        let mut deleted_blocks = 0usize;
        if let Some(next_height) = height.checked_add(1) {
            let delete_from = next_height.to_be_bytes();

            // Sweep every derived tree independently above `height` so a crash
            // mid-rewind cannot leave orphan rows in sibling trees.
            let block_keys: Vec<sled::IVec> = self
                .compact_blocks
                .range(delete_from..)
                .filter_map(|r| r.ok().map(|(k, _)| k))
                .collect();
            deleted_blocks = block_keys.len();
            for key in &block_keys {
                self.compact_blocks.remove(key)?;
            }

            let hash_entries: Vec<(sled::IVec, sled::IVec)> = self
                .block_hashes
                .range(delete_from..)
                .filter_map(|r| r.ok())
                .collect();
            for (key, hash) in &hash_entries {
                if self
                    .hash_to_height
                    .get(hash.as_ref())?
                    .is_some_and(|v| v.as_ref() == key.as_ref())
                {
                    self.hash_to_height.remove(hash.as_ref())?;
                }
                self.block_hashes.remove(key)?;
            }

            let nullifier_keys: Vec<sled::IVec> = self
                .nullifiers
                .range(delete_from..)
                .filter_map(|r| r.ok().map(|(k, _)| k))
                .collect();
            for key in &nullifier_keys {
                self.nullifiers.remove(key)?;
            }

            let coin_keys: Vec<sled::IVec> = self
                .coins
                .range(delete_from..)
                .filter_map(|r| r.ok().map(|(k, _)| k))
                .collect();
            for key in &coin_keys {
                self.coins.remove(key)?;
            }
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

        self.meta.remove(META_TIP_CHAIN_FACTS)?;
        self.meta.remove(META_REWINDING_TO)?;
        // Flush to disk
        self.db.flush()?;

        info!(
            target: "lightwalletd::cache",
            "Cache rewound to height {height}, deleted {deleted_blocks} compact block entries"
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

    /// Empty Money Merkle tree containing the on-chain dummy `ZERO` sentinel leaf.
    pub fn empty_tip_tree() -> darkfi_sdk::crypto::MerkleTree {
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

    pub(super) fn coin_to_merkle_node(coin: &[u8; 32]) -> Result<darkfi_sdk::crypto::MerkleNode> {
        darkfi_sdk::crypto::MerkleNode::from_bytes(*coin).ok_or_else(|| {
            LightWalletError::SerializationError(
                "coin bytes are not a canonical pallas::Base".into(),
            )
        })
    }

    pub(super) fn lock_tip_tree(&self) -> std::sync::MutexGuard<'_, LiveTipTree> {
        self.tip_tree.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Copy `META_TIP_MERKLE_*` into the in-memory tree. Missing meta keeps
    /// the empty sentinel created in [`Cache::new`].
    pub(super) fn load_live_tip_from_disk(&self) -> Result<()> {
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

    pub(super) fn store_tip_tree(
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
    pub(super) fn record_tree_snapshot(
        &self,
        prev_height: Option<u32>,
        height: u32,
        tree_data: &[u8],
        is_tip: bool,
    ) -> Result<()> {
        if height.is_multiple_of(MERKLE_SNAPSHOT_INTERVAL) || is_tip {
            self.merkle_snapshots
                .insert(height.to_be_bytes(), tree_data)?;
        }
        if is_tip {
            self.drop_non_interval_snapshots_except(prev_height, height)?;
        }
        Ok(())
    }

    /// Remove the previous tip row when it is not an interval boundary.
    ///
    /// One key delete. Interval snapshots and `keep` stay.
    pub(super) fn drop_non_interval_snapshots_except(
        &self,
        prev: Option<u32>,
        keep: u32,
    ) -> Result<()> {
        let Some(prev) = prev else {
            return Ok(());
        };
        if prev != keep && !prev.is_multiple_of(MERKLE_SNAPSHOT_INTERVAL) {
            self.merkle_snapshots.remove(prev.to_be_bytes())?;
        }
        Ok(())
    }

    pub(super) fn delete_snapshots_above(&self, height: u32) -> Result<()> {
        let Some(start) = height.checked_add(1) else {
            return Ok(());
        };
        self.delete_snapshots_at_or_above(start)
    }

    pub(super) fn delete_snapshots_at_or_above(&self, height: u32) -> Result<()> {
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

    pub(super) fn clear_merkle_snapshots(&self) -> Result<()> {
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
    pub(super) fn index_existing_tip_snapshot(&self) -> Result<()> {
        let Some((height, data)) = self.get_tip_tree_state()? else {
            return Ok(());
        };
        if self.merkle_snapshots.get(height.to_be_bytes())?.is_none() {
            self.merkle_snapshots
                .insert(height.to_be_bytes(), data.as_slice())?;
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
    pub(super) fn snapshot_heights(&self) -> Result<Vec<u32>> {
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

    pub(super) fn append_coins_to_tip_tree(&self, height: u32, coins: &[[u8; 32]]) -> Result<()> {
        let (needs_rebuild, overwrite) = {
            let live = self.lock_tip_tree();
            let overwrite = live.height.is_some_and(|prev| height <= prev);
            let needs_rebuild = live.load_failed
                || match live.height {
                    Some(prev) => height != prev.saturating_add(1),
                    None => false,
                };
            (needs_rebuild, overwrite)
        };
        if needs_rebuild {
            if overwrite {
                self.delete_snapshots_at_or_above(height)?;
            }
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
            .map(Self::coin_to_merkle_node)
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

    pub(super) fn reload_live_tip_locked(&self, live: &mut LiveTipTree) {
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

    pub(super) fn rebuild_tip_merkle_tree(&self, tip_height: u32) -> Result<()> {
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
                if boundary.is_multiple_of(MERKLE_SNAPSHOT_INTERVAL) {
                    let tree_data = darkfi_serial::serialize(&tree);
                    self.merkle_snapshots
                        .insert(boundary.to_be_bytes(), tree_data.as_slice())?;
                }
            }
            if boundary >= tip_height {
                break;
            }
            let next = if boundary.is_multiple_of(MERKLE_SNAPSHOT_INTERVAL) {
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
    /// Height below which historical blocks were pruned (0 if unpruned).
    pub fn pruned_below_height(&self) -> Result<u32> {
        let Some(bytes) = self.meta.get(META_PRUNED_BELOW_HEIGHT)? else {
            return Ok(0);
        };
        if bytes.len() != 4 {
            return Ok(0);
        }
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

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

            // Preserve block_hashes for retained merkle snapshots so GetTreeState /
            // GetCheckpointSnapshot still return the checkpoint block_hash.
            if !self.merkle_snapshots.contains_key(key)? {
                if let Some(hash) = self.block_hashes.remove(key)? {
                    self.hash_to_height.remove(hash.as_ref())?;
                }
            }

            self.nullifiers.remove(key)?;
            self.coins.remove(key)?;
            pruned_count += 1;
        }

        let prev_pruned = self.pruned_below_height()?;
        if min_height > prev_pruned {
            self.meta
                .insert(META_PRUNED_BELOW_HEIGHT, &min_height.to_be_bytes())?;
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
