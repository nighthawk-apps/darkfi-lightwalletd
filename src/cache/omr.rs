use super::*;

impl Cache {
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
        let existing = self.omr_clue_pubkeys.get(payment_pubkey.as_slice())?;
        let mut reserved_slot = false;
        if let Some(ref existing) = existing {
            if let Some((stored_version, _stored_proof, stored_clue)) =
                Self::parse_clue_pubkey_value(existing)
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
        } else {
            let cap = self.max_clue_pubkey_entries.load(Ordering::Relaxed);
            let mut cur = self.clue_pubkey_count.load(Ordering::Acquire);
            loop {
                if cur >= cap {
                    return Err(LightWalletError::CacheError(
                        "clue public key registry is full".into(),
                    ));
                }
                match self.clue_pubkey_count.compare_exchange_weak(
                    cur,
                    cur + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
            reserved_slot = true;
        }
        let mut value = Vec::with_capacity(8 + 4 + ownership_proof.len() + clue_pk.len());
        value.extend_from_slice(&key_version.to_le_bytes());
        value.extend_from_slice(&(ownership_proof.len() as u32).to_le_bytes());
        value.extend_from_slice(ownership_proof);
        value.extend_from_slice(clue_pk);
        let prev = match self
            .omr_clue_pubkeys
            .insert(payment_pubkey.as_slice(), value)
        {
            Ok(prev) => prev,
            Err(e) => {
                if reserved_slot {
                    self.clue_pubkey_count.fetch_sub(1, Ordering::AcqRel);
                }
                return Err(e.into());
            }
        };
        if reserved_slot && prev.is_some() {
            // Raced with a concurrent insert of the same key; release our extra count.
            self.clue_pubkey_count.fetch_sub(1, Ordering::AcqRel);
        } else if !reserved_slot && prev.is_none() {
            self.clue_pubkey_count.fetch_add(1, Ordering::AcqRel);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_max_clue_pubkey_entries(&self, max: usize) {
        self.max_clue_pubkey_entries.store(max, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_max_omr_metadata_enc_entries(&self, max: usize) {
        self.max_omr_metadata_enc_entries
            .store(max, Ordering::Relaxed);
    }

    /// Parse stored clue-directory value → `(key_version, ownership_proof, clue_pk)`.
    ///
    /// Format: `key_version u64 LE || proof_len u32 LE || proof || clue_pk`.
    /// Older rows may start with the `b"v3"` tag; those bytes are skipped.
    pub(super) fn parse_clue_pubkey_value(v: &[u8]) -> Option<(u64, Vec<u8>, Vec<u8>)> {
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
    ) -> Result<Option<CluePublicKeyEntry>> {
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

    pub(super) fn sweep_expired_omr_clue_hints_at(&self, now: u64) -> Result<()> {
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

        let mut expired_meta = Vec::new();
        for item in self.omr_metadata_enc_meta.iter() {
            let (key, value) = item?;
            if omr_metadata_enc_row_expired(Some(value.as_ref()), now) {
                expired_meta.push(key.to_vec());
            }
        }
        for key in expired_meta {
            self.delete_omr_metadata_enc(key.as_slice())?;
        }

        // 0.3.12 stored ciphertext with no TTL meta. Those rows never expire
        // on their own; drop them instead of backfilling a timestamp.
        let mut legacy = Vec::new();
        for item in self.omr_metadata_enc.iter() {
            let (key, _) = item?;
            if self.omr_metadata_enc_meta.get(key.as_ref())?.is_none() {
                legacy.push(key.to_vec());
            }
        }
        for key in legacy {
            // A store may have written TTL meta after this key was queued.
            if self.omr_metadata_enc_meta.get(key.as_slice())?.is_some() {
                continue;
            }
            self.delete_omr_metadata_enc(key.as_slice())?;
        }
        Ok(())
    }

    /// Drop this tx's hint when its meta row is expired. Does not scan the tree.
    pub(super) fn drop_omr_clue_hint_if_expired(&self, tx_hash: &[u8; 32]) -> Result<bool> {
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

    /// Drop this tx's encrypted OMR metadata when its TTL has elapsed.
    ///
    /// A ciphertext row with no meta record is a legacy 0.3.12 insert. It has
    /// no TTL, so it is deleted rather than kept.
    pub(super) fn drop_omr_metadata_enc_if_expired(&self, tx_hash: &[u8; 32]) -> Result<bool> {
        let now = omr_hint_unix_now();
        match self.omr_metadata_enc_meta.get(tx_hash.as_slice())? {
            Some(value) if !omr_metadata_enc_row_expired(Some(value.as_ref()), now) => Ok(false),
            Some(_) => self.delete_omr_metadata_enc(tx_hash.as_slice()),
            None => {
                if self.omr_metadata_enc.get(tx_hash.as_slice())?.is_some() {
                    self.delete_omr_metadata_enc(tx_hash.as_slice())
                } else {
                    Ok(false)
                }
            }
        }
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

            // Merge recipient-encrypted OMR metadata (kept until TTL expiry so
            // reorgs can re-merge it, matching omr_clue_hints).
            if !self.drop_omr_metadata_enc_if_expired(&tx_hash)? {
                if let Some(stored_meta) = self.omr_metadata_enc.get(tx_hash.as_slice())? {
                    let (output_index, meta_enc) = parse_stored_omr_clue_hint(&stored_meta);
                    if meta_enc.is_empty() {
                        self.delete_omr_metadata_enc(tx_hash.as_slice())?;
                    } else if output_index.is_some()
                        || !tx.outputs.iter().any(|o| o.omr_metadata_enc == meta_enc)
                    {
                        let target = match output_index {
                            Some(idx) => tx.outputs.get_mut(idx as usize),
                            None => tx
                                .outputs
                                .iter_mut()
                                .find(|o| o.omr_metadata_enc.is_empty()),
                        };
                        if let Some(output) = target {
                            if output.omr_metadata_enc.is_empty() {
                                output.omr_metadata_enc = meta_enc;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub(super) fn omr_hint_unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(super) fn omr_hint_meta_expired(value: &[u8], now: u64) -> bool {
    if value.len() < 8 {
        return true;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&value[..8]);
    let stored_at = u64::from_le_bytes(buf);
    now.saturating_sub(stored_at) > OMR_CLUE_HINT_TTL_SECS
}

/// `None` is a legacy ciphertext row with no TTL meta. Those are not kept.
pub(super) fn omr_metadata_enc_row_expired(meta: Option<&[u8]>, now: u64) -> bool {
    match meta {
        Some(value) => omr_hint_meta_expired(value, now),
        None => true,
    }
}

pub(super) fn height_from_snapshot_key(key: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = key.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// Stored clue hints are an `MCL1` list of `(output_index, clue)`.
pub(super) const OMR_CLUE_LIST_MAGIC: &[u8; 4] = b"MCL1";

/// Length-prefixed list of `(output_index, clue)`. `u32::MAX` means first empty.
pub(super) fn encode_omr_clue_hints(clues: &[(Option<u32>, Vec<u8>)]) -> Vec<u8> {
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

pub(super) fn decode_omr_clue_hints(stored: &[u8]) -> Vec<(Option<u32>, Vec<u8>)> {
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

pub(super) fn parse_stored_omr_clue_hint(stored: &[u8]) -> (Option<u32>, Vec<u8>) {
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
