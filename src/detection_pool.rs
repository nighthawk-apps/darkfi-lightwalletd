/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

//! In-memory UnifOMR detection-key pool.
//!
//! A process restart drops every handle (clients re-upload). Entries are not
//! written to sled. Handles and key bytes are never logged.

use rand::TryRngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Concurrent pooled handles. Expired rows are removed on insert and on lookup.
pub const MAX_DETECTION_KEY_HANDLES: usize = 4096;

/// Retained key bytes across all handles. One key is about 120 MiB, so the
/// handle cap alone would allow hundreds of GiB. A full pool sends clients to
/// per-request `GetUnifOmrDigest`.
pub const MAX_DETECTION_POOL_BYTES: u64 = 8 << 30;

/// Same horizon as OMR clue hints.
pub const DETECTION_KEY_TTL_SECS: u64 = 86_400;

/// Full-map expiry sweep interval. Lookup also expires the requested handle
/// immediately, and insert always sweeps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Validated detection key retained for later digests.
///
/// `keys` are the reassembled wire bytes that `parse_detection_key` accepted
/// at registration. Digest evaluation passes those bytes back through
/// `encode_messages_padded`, the same function `GetUnifOmrDigest` uses, so the
/// pool does not keep a second partial-decrypt implementation. Parsed BFV
/// ciphertexts are dropped after that check; retaining them would fork the
/// evaluator from the upload path.
#[derive(Clone)]
pub struct PooledDetectionKey {
    pub keys: Vec<Arc<Vec<u8>>>,
    pub network_byte: u8,
    pub expires_unix: u64,
    pub byte_length: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PoolReject {
    Full,
    TooLarge,
    Empty,
}

pub struct DetectionKeyPool {
    entries: HashMap<[u8; 32], PooledDetectionKey>,
    max_handles: usize,
    max_total_bytes: u64,
    total_bytes: u64,
    last_sweep: Instant,
}

fn retained_bytes(key: &PooledDetectionKey) -> u64 {
    key.keys.iter().map(|k| k.len() as u64).sum()
}

impl DetectionKeyPool {
    pub fn new() -> Self {
        Self::with_limits(MAX_DETECTION_KEY_HANDLES, MAX_DETECTION_POOL_BYTES)
    }

    #[cfg(test)]
    pub fn with_capacity(max_handles: usize) -> Self {
        Self::with_limits(max_handles, MAX_DETECTION_POOL_BYTES)
    }

    pub fn with_limits(max_handles: usize, max_total_bytes: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_handles: max_handles.max(1),
            max_total_bytes,
            total_bytes: 0,
            last_sweep: Instant::now(),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Insert a validated key. Sweeps expired rows first.
    ///
    /// The handle is 32 bytes from the OS RNG. It is not derived from the key.
    pub fn insert(
        &mut self,
        key: PooledDetectionKey,
        max_key_bytes: usize,
        now_unix: u64,
    ) -> Result<[u8; 32], PoolReject> {
        self.sweep_expired(now_unix);
        if key.keys.is_empty() || key.keys.iter().any(|k| k.is_empty()) {
            return Err(PoolReject::Empty);
        }
        if key.byte_length > max_key_bytes || key.keys.iter().any(|k| k.len() > max_key_bytes) {
            return Err(PoolReject::TooLarge);
        }
        let bytes = retained_bytes(&key);
        if self.entries.len() >= self.max_handles
            || self.total_bytes.saturating_add(bytes) > self.max_total_bytes
        {
            return Err(PoolReject::Full);
        }
        let mut handle = [0u8; 32];
        for _ in 0..8 {
            rand::rngs::OsRng
                .try_fill_bytes(&mut handle)
                .expect("os rng");
            if !self.entries.contains_key(&handle) {
                break;
            }
        }
        if let Some(old) = self.entries.insert(handle, key) {
            self.total_bytes = self.total_bytes.saturating_sub(retained_bytes(&old));
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        Ok(handle)
    }

    /// Clone the entry if it is still live. Expired and unknown handles yield `None`.
    pub fn lookup(&mut self, handle: &[u8; 32], now_unix: u64) -> Option<PooledDetectionKey> {
        if self.last_sweep.elapsed() >= SWEEP_INTERVAL {
            self.sweep_expired(now_unix);
        }
        match self.entries.get(handle) {
            Some(entry) if entry.expires_unix > now_unix => Some(entry.clone()),
            Some(_) => {
                if let Some(old) = self.entries.remove(handle) {
                    self.total_bytes = self.total_bytes.saturating_sub(retained_bytes(&old));
                }
                None
            }
            None => None,
        }
    }

    fn sweep_expired(&mut self, now_unix: u64) {
        let mut freed = 0u64;
        self.entries.retain(|_, entry| {
            let live = entry.expires_unix > now_unix;
            if !live {
                freed = freed.saturating_add(retained_bytes(entry));
            }
            live
        });
        self.total_bytes = self.total_bytes.saturating_sub(freed);
        self.last_sweep = Instant::now();
    }
}

impl Default for DetectionKeyPool {
    fn default() -> Self {
        Self::new()
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn expiry_from(now_unix: u64) -> u64 {
    now_unix.saturating_add(DETECTION_KEY_TTL_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_expiring(at: u64) -> PooledDetectionKey {
        PooledDetectionKey {
            keys: vec![Arc::new(vec![0xAB, 0xCD])],
            network_byte: 1,
            expires_unix: at,
            byte_length: 2,
        }
    }

    #[test]
    fn expired_handle_is_removed_on_lookup_and_missing_is_empty() {
        let mut pool = DetectionKeyPool::with_capacity(4);
        let handle = pool.insert(key_expiring(50), 1024, 0).unwrap();
        assert_eq!(handle.len(), 32);
        assert!(pool.lookup(&handle, 49).is_some());
        assert!(
            pool.lookup(&handle, 50).is_none(),
            "expires_unix is exclusive"
        );
        assert!(pool.lookup(&handle, 51).is_none());
        assert_eq!(pool.len(), 0);
        let unknown = [7u8; 32];
        assert!(pool.lookup(&unknown, 0).is_none());
    }

    #[test]
    fn insert_sweeps_expired_before_enforcing_the_cap() {
        let mut pool = DetectionKeyPool::with_capacity(1);
        let first = pool.insert(key_expiring(5), 1024, 0).unwrap();
        assert!(matches!(
            pool.insert(key_expiring(100), 1024, 1),
            Err(PoolReject::Full)
        ));
        let second = pool.insert(key_expiring(100), 1024, 10).unwrap();
        assert_ne!(first, second);
        assert!(pool.lookup(&first, 10).is_none());
        let live = pool.lookup(&second, 10).unwrap();
        assert_eq!(live.network_byte, 1);
        assert_eq!(live.byte_length, 2);
        assert_eq!(live.expires_unix, 100);
    }

    #[test]
    fn rejects_oversize_and_empty_keys() {
        let mut pool = DetectionKeyPool::with_capacity(2);
        let mut big = key_expiring(10);
        big.byte_length = 100;
        big.keys = vec![Arc::new(vec![1u8; 100])];
        assert!(matches!(pool.insert(big, 16, 0), Err(PoolReject::TooLarge)));
        let mut empty = key_expiring(10);
        empty.keys.clear();
        empty.byte_length = 0;
        assert!(matches!(pool.insert(empty, 16, 0), Err(PoolReject::Empty)));
    }

    #[test]
    fn byte_budget_rejects_until_expired_keys_are_swept() {
        let mut pool = DetectionKeyPool::with_limits(8, 3);
        let first = pool.insert(key_expiring(5), 1024, 0).unwrap();
        assert!(matches!(
            pool.insert(key_expiring(100), 1024, 1),
            Err(PoolReject::Full)
        ));
        assert!(pool.lookup(&first, 6).is_none());
        pool.insert(key_expiring(100), 1024, 6).unwrap();
        assert_eq!(pool.total_bytes, 2);
    }
}
