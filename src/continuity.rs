/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

//! Compact-block chain continuity (GHSA-m7j5 analogue).
//!
//! A streamed range must describe a single fork: consecutive heights and
//! `block[n+1].prev_hash == block[n].hash`. Gaps (prune / rewind races) and
//! mixed-fork pairs fail the stream with `Aborted` — not `Internal`, which
//! wallets retry as a server fault.

use tonic::Status;

use crate::compact_block::CompactBlock;

/// gRPC status for a range that is not a connected chain.
pub fn discontinuity_status() -> Status {
    Status::aborted("chain discontinuity")
}

/// `next` must be the block immediately after `prev` on the same fork.
#[allow(clippy::result_large_err)]
pub fn check_successor(prev: &CompactBlock, next: &CompactBlock) -> Result<(), Status> {
    if next.height != prev.height.saturating_add(1) || next.prev_hash != prev.hash {
        return Err(discontinuity_status());
    }
    Ok(())
}

/// Adjacent entries in a sparse height list (h, h+1) must connect.
#[allow(clippy::result_large_err)]
pub fn check_adjacent_pair(left: &CompactBlock, right: &CompactBlock) -> Result<(), Status> {
    if right.height == left.height.saturating_add(1) {
        check_successor(left, right)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact_block::{CompactBlock, CompactTx};

    fn blk(height: u32, hash: u8, prev: u8) -> CompactBlock {
        CompactBlock {
            height,
            hash: [hash; 32],
            prev_hash: [prev; 32],
            timestamp: 0,
            txs: Vec::<CompactTx>::new(),
        }
    }

    #[test]
    fn successor_accepts_connected_pair() {
        let a = blk(10, 1, 0);
        let b = blk(11, 2, 1);
        assert!(check_successor(&a, &b).is_ok());
    }

    #[test]
    fn successor_rejects_hash_mismatch() {
        let a = blk(10, 1, 0);
        let b = blk(11, 2, 9);
        assert_eq!(
            check_successor(&a, &b).unwrap_err().code(),
            tonic::Code::Aborted
        );
    }

    #[test]
    fn successor_rejects_height_gap() {
        let a = blk(10, 1, 0);
        let b = blk(12, 2, 1);
        assert!(check_successor(&a, &b).is_err());
    }

    #[test]
    fn sparse_non_adjacent_skips_prev_check() {
        let a = blk(10, 1, 0);
        let c = blk(12, 3, 99);
        assert!(check_adjacent_pair(&a, &c).is_ok());
    }
}
