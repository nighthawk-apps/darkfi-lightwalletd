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

//! gRPC server implementation for the DarkFi Lightwallet Service.
//!
//! Implements the `DarkFiLightWallet` service defined in `lightwallet.proto`.
//! Each method reads from the local sled cache (populated by the block processor)
//! and streams/returns data to wallet clients.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};

// PoolReject is named by the fhe-omr handlers. The default build and unit
// tests still import it with the other pool types.
#[cfg_attr(not(feature = "fhe-omr"), allow(unused_imports))]
use crate::detection_pool::{self, DetectionKeyPool, PoolReject, PooledDetectionKey};

use crate::{
    cache::Cache,
    compact_block::CompactBlock,
    continuity::{check_adjacent_pair, check_successor, discontinuity_status},
    proto::{self, dark_fi_light_wallet_server::DarkFiLightWallet},
    rate_limit::PeerRateLimiter,
    rpc_client::DarkfidRpcClient,
};

mod helpers;
mod rpc;
mod service;
#[cfg(test)]
mod tests;

pub use helpers::*;
pub use service::*;
