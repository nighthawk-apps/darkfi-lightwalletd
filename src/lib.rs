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

//! DarkFi Lightwallet Server
//!
//! A bandwidth-efficient backend for DarkFi light wallets. Connects to a
//! `darkfid` full node via JSON-RPC and serves compact blocks (stripped of
//! ZK proofs and signatures) over gRPC to mobile and desktop wallet clients.
//!
//! ## Architecture
//!
//! ```text
//! darkfid (full node)  <--JSON-RPC-->  darkfi-lightwalletd  <--gRPC-->  Wallet
//! ```
//!
//! The server:
//! - Polls darkfid for new blocks
//! - Strips proofs and signatures, keeping only wallet-relevant data
//! - Caches compact blocks in a local sled database
//! - Serves them to clients via gRPC streaming
//! - Proxies transaction submission back to darkfid

pub mod block_processor;
pub mod cache;
pub mod chain_poller;
pub mod clue_ownership;
pub mod compact_block;
pub mod config;
pub mod error;
pub mod limited_incoming;
pub mod omr_detector;
pub mod omr_envelope;
pub mod omr_traits;
#[cfg(feature = "fhe-omr")]
pub mod pir_server;
pub mod rate_limit;
pub mod rpc_client;
pub mod server;
#[cfg(feature = "fhe-omr")]
pub mod unifomr;
/// Generated protobuf types
pub mod proto {
    // This will be populated by tonic-build or a checked-in generated file.
    // For now, we include a stub module.
    tonic::include_proto!("darkfi.lightwallet");
}
