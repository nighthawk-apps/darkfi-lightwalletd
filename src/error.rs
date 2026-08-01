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

use thiserror::Error;

/// Lightwallet server error types
#[derive(Debug, Error)]
pub enum LightWalletError {
    #[error("darkfid RPC error: {0}")]
    RpcError(String),

    #[error("Block not found at height {0}")]
    BlockNotFound(u32),

    #[error("Transaction not found: {0}")]
    TxNotFound(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Block processing error: {0}")]
    ProcessingError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Chain reorg detected at height {0}")]
    ReorgDetected(u32),

    #[error("Invalid block range: start={0} end={1}")]
    InvalidBlockRange(u32, u32),

    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type Result<T> = std::result::Result<T, LightWalletError>;

impl From<sled::Error> for LightWalletError {
    fn from(e: sled::Error) -> Self {
        LightWalletError::CacheError(e.to_string())
    }
}
