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

//! JSON-RPC client for communicating with a `darkfid` full node.
//!
//! This module wraps the darkfid JSON-RPC API, providing typed methods for:
//! - Fetching blocks by height
//! - Fetching transactions by hash
//! - Getting chain tip information
//! - Subscribing to new blocks
//! - Submitting transactions
//! - Querying contract state

use darkfi::{blockchain::block_store::BlockInfo, util::encoding::base64};
use darkfi_serial::deserialize_async;
use tinyjson::JsonValue;
use tracing::{debug, info};
use url::Url;

use crate::error::{LightWalletError, Result};

/// Client for communicating with a darkfid full node via JSON-RPC.
pub struct DarkfidRpcClient {
    /// The URL of the darkfid JSON-RPC endpoint
    endpoint: Url,
}

impl DarkfidRpcClient {
    /// Create a new RPC client pointing at the given darkfid endpoint.
    pub fn new(endpoint: Url) -> Self {
        Self { endpoint }
    }

    /// Fetch a block at the given height from darkfid.
    ///
    /// Maps to: `blockchain.get_block(height) -> base64(BlockInfo)`
    pub async fn get_block(&self, height: u32) -> Result<BlockInfo> {
        debug!(target: "lightwalletd::rpc_client", "Fetching block at height {height}");

        let params = JsonValue::Array(vec![JsonValue::Number(height as f64)]);
        let response = self.request("blockchain.get_block", params).await?;

        let block_b64 = response.get::<String>().ok_or_else(|| {
            LightWalletError::RpcError(format!("Expected string response for get_block({height})"))
        })?;

        let block_bytes = base64::decode(block_b64).ok_or_else(|| {
            LightWalletError::SerializationError(format!(
                "Failed to decode base64 for block at height {height}"
            ))
        })?;

        let block_info: BlockInfo = deserialize_async(&block_bytes).await.map_err(|e| {
            LightWalletError::SerializationError(format!(
                "Failed to deserialize BlockInfo at height {height}: {e}"
            ))
        })?;

        Ok(block_info)
    }

    /// Get the last confirmed block height and header hash.
    ///
    /// Maps to: `blockchain.last_confirmed_block() -> [height, hash_string]`
    pub async fn get_last_confirmed_block(&self) -> Result<(u32, String)> {
        debug!(target: "lightwalletd::rpc_client", "Fetching last confirmed block");

        let params = JsonValue::Array(vec![]);
        let response = self
            .request("blockchain.last_confirmed_block", params)
            .await?;

        let arr = response.get::<Vec<JsonValue>>().ok_or_else(|| {
            LightWalletError::RpcError(
                "Expected array response for last_confirmed_block".to_string(),
            )
        })?;

        if arr.len() != 2 {
            return Err(LightWalletError::RpcError(format!(
                "Expected 2-element array, got {}",
                arr.len()
            )));
        }

        let height = *arr[0]
            .get::<f64>()
            .ok_or_else(|| LightWalletError::RpcError("Expected number for height".to_string()))?
            as u32;

        let hash = arr[1]
            .get::<String>()
            .ok_or_else(|| LightWalletError::RpcError("Expected string for hash".to_string()))?
            .clone();

        Ok((height, hash))
    }

    /// Get the current block target time in seconds.
    ///
    /// Maps to: `blockchain.block_target() -> seconds`
    pub async fn get_block_target(&self) -> Result<u32> {
        debug!(target: "lightwalletd::rpc_client", "Fetching block target");

        let params = JsonValue::Array(vec![]);
        let response = self.request("blockchain.block_target", params).await?;

        let target = *response.get::<f64>().ok_or_else(|| {
            LightWalletError::RpcError("Expected number for block_target".to_string())
        })? as u32;

        Ok(target)
    }

    /// Get the current network difficulty.
    ///
    /// Maps to: `blockchain.get_difficulty() -> difficulty_string_or_number`
    pub async fn get_difficulty(&self) -> Result<String> {
        debug!(target: "lightwalletd::rpc_client", "Fetching difficulty");

        let params = JsonValue::Array(vec![]);
        let response = self.request("blockchain.get_difficulty", params).await?;

        match response {
            JsonValue::String(s) => Ok(s),
            JsonValue::Number(n) => Ok(n.to_string()),
            _ => Err(LightWalletError::RpcError(
                "Expected string or number for difficulty".to_string(),
            )),
        }
    }

    /// Submit a signed transaction to the network.
    ///
    /// Maps to: `tx.broadcast(base64_tx) -> tx_hash`
    pub async fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<String> {
        info!(target: "lightwalletd::rpc_client", "Broadcasting transaction");

        let tx_b64 = base64::encode(tx_bytes);
        let params = JsonValue::Array(vec![JsonValue::String(tx_b64.to_string())]);
        let response = self.request("tx.broadcast", params).await?;

        let tx_hash = response
            .get::<String>()
            .ok_or_else(|| {
                LightWalletError::RpcError("Expected string response for tx.broadcast".to_string())
            })?
            .clone();

        Ok(tx_hash)
    }

    /// Fetch a transaction by its hash.
    ///
    /// Maps to: `blockchain.get_tx(hash_hex) -> base64(Transaction)`
    pub async fn get_tx(&self, tx_hash: &str) -> Result<Vec<u8>> {
        debug!(target: "lightwalletd::rpc_client", "Fetching transaction {tx_hash}");

        let params = JsonValue::Array(vec![JsonValue::String(tx_hash.to_string())]);
        let response = self.request("blockchain.get_tx", params).await?;

        let tx_b64 = response.get::<String>().ok_or_else(|| {
            LightWalletError::RpcError(format!("Expected string response for get_tx({tx_hash})"))
        })?;

        let tx_bytes = base64::decode(tx_b64).ok_or_else(|| {
            LightWalletError::SerializationError(format!(
                "Failed to decode base64 for tx {tx_hash}"
            ))
        })?;

        Ok(tx_bytes)
    }

    /// Lookup zkas bincodes for a given contract ID.
    ///
    /// Maps to: `blockchain.lookup_zkas(contract_id) -> [[ns, bincode], ...]`
    pub async fn lookup_zkas(&self, contract_id: &str) -> Result<Vec<(String, Vec<u8>)>> {
        debug!(target: "lightwalletd::rpc_client", "Looking up zkas for contract {contract_id}");

        let params = JsonValue::Array(vec![JsonValue::String(contract_id.to_string())]);
        let response = self.request("blockchain.lookup_zkas", params).await?;

        let arr = response.get::<Vec<JsonValue>>().ok_or_else(|| {
            LightWalletError::RpcError("Expected array response for lookup_zkas".to_string())
        })?;

        let mut result = Vec::new();
        for item in arr {
            let pair = item.get::<Vec<JsonValue>>().ok_or_else(|| {
                LightWalletError::RpcError("Expected [ns, bincode] pair".to_string())
            })?;

            if pair.len() != 2 {
                continue;
            }

            let ns = pair[0]
                .get::<String>()
                .ok_or_else(|| LightWalletError::RpcError("Expected string namespace".to_string()))?
                .clone();

            let bincode_b64 = pair[1]
                .get::<String>()
                .ok_or_else(|| LightWalletError::RpcError("Expected string bincode".to_string()))?;

            let bincode = base64::decode(bincode_b64).ok_or_else(|| {
                LightWalletError::SerializationError("Failed to decode zkas bincode".to_string())
            })?;

            result.push((ns, bincode));
        }

        Ok(result)
    }

    /// Send a JSON-RPC request to darkfid and return the result value.
    async fn request(&self, method: &str, params: JsonValue) -> Result<JsonValue> {
        use darkfi::rpc::jsonrpc::JsonRequest;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let host = self.endpoint.host_str().unwrap_or("127.0.0.1");
        let port = self.endpoint.port().unwrap_or(18345);

        let mut stream = TcpStream::connect((host, port)).await.map_err(|e| {
            LightWalletError::ConnectionError(format!(
                "Failed to connect to {}: {}",
                self.endpoint, e
            ))
        })?;

        let req = JsonRequest::new(method, params);

        let req_str = req.stringify().map_err(|e| {
            LightWalletError::SerializationError(format!("Failed to stringify request: {}", e))
        })?;

        stream.write_all(req_str.as_bytes()).await.map_err(|e| {
            LightWalletError::ConnectionError(format!("Failed to write request: {}", e))
        })?;
        stream.write_all(b"\n").await.map_err(|e| {
            LightWalletError::ConnectionError(format!("Failed to write newline: {}", e))
        })?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(|e| {
            LightWalletError::ConnectionError(format!("Failed to read response: {}", e))
        })?;

        if line.is_empty() {
            return Err(LightWalletError::ConnectionError(
                "Empty response from server".to_string(),
            ));
        }

        let parsed: JsonValue = line.parse().map_err(|e| {
            LightWalletError::SerializationError(format!("Failed to parse response JSON: {}", e))
        })?;

        let result = parsed
            .get::<std::collections::HashMap<String, JsonValue>>()
            .ok_or_else(|| {
                LightWalletError::SerializationError(
                    "Response is not a valid JSON object".to_string(),
                )
            })?;
        if let Some(error) = result.get("error") {
            return Err(LightWalletError::RpcError(format!(
                "RPC error: {:?}",
                error
            )));
        }

        let res = result
            .get("result")
            .ok_or_else(|| LightWalletError::RpcError("No result field in response".to_string()))?;

        Ok(res.clone())
    }
}
