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

use std::net::SocketAddr;
use std::time::Duration;

use darkfi::{blockchain::block_store::BlockInfo, util::encoding::base64};
use darkfi_serial::deserialize_async;
use tinyjson::JsonValue;
use tracing::{debug, info, warn};
use url::Url;

use crate::error::{LightWalletError, Result};

/// Client for communicating with a darkfid full node via JSON-RPC.
pub struct DarkfidRpcClient {
    /// The URL of the darkfid JSON-RPC endpoint
    endpoint: Url,
    /// Resolved host:port (DNS pinned at construction when enabled).
    connect_addr: String,
    /// Connect + read timeout.
    timeout: Duration,
}

impl DarkfidRpcClient {
    /// Create a new RPC client. Optionally pin DNS at construction.
    pub async fn new(
        endpoint: Url,
        timeout: Duration,
        pin_dns: bool,
    ) -> Result<Self> {
        let host = endpoint.host_str().unwrap_or("127.0.0.1").to_string();
        let port = endpoint.port().unwrap_or(18345);
        let connect_addr = if pin_dns {
            match tokio::net::lookup_host((host.as_str(), port)).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        let pinned = addr.to_string();
                        info!(
                            target: "lightwalletd::rpc_client",
                            "darkfid DNS pinned: {host}:{port} → {pinned}"
                        );
                        pinned
                    } else {
                        warn!(
                            target: "lightwalletd::rpc_client",
                            "DNS pin: no addresses for {host}; falling back to hostname"
                        );
                        format!("{host}:{port}")
                    }
                }
                Err(e) => {
                    warn!(
                        target: "lightwalletd::rpc_client",
                        "DNS pin failed for {host}: {e}; falling back to hostname"
                    );
                    format!("{host}:{port}")
                }
            }
        } else {
            format!("{host}:{port}")
        };
        Ok(Self {
            endpoint,
            connect_addr,
            timeout,
        })
    }

    /// Convenience for tests (loopback, 15s timeout, no pin).
    pub fn new_simple(endpoint: Url) -> Self {
        let host = endpoint.host_str().unwrap_or("127.0.0.1");
        let port = endpoint.port().unwrap_or(18345);
        Self {
            connect_addr: format!("{host}:{port}"),
            endpoint,
            timeout: Duration::from_secs(15),
        }
    }

    /// Fetch a block at the given height from darkfid.
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

        let connect_fut = TcpStream::connect(&self.connect_addr);
        let mut stream = tokio::time::timeout(self.timeout, connect_fut)
            .await
            .map_err(|_| {
                LightWalletError::ConnectionError(format!(
                    "Timeout connecting to darkfid at {}",
                    self.connect_addr
                ))
            })?
            .map_err(|e| {
                LightWalletError::ConnectionError(format!(
                    "Failed to connect to {} ({}): {}",
                    self.endpoint, self.connect_addr, e
                ))
            })?;

        // Prefer nodelay for request/response RPC.
        let _ = stream.set_nodelay(true);

        let req = JsonRequest::new(method, params);

        let req_str = req.stringify().map_err(|e| {
            LightWalletError::SerializationError(format!("Failed to stringify request: {}", e))
        })?;

        tokio::time::timeout(self.timeout, async {
            stream.write_all(req_str.as_bytes()).await?;
            stream.write_all(b"\n").await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| {
            LightWalletError::ConnectionError("Timeout writing darkfid RPC request".into())
        })?
        .map_err(|e| {
            LightWalletError::ConnectionError(format!("Failed to write request: {}", e))
        })?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        tokio::time::timeout(self.timeout, reader.read_line(&mut line))
            .await
            .map_err(|_| {
                LightWalletError::ConnectionError("Timeout reading darkfid RPC response".into())
            })?
            .map_err(|e| {
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
                    "Expected JSON object response".to_string(),
                )
            })?;

        if let Some(err) = result.get("error") {
            return Err(LightWalletError::RpcError(format!("{err:?}")));
        }

        result
            .get("result")
            .cloned()
            .ok_or_else(|| LightWalletError::RpcError("Missing result field".to_string()))
    }
}

#[allow(dead_code)]
fn _socket_addr_hint(addr: &str) -> Option<SocketAddr> {
    addr.parse().ok()
}
