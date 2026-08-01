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

//! Configuration for darkfi-lightwalletd.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Configuration file structure, loaded from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// darkfid JSON-RPC endpoint URL
    #[serde(default = "default_darkfid_endpoint")]
    pub darkfid_endpoint: String,

    /// gRPC listen address for wallet clients
    #[serde(default = "default_grpc_listen")]
    pub grpc_listen: String,

    /// Path to the sled cache database (supports `~` expansion)
    #[serde(default = "default_cache_path")]
    pub cache_path: String,

    /// Poll interval in seconds for checking new blocks from darkfid
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,

    /// Chain name identifier returned in `GetLightInfo`
    #[serde(default = "default_chain_name")]
    pub chain_name: String,

    /// Network mode: `"mainnet"` or `"testnet"`.
    /// Controls UnifOMR detection-key network-byte validation and default
    /// compact-block cache subdirectory.
    #[serde(default = "default_network")]
    pub network: String,

    /// Max GetUnifOmrDigest / FetchPirBatch requests per peer IP per minute (S6).
    /// Set to 0 to disable rate limiting (not recommended for public listen).
    #[serde(default = "default_omr_rate_limit_per_min")]
    pub omr_rate_limit_per_min: u32,

    /// Optional path to PEM TLS certificate for gRPC (S6).
    /// When set together with `tls_key_path`, the server serves HTTPS.
    #[serde(default)]
    pub tls_cert_path: Option<String>,

    /// Optional path to PEM TLS private key for gRPC (S6).
    #[serde(default)]
    pub tls_key_path: Option<String>,
}

fn default_darkfid_endpoint() -> String {
    "tcp://127.0.0.1:18345".to_string()
}

fn default_grpc_listen() -> String {
    // SECURITY: Default to localhost. Operators MUST explicitly set 0.0.0.0
    // to expose the gRPC server to the network — and MUST also set TLS
    // (tls_cert_path + tls_key_path). Cleartext off-loopback is refused at startup (S6).
    "127.0.0.1:9067".to_string()
}

/// True if the gRPC listen host is loopback-only (cleartext allowed).
pub fn is_loopback_listen(addr: &str) -> bool {
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or(addr);
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "0:0:0:0:0:0:0:1")
}

fn default_cache_path() -> String {
    "~/.local/share/darkfi/lightwalletd_cache".to_string()
}

fn default_poll_interval() -> u64 {
    10
}

fn default_chain_name() -> String {
    "darkfi-testnet".to_string()
}

fn default_network() -> String {
    "testnet".to_string()
}

fn default_omr_rate_limit_per_min() -> u32 {
    30
}

/// Expand a leading `~/` to the user home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// UnifOMR / OMR wire network byte: mainnet `0x00`, testnet `0x01`.
pub fn network_byte(network: &str) -> Result<u8, String> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" => Ok(0x00),
        "testnet" | "localnet" => Ok(0x01),
        other => Err(format!(
            "invalid network `{other}` (expected mainnet or testnet)"
        )),
    }
}

fn expected_chain_name(network: &str) -> &'static str {
    match network {
        "mainnet" => "darkfi-mainnet",
        _ => "darkfi-testnet",
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            darkfid_endpoint: default_darkfid_endpoint(),
            grpc_listen: default_grpc_listen(),
            cache_path: default_cache_path(),
            poll_interval: default_poll_interval(),
            chain_name: default_chain_name(),
            network: default_network(),
            omr_rate_limit_per_min: default_omr_rate_limit_per_min(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl Config {
    /// Load config from a TOML file. Fails hard on missing file or parse errors.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&content)
            .map_err(|e| format!("failed to parse config {}: {e}", path.display()))?;
        cfg.finalize()
    }

    /// Normalize network/chain_name, expand `~` paths, scope default cache by network.
    pub fn finalize(mut self) -> Result<Self, String> {
        let net = self.network.trim().to_ascii_lowercase();
        match net.as_str() {
            "mainnet" | "testnet" => self.network = net,
            "localnet" => {
                // Treat localnet like testnet for OMR wire bytes / cache scoping.
                self.network = "testnet".to_string();
            }
            other => {
                return Err(format!(
                    "network must be \"mainnet\" or \"testnet\", got `{other}`"
                ));
            }
        }
        let _ = network_byte(&self.network)?;

        let chain = self.chain_name.trim().to_ascii_lowercase();
        let expected = expected_chain_name(&self.network);
        if chain.is_empty() || chain == default_chain_name() {
            // Auto-align default chain_name when operator only set `network`.
            self.chain_name = expected.to_string();
        } else {
            self.chain_name = self.chain_name.trim().to_string();
            let lower = self.chain_name.to_ascii_lowercase();
            let ok = match self.network.as_str() {
                "mainnet" => {
                    lower.contains("mainnet")
                        && !lower.contains("testnet")
                        && !lower.contains("localnet")
                }
                "testnet" => {
                    (lower.contains("testnet") || lower.contains("localnet"))
                        && !lower.contains("mainnet")
                }
                _ => false,
            };
            if !ok {
                return Err(format!(
                    "chain_name `{}` is inconsistent with network `{}` \
                     (expected something like `{expected}`)",
                    self.chain_name, self.network
                ));
            }
        }

        if self.poll_interval == 0 {
            return Err("poll_interval must be >= 1".into());
        }
        if self.darkfid_endpoint.trim().is_empty() {
            return Err("darkfid_endpoint must not be empty".into());
        }
        if self.grpc_listen.trim().is_empty() {
            return Err("grpc_listen must not be empty".into());
        }

        // Expand ~ in cache + TLS paths.
        let raw_cache = self.cache_path.clone();
        let mut cache = expand_tilde(&raw_cache);

        // Scope the *default* cache root by network so testnet/mainnet never share sled DBs.
        let is_default_cache = raw_cache.trim() == default_cache_path()
            || cache.file_name().and_then(|s| s.to_str()) == Some("lightwalletd_cache");
        if is_default_cache {
            cache = cache.join(&self.network);
        }
        self.cache_path = cache.to_string_lossy().into_owned();

        if let Some(p) = self.tls_cert_path.take() {
            self.tls_cert_path = Some(expand_tilde(&p).to_string_lossy().into_owned());
        }
        if let Some(p) = self.tls_key_path.take() {
            self.tls_key_path = Some(expand_tilde(&p).to_string_lossy().into_owned());
        }

        Ok(self)
    }

    /// Wire network byte for UnifOMR detection keys.
    pub fn omr_network_byte(&self) -> u8 {
        network_byte(&self.network).expect("network validated in finalize()")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detect() {
        assert!(is_loopback_listen("127.0.0.1:9067"));
        assert!(is_loopback_listen("localhost:9067"));
        assert!(!is_loopback_listen("0.0.0.0:9067"));
        assert!(!is_loopback_listen("192.168.1.1:9067"));
    }

    #[test]
    fn expand_tilde_home() {
        std::env::set_var("HOME", "/tmp/lwd-home-test");
        let p = expand_tilde("~/cache/db");
        assert_eq!(p, PathBuf::from("/tmp/lwd-home-test/cache/db"));
    }

    #[test]
    fn finalize_testnet_scopes_cache() {
        std::env::set_var("HOME", "/tmp/lwd-home-test");
        let cfg = Config {
            network: "testnet".into(),
            chain_name: "darkfi-testnet".into(),
            cache_path: "~/.local/share/darkfi/lightwalletd_cache".into(),
            ..Config::default()
        }
        .finalize()
        .unwrap();
        assert!(cfg.cache_path.ends_with("lightwalletd_cache/testnet"));
        assert_eq!(cfg.omr_network_byte(), 0x01);
    }

    #[test]
    fn finalize_mainnet_auto_chain_name() {
        std::env::set_var("HOME", "/tmp/lwd-home-test");
        let cfg = Config {
            network: "mainnet".into(),
            chain_name: "darkfi-testnet".into(), // default → rewritten
            cache_path: "~/.local/share/darkfi/lightwalletd_cache".into(),
            ..Config::default()
        }
        .finalize()
        .unwrap();
        assert_eq!(cfg.chain_name, "darkfi-mainnet");
        assert!(cfg.cache_path.ends_with("lightwalletd_cache/mainnet"));
        assert_eq!(cfg.omr_network_byte(), 0x00);
    }

    #[test]
    fn finalize_rejects_mismatched_chain() {
        let err = Config {
            network: "mainnet".into(),
            chain_name: "darkfi-testnet-custom".into(),
            ..Config::default()
        }
        .finalize()
        .unwrap_err();
        assert!(err.contains("inconsistent"));
    }

    #[test]
    fn finalize_rejects_bad_network() {
        let err = Config {
            network: "devnet".into(),
            ..Config::default()
        }
        .finalize()
        .unwrap_err();
        assert!(err.contains("mainnet") || err.contains("testnet"));
    }

    #[test]
    fn explicit_cache_path_not_auto_scoped_unless_basename() {
        std::env::set_var("HOME", "/tmp/lwd-home-test");
        let cfg = Config {
            network: "testnet".into(),
            chain_name: "darkfi-testnet".into(),
            cache_path: "/var/lib/lwd-testnet".into(),
            ..Config::default()
        }
        .finalize()
        .unwrap();
        assert_eq!(cfg.cache_path, "/var/lib/lwd-testnet");
    }
}
