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

//! darkfi-lightwalletd main entry point.
//!
//! Usage:
//!   darkfi-lightwalletd [--config <path>]
//!
//! The server:
//! 1. Loads configuration from TOML file
//! 2. Opens/creates the sled cache database
//! 3. Connects to darkfid via JSON-RPC
//! 4. Starts the chain poller (syncs blocks from darkfid ? cache)
//! 5. Starts the gRPC server (serves compact blocks to wallet clients)

use std::sync::Arc;

use tonic::transport::Server;
use tracing::{error, info, warn};
use url::Url;

use darkfi_lightwalletd::{
    cache::Cache,
    chain_poller::{ChainPoller, ChainPollerConfig},
    config::{self, Config},
    proto::dark_fi_light_wallet_server::DarkFiLightWalletServer,
    rpc_client::DarkfidRpcClient,
    server::LightWalletService,
};

/// Cyberpunk teal `#5CE1FF` and wallpaper pink `#C94BB8`.
const CYBER_TEAL: (u8, u8, u8) = (0x5C, 0xE1, 0xFF);
const CYBER_PINK: (u8, u8, u8) = (0xC9, 0x4B, 0xB8);

/// Three-line wordmark: nighthawk × darkfi / lightwalletd server.
const HEADER_ART: &str = r#"
┌─ nighthawk  ×  darkfi ─┐
│  lightwalletd server   │
└────────────────────────┘
"#;

fn nighthawk_header() -> String {
    paint_cyberpunk(HEADER_ART)
}

/// Sweep glyphs from teal to pink and back. Each row is phase-shifted so the
/// two cyberpunk colors change across the wordmark.
fn paint_cyberpunk(art: &str) -> String {
    let mut out = String::new();
    for (row, line) in art.trim_matches('\n').lines().enumerate() {
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                out.push(' ');
                continue;
            }
            let phase = (col as f64 + row as f64 * 7.0) * std::f64::consts::TAU / 28.0;
            let t = (phase.cos() + 1.0) * 0.5;
            let r = blend(CYBER_TEAL.0, CYBER_PINK.0, t);
            let g = blend(CYBER_TEAL.1, CYBER_PINK.1, t);
            let b = blend(CYBER_TEAL.2, CYBER_PINK.2, t);
            out.push_str(&format!("\x1b[38;2;{r};{g};{b}m{ch}"));
        }
        out.push_str("\x1b[0m\n");
    }
    out
}

fn blend(from: u8, to: u8, t: f64) -> u8 {
    (from as f64 + (to as f64 - from as f64) * t).round() as u8
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    print!("{}", nighthawk_header());

    info!(target: "lightwalletd", "darkfi-lightwalletd v{} ({})", env!("CARGO_PKG_VERSION"), option_env!("GIT_HASH").unwrap_or("unknown"));
    info!(target: "lightwalletd", "Anonymous. Uncensored. Sovereign.");

    // Load config from --config <path> CLI argument, or use defaults (then finalize).
    let config = {
        let args: Vec<String> = std::env::args().collect();
        let config_path = args
            .iter()
            .position(|a| a == "--config")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.to_string());

        let loaded = if let Some(path) = config_path {
            info!(target: "lightwalletd", "Loading config from: {}", path);
            Config::load_from_file(&path).unwrap_or_else(|e| {
                error!(target: "lightwalletd", "Config error: {e}");
                std::process::exit(1);
            })
        } else {
            info!(target: "lightwalletd", "No --config specified, using defaults.");
            Config::default().finalize().unwrap_or_else(|e| {
                error!(target: "lightwalletd", "Default config error: {e}");
                std::process::exit(1);
            })
        };
        loaded
    };

    info!(
        target: "lightwalletd",
        "darkfid endpoint: {}",
        config.darkfid_endpoint
    );
    info!(
        target: "lightwalletd",
        "gRPC listen: {}",
        config.grpc_listen
    );
    info!(
        target: "lightwalletd",
        "Cache path: {}",
        config.cache_path
    );
    info!(
        target: "lightwalletd",
        "Network: {} (omr byte {:#04x}, chain_name={})",
        config.network,
        config.omr_network_byte(),
        config.chain_name
    );

    // Open cache
    let cache = match Cache::new(&config.cache_path) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(target: "lightwalletd", "Failed to open cache: {e}");
            std::process::exit(1);
        }
    };

    // Report cache state
    match cache.get_tip() {
        Ok(Some((height, _))) => {
            info!(
                target: "lightwalletd",
                "Cache contains blocks up to height {height}"
            );
        }
        Ok(None) => {
            info!(target: "lightwalletd", "Cache is empty, will sync from genesis");
        }
        Err(e) => {
            error!(target: "lightwalletd", "Failed to read cache tip: {e}");
            std::process::exit(1);
        }
    }

    // Parse darkfid endpoint
    let endpoint = match Url::parse(&config.darkfid_endpoint) {
        Ok(u) => u,
        Err(e) => {
            error!(
                target: "lightwalletd",
                "Invalid darkfid endpoint URL: {e}"
            );
            std::process::exit(1);
        }
    };

    // Create RPC client (DNS pin + timeouts)
    let rpc_client = match DarkfidRpcClient::new(
        endpoint,
        std::time::Duration::from_secs(config.darkfid_rpc_timeout_s.max(1)),
        config.pin_darkfid_dns,
    )
    .await
    {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(target: "lightwalletd", "Failed to create darkfid RPC client: {e}");
            std::process::exit(1);
        }
    };

    match rpc_client.get_last_confirmed_block().await {
        Ok((height, _)) => {
            info!(
                target: "lightwalletd",
                "darkfid backend reachable (last_confirmed_block height {height})"
            );
            if let Err(e) = rpc_client.get_block(height).await {
                error!(
                    target: "lightwalletd",
                    "darkfid backend check failed (blockchain.get_block): {e}"
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!(
                target: "lightwalletd",
                "darkfid backend check failed (blockchain.last_confirmed_block): {e}"
            );
            std::process::exit(1);
        }
    }

    #[cfg(feature = "fhe-omr")]
    info!(
        target: "lightwalletd",
        "UnifOMR enabled (GetUnifOmrDigest + FetchPirBatch)"
    );
    #[cfg(not(feature = "fhe-omr"))]
    info!(
        target: "lightwalletd",
        "Trial decrypt is the default path (GetCompactOutputBodies, GetNullifiers, GetCompactDaoCalls). UnifOMR is not in this build."
    );

    // Shared tip watch: poller notifies, SubscribeBlocks wakes.
    let initial_tip = cache.get_tip().ok().flatten().map(|(h, _)| h).unwrap_or(0);
    let (tip_tx, tip_rx) = tokio::sync::watch::channel(initial_tip);

    // Create gRPC service with rate limits + tx size cap
    let mut service = LightWalletService::with_limits(
        Arc::clone(&cache),
        Arc::clone(&rpc_client),
        config.chain_name.clone(),
        config.omr_network_byte(),
        config.omr_rate_limit_per_min,
        config.rpc_rate_limit_per_min,
        config.max_tx_bytes,
        tip_rx,
        config.trusted_proxies.clone(),
    );
    service.apply_resource_caps(
        config.max_detection_key_bytes,
        config.max_send_peer_entries,
        config.rate_limit_gc_threshold,
        config.upload_budget_mib,
        config.max_uploads_per_ip,
    );

    // Start chain poller in background
    let poller = ChainPoller::new(
        Arc::clone(&rpc_client),
        Arc::clone(&cache),
        ChainPollerConfig {
            poll_interval_secs: config.poll_interval,
            ..Default::default()
        },
        tip_tx,
    );

    let poller_handle = tokio::spawn(async move {
        info!(target: "lightwalletd", "Chain poller started");
        poller.run().await;
    });

    // Parse gRPC listen address
    let grpc_addr = config.grpc_listen.parse().unwrap_or_else(|e| {
        error!(target: "lightwalletd", "Invalid gRPC listen address: {e}");
        std::process::exit(1);
    });

    info!(
        target: "lightwalletd",
        "Starting gRPC server on {grpc_addr} (omr_rate={}/min rpc_rate={}/min max_conn={} max_tx={})",
        config.omr_rate_limit_per_min,
        config.rpc_rate_limit_per_min,
        config.max_connections,
        config.max_tx_bytes
    );

    let max_connections = config.max_connections as usize;
    let max_streams = config.max_streams_per_conn as usize;
    let request_timeout_s = config.request_timeout_s;

    // TLS (S6): required for any non-loopback bind. Cleartext only on 127.0.0.1 / ::1.
    let tls_identity = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert = std::fs::read(cert_path).unwrap_or_else(|e| {
                error!(target: "lightwalletd", "Failed to read TLS cert {cert_path}: {e}");
                std::process::exit(1);
            });
            let key = std::fs::read(key_path).unwrap_or_else(|e| {
                error!(target: "lightwalletd", "Failed to read TLS key {key_path}: {e}");
                std::process::exit(1);
            });
            info!(target: "lightwalletd", "TLS enabled for gRPC");
            Some(tonic::transport::Identity::from_pem(cert, key))
        }
        (None, None) => {
            if !config::is_loopback_listen(&config.grpc_listen) {
                error!(
                    target: "lightwalletd",
                    "Refusing cleartext gRPC on non-loopback listen `{}`. \
                     Set tls_cert_path + tls_key_path, or bind 127.0.0.1 / ::1 only (S6).",
                    config.grpc_listen
                );
                std::process::exit(1);
            }
            warn!(
                target: "lightwalletd",
                "gRPC cleartext on loopback only ({})",
                config.grpc_listen
            );
            None
        }
        _ => {
            error!(
                target: "lightwalletd",
                "Both tls_cert_path and tls_key_path must be set together"
            );
            std::process::exit(1);
        }
    };

    // Start gRPC server with graceful shutdown + connection/stream limits
    let server_handle = tokio::spawn(async move {
        let mut builder = Server::builder();
        if let Some(identity) = tls_identity {
            let tls = tonic::transport::ServerTlsConfig::new().identity(identity);
            builder = match builder.tls_config(tls) {
                Ok(b) => b,
                Err(e) => {
                    error!(target: "lightwalletd", "Invalid TLS config: {e}");
                    return;
                }
            };
        }
        builder = builder.concurrency_limit_per_connection(max_streams.max(1));
        builder = builder
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
            .tcp_keepalive(Some(std::time::Duration::from_secs(60)));
        if request_timeout_s > 0 {
            builder = builder.timeout(std::time::Duration::from_secs(request_timeout_s));
        }

        let svc = DarkFiLightWalletServer::new(service)
            // Param2 UnifOMR detection keys are ~120 MiB; keep headroom for digests.
            .max_decoding_message_size(160 * 1024 * 1024)
            .max_encoding_message_size(160 * 1024 * 1024);

        let shutdown = async {
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("Failed to install SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to install CTRL+C handler");
            }
            info!(target: "lightwalletd", "Received shutdown signal");
        };

        let serve_result = if max_connections > 0 {
            match tokio::net::TcpListener::bind(grpc_addr).await {
                Ok(listener) => {
                    info!(target: "lightwalletd", "gRPC listening on {grpc_addr}");
                    let incoming = darkfi_lightwalletd::limited_incoming::LimitedTcpIncoming::new(
                        listener,
                        max_connections,
                    );
                    builder
                        .add_service(svc)
                        .serve_with_incoming_shutdown(incoming, shutdown)
                        .await
                }
                Err(e) => {
                    error!(target: "lightwalletd", "Failed to bind {grpc_addr}: {e}");
                    return;
                }
            }
        } else {
            info!(target: "lightwalletd", "gRPC listening on {grpc_addr}");
            builder
                .add_service(svc)
                .serve_with_shutdown(grpc_addr, shutdown)
                .await
        };

        if let Err(e) = serve_result {
            error!(target: "lightwalletd", "gRPC server error: {e}");
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = poller_handle => {
            error!(target: "lightwalletd", "Chain poller exited unexpectedly");
        }
        _ = server_handle => {
            info!(target: "lightwalletd", "gRPC server stopped");
        }
    }

    // Flush cache on shutdown
    info!(target: "lightwalletd", "Flushing cache...");
    if let Err(e) = cache.flush() {
        error!(target: "lightwalletd", "Failed to flush cache: {e}");
    }

    info!(target: "lightwalletd", "Shutdown complete");
    Ok(())
}

#[cfg(test)]
mod header_tests {
    use super::paint_cyberpunk;

    #[test]
    fn header_shifts_between_cyberpunk_teal_and_pink() {
        let painted = paint_cyberpunk(&"#".repeat(48));
        let mut saw_teal = false;
        let mut saw_pink = false;
        for code in painted.split("\u{1b}[38;2;").skip(1) {
            let rgb = code.split('m').next().unwrap();
            let mut parts = rgb.split(';');
            let r: u8 = parts.next().unwrap().parse().unwrap();
            let g: u8 = parts.next().unwrap().parse().unwrap();
            let b: u8 = parts.next().unwrap().parse().unwrap();
            if r < 120 && g > 180 && b > 220 {
                saw_teal = true;
            }
            if r > 170 && g < 120 && (150..220).contains(&b) {
                saw_pink = true;
            }
        }
        assert!(saw_teal, "expected cyberpunk teal #5CE1FF");
        assert!(saw_pink, "expected cyberpunk pink #C94BB8");

        let header = super::nighthawk_header();
        let plain = strip_ansi(&header);
        assert_eq!(plain.trim_matches('\n').lines().count(), 3);
        assert!(plain.contains("nighthawk"));
        assert!(plain.contains("darkfi"));
        assert!(plain.contains("lightwalletd server"));
        assert!(header.contains("\u{1b}[38;2;"));
        assert!(!header.contains("\u{1b}[33m"));
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(ch) = chars.next() {
            if ch == '\u{1b}' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }
}
