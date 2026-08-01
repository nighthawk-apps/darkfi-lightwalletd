# DarkFi Testnet & Localnet — Quick Reference

> Reference guide for running darkfid + lightwalletd + mining for development and E2E testing.
> See upstream docs: `doc/src/testnet/node.md`

## Architecture

```
xmrig (PoW miner)
  │  Stratum RPC (tcp://127.0.0.1:48347)
  ▼
darkfid (full node, localnet, pow_fixed_difficulty=1)
  │  JSON-RPC (tcp://127.0.0.1:48345)
  │  Management RPC (tcp://127.0.0.1:48346)
  ▼
darkfi-lightwalletd (compact block server)
  │  gRPC (127.0.0.1:9067)
  ▼
Wallet Clients (moonshine, Android, iOS)
```

## Quick Start — Localnet with Mining

### 1. Build all binaries

```bash
cd ~/GitHub/darkfi
cargo build --release -p darkfid -p drk -p darkfi-lightwalletd
```

### 2. Initialize wallet (one time)

```bash
cd contrib/localnet/darkfid-single-node
../../drk -c drk.toml wallet initialize
../../drk -c drk.toml wallet keygen
../../drk -c drk.toml wallet default-address 1
WALLET_ADDR=$(../../../drk -c drk.toml wallet address)
echo "Wallet address: $WALLET_ADDR"
```

### 3. Start darkfid

```bash
cd ~/GitHub/darkfi/contrib/localnet/darkfid-single-node
LOG_TARGETS='!net,!runtime,!sled' ../../../target/release/darkfid -c darkfid.toml
```

Wait for "Darkfi daemon started successfully!"

### 4. Start xmrig (separate terminal)

```bash
# Get your wallet address first
WALLET_ADDR=$(cd ~/GitHub/darkfi/contrib/localnet/darkfid-single-node && ../../../target/release/drk -c drk.toml wallet address)

# Start mining with 2 threads on localnet stratum port
xmrig -r 1000 -R 20 -o 127.0.0.1:48347 -t 2 -u "$WALLET_ADDR"
```

You should see in darkfid logs:
```
[INFO] [RPC-STRATUM] Got login from {WALLET_ADDR}
[INFO] Created new block template for wallet: address=...
[INFO] Appended proposal ...
[INFO] Proposing new block to network
```

### 5. Start lightwalletd (separate terminal)

```bash
cat > /tmp/lwd_localnet.toml <<'EOF'
darkfid_endpoint = "tcp://127.0.0.1:48345"
grpc_listen = "127.0.0.1:9067"
cache_path = "/tmp/lwd_localnet_cache"
poll_interval = 5
chain_name = "darkfi-localnet"
network = "testnet"
EOF

RUST_LOG=info ~/GitHub/darkfi/target/release/darkfi-lightwalletd --config /tmp/lwd_localnet.toml
```

### 6. Connect moonshine

```bash
# Create a wallet
~/GitHub/moonshine/target/release/moonshine wallet create mytest

# Check status
~/GitHub/moonshine/target/release/moonshine status

# Sync blocks
~/GitHub/moonshine/target/release/moonshine sync

# Check balance
~/GitHub/moonshine/target/release/moonshine balance
```

## Port Reference

| Service | Port | Protocol | Config Key |
|---------|------|----------|------------|
| darkfid JSON-RPC | 48345 (localnet) / 18345 (testnet) | TCP | `rpc_listen` |
| darkfid Management RPC | 48346 (localnet) / 18346 (testnet) | TCP | `management_rpc.rpc_listen` |
| darkfid Stratum RPC | 48347 (localnet) / 18347 (testnet) | TCP | `stratum_rpc.rpc_listen` |
| darkfid P2P | 48340 (localnet) / 18340 (testnet) | TCP+TLS | `net.inbound` |
| lightwalletd gRPC | 9067 | HTTP/2 | `grpc_listen` |

## DRK RPC Methods Used by lightwalletd

| Method | Purpose |
|--------|---------|
| `blockchain.last_confirmed_block` | Get current tip height + hash |
| `blockchain.get_block` | Fetch block by height |
| `blockchain.block_target` | Get PoW target for block |
| `blockchain.get_tx` | Fetch transaction by hash |
| `blockchain.lookup_zkas` | Look up ZK circuit |
| `tx.broadcast` | Submit signed transaction |

## Wallet Sync with `drk`

```bash
# In the localnet folder:
cd contrib/localnet/darkfid-single-node
DRK="../../../target/release/drk -c drk.toml"

# Interactive mode (subscribes to blocks)
$DRK interactive

# In the drk> prompt:
drk> subscribe
drk> wallet balance
```

## Mining Rewards

- Each mined block produces a coinbase transaction
- Reward is sent to the xmrig user address
- Blocks need to be confirmed (threshold=1 in localnet)
- Use `drk wallet balance` or `moonshine balance` to see received coins

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No blocks cached yet" | lightwalletd hasn't synced — wait for chain poller to fetch from darkfid |
| "Connection refused" on 48345 | darkfid not running or wrong port |
| No blocks being mined | xmrig not connected or not running |
| lightwalletd ignores config | Use `--config /path/to/config.toml` flag |
| "method not found" on RPC | Wrong port (use 48345 for JSON-RPC, 48347 for Stratum) |

## Testnet (Live Network)

### Quick Start — Live Testnet

```bash
# 1. Generate default configs
darkfid   # Creates ~/.config/darkfi/darkfid_config.toml
drk       # Creates ~/.config/darkfi/drk_config.toml

# 2. Enable stratum mining in darkfid config
# Uncomment [network_config."testnet".stratum_rpc] section:
#   rpc_listen = "tcp://127.0.0.1:18347"

# 3. Change wallet password in drk config
# Edit ~/.config/darkfi/drk_config.toml:
#   wallet_pass = "your_secure_password"

# 4. Start darkfid (will sync with testnet peers)
LOG_TARGETS='!net,!runtime,!sled' darkfid &
# Wait for "Blockchain synced!" message

# 5. Initialize wallet
drk wallet initialize
drk wallet keygen
drk wallet default-address 1
WALLET_ADDR=$(drk wallet address)
echo "Wallet: $WALLET_ADDR"

# 6. Start mining
xmrig -r 1000 -R 20 -o 127.0.0.1:18347 -t 2 -u "$WALLET_ADDR"

# 7. Scan for rewards and check balance
drk scan
drk wallet balance
```

### Testnet Configuration Details

| Setting | Value |
|---------|-------|
| Network | `testnet` |
| JSON-RPC | `tcp://127.0.0.1:18345` |
| Management RPC | `tcp://127.0.0.1:18346` |
| Stratum RPC | `tcp://127.0.0.1:18347` |
| PoW Target | 120 seconds |
| Confirmation Threshold | 6 blocks |
| P2P Port | 18340 (tcp+tls) |

### Seed Nodes (Tor)

```
tor://wgxxaifz5gv4iggcflyl67lgmsihffs6bbwobqah4np52t3y3olrnpid.onion:18341
tor://eu7b6sqsxvyfgmufquwr622fbbaqut7qwvpedzlste3b66bv7jvxlpyd.onion:18341
```

### Seed Nodes (tcp+tls, via Tor)

```
tor+tls://lilith0.dark.fi:18340
tor+tls://lilith1.dark.fi:18340
```

### Connecting lightwalletd to Live Testnet

```toml
# /tmp/lwd_testnet.toml
darkfid_endpoint = "tcp://127.0.0.1:18345"
grpc_listen = "127.0.0.1:9067"
cache_path = "/tmp/lwd_testnet_cache"
poll_interval = 10
chain_name = "darkfi-testnet-v0.3"
network = "testnet"
```

```bash
darkfi-lightwalletd --config /tmp/lwd_testnet.toml
```

### Notes

- Testnet uses RandomX PoW (same as Monero), designed for CPU mining
- Block confirmation requires 6 sequential blocks (vs 1 for localnet)
- Mining rewards appear after scanning with `drk scan`
- The testnet may be reset periodically — check dark.fi for announcements
- Without Tor, use `tcp+tls` active profile and the lilith seed nodes
