# darkfi-lightwalletd Operations Runbook

Operational guide for running and maintaining the Nighthawk DarkFi testnet lightwallet infrastructure (Mac Studio `launchd` stack behind `ngrok`).

---

## 1. Mac Studio `launchd` Service Stack

All four services run as user LaunchAgents under `~/Library/LaunchAgents/` (user `hawk`, repos in `~/GitHub/`):

| LaunchAgent Label | Purpose | Endpoint / Binding | Logs |
|---|---|---|---|
| `org.darkfi.darkfid` | DarkFi testnet full node (Tor P2P, RandomX validation, JSON-RPC, Stratum) | JSON-RPC `127.0.0.1:18345`<br>Stratum `127.0.0.1:18347` | `~/Library/Logs/darkfi/darkfid.*` |
| `org.darkfi.lightwalletd` | Compact-block & OMR gRPC server (`~/bin/darkfi-lightwalletd`) | gRPC `127.0.0.1:9067` (cleartext loopback behind ngrok) | `~/Library/Logs/darkfi/lightwalletd.out.log`<br>`~/Library/Logs/darkfi/lightwalletd.err.log` |
| `com.ngrok.lightwalletd` | Public HTTPS / HTTP/2 reverse tunnel to loopback gRPC | `https://epidermis-sandbox-marshland.ngrok-free.dev:443` → `127.0.0.1:9067` | `~/Library/Logs/darkfi/ngrok.*` |
| `org.darkfi.xmrig` | Testnet CPU miner connected to local Stratum | `127.0.0.1:18347` | `~/Library/Logs/darkfi/xmrig.*` |

### Service Supervision Commands

Always manage `darkfid` and `lightwalletd` exclusively via `launchctl` — **never** run a second manual `darkfid` process alongside `org.darkfi.darkfid` (doing so causes `FjallError: Locked` restart loops).

```bash
# Check status and PIDs of all DarkFi / ngrok agents
launchctl list | grep -E 'darkfi|ngrok'

# Restart lightwalletd cleanly after a binary or config update
launchctl kickstart -k "gui/$(id -u)/org.darkfi.lightwalletd"

# Restart darkfid (graceful stop + launchd restart)
launchctl kickstart -k "gui/$(id -u)/org.darkfi.darkfid"

# Temporarily stop / reload a LaunchAgent
launchctl bootout "gui/$(id -u)/org.darkfi.lightwalletd"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/org.darkfi.lightwalletd.plist"
```

### Build & Deploy `darkfi-lightwalletd` on Mac Studio

Use the **stable** Rust toolchain on macOS (nightly breaks `branches 0.4.6`):

```bash
cd ~/GitHub/darkfi-lightwalletd
RUSTUP_TOOLCHAIN=stable cargo build --release
./scripts/deploy-studio-lwd.sh
~/bin/darkfi-lightwalletd --version
```

> **CPU headroom note (`org.darkfi.xmrig`):** Keep `xmrig` thread count conservative (e.g. `-t 4` to `-t 6`, rather than saturating all cores) so `darkfid`, `darkfi-lightwalletd`, and Xcode test runs retain headroom during multi-tester bursts.

---

## 2. `trusted_proxies` & Rate Limits Behind `ngrok`

Because `ngrok` terminates TLS/HTTP2 and forwards gRPC connections over loopback (`127.0.0.1` / `::1`), `~/.config/darkfi/lightwalletd.toml` **must** list loopback in `trusted_proxies`:

```toml
grpc_listen = "127.0.0.1:9067"
trusted_proxies = ["127.0.0.1", "::1"]

# Multi-tester public testnet budgets (per client IP per minute)
rpc_rate_limit_per_min = 600
omr_rate_limit_per_min = 30
max_connections = 512
max_streams_per_conn = 256
```

### How Peer Accounting Works
- When the TCP source IP matches `trusted_proxies` (including IPv4-mapped IPv6 `::ffff:127.0.0.1`), `darkfi-lightwalletd` walks **all** `x-forwarded-for` HTTP/2 metadata headers and comma-separated hops **right-to-left**, skipping trusted proxy entries and selecting the **rightmost untrusted IP**.
- Client-spoofed leftmost hops or prepended HTTP/2 `x-forwarded-for` headers are ignored, preventing attackers from bypassing per-IP rate limits behind `ngrok`.
- Direct connections from untrusted peers ignore `x-forwarded-for` completely and use the TCP peer address.
- Without `trusted_proxies = ["127.0.0.1", "::1"]`, every external tester behind `ngrok` would share one `127.0.0.1` bucket and lock each other out during initial sync.

### Observability (`lightwalletd::metrics`)
Every 60 seconds, `darkfi-lightwalletd` emits a lock-free `INFO` summary line:

```text
INFO lightwalletd::metrics: summary: rpc_requests=1420 (+84) rate_limited=0 (+0) active_streams=2 tip_height=91840 tip_age=7s
```

- Watch `rate_limited` deltas during tester bursts; raise `rpc_rate_limit_per_min` if legitimate wallets hit `RESOURCE_EXHAUSTED`.
- Watch `tip_age`: if `tip_age` grows beyond ~120s, check `org.darkfi.darkfid` health (`ChainPoller` backs off exponentially up to `max_backoff_secs = 300s` when `darkfid` is unreachable and logs an error after 5 minutes).

---

## 3. Log Rotation & Disk Monitoring

### Log Verbosity
Keep `RUST_LOG=info` in `org.darkfi.lightwalletd.plist` (set automatically by `scripts/deploy-studio-lwd.sh`). Do **not** leave `-vv` or `RUST_LOG=trace` enabled in production — `h2` HTTP/2 frame logging can grow logs by gigabytes per day.

### Log Rotation (`newsyslog` on macOS)
Create `/etc/newsyslog.d/darkfi.conf` (root-owned, `0644`) to rotate logs at 50 MB and keep 5 compressed archives without restarting `launchd` agents (`N` = no signal, or use `copytruncate` semantics):

```text
# logfilename                                          [owner:group]  mode count size(KB) when flags
/Users/hawk/Library/Logs/darkfi/lightwalletd.out.log   hawk:staff     644  5     51200    *    JCN
/Users/hawk/Library/Logs/darkfi/lightwalletd.err.log   hawk:staff     644  5     51200    *    JCN
/Users/hawk/Library/Logs/darkfi/darkfid.stdout         hawk:staff     644  3     51200    *    JCN
/Users/hawk/Library/Logs/darkfi/darkfid.stderr         hawk:staff     644  3     51200    *    JCN
```

Validate with `sudo newsyslog -n -v`. If LaunchAgents hold open file descriptors across rotation, periodically truncate in place (`: > ~/Library/Logs/darkfi/lightwalletd.out.log`) or bounce the agent during a maintenance window.

### Disk Space Monitoring
Alert if root volume free space drops below **20 GiB** or **15% free**:

```bash
df -h /
du -sh ~/Library/Logs/darkfi ~/.local/share/darkfi/* ~/GitHub/*/target 2>/dev/null
```

Safe cleanup targets when reclaiming space:
- Stale Rust debug build directories (`~/GitHub/*/target/debug`) and old Xcode `DerivedData`.
- Rotated / stale log files under `~/Library/Logs/darkfi/`.
- **Never** delete live `darkfid` data or `~/.local/share/darkfi/lightwalletd_cache/testnet` while the service is running. If `lightwalletd_cache` must be rebuilt from scratch, stop `org.darkfi.lightwalletd` first, remove the cache directory, and restart (compact blocks rebuild automatically from `darkfid`; clue public keys and the directory attestation key will reset).

---

## 4. TLS Leaf Certificate Pin Rotation Runbook

Nighthawk clients enforce **fail-closed leaf DER SHA-256 certificate pinning** on remote `https://` endpoints (see [`TLS_PINNING.md`](TLS_PINNING.md)).

- **Current live testnet endpoint:** `https://epidermis-sandbox-marshland.ngrok-free.dev:443`
- **Current leaf pin:** `d8163009e3bb0bac39adbbfeb227827a91a590b96ec33f72576278c492be628e` (valid through **2027-02-22**; Let's Encrypt rotates `*.ngrok-free.dev` roughly every 60–90 days).

### Step 1: Compute the Live Leaf DER SHA-256 Pin & Expiry

```bash
# Using the helper script:
./scripts/print_tls_pin.sh --host epidermis-sandbox-marshland.ngrok-free.dev:443

# Or directly with openssl (prints validity window + 64-hex lowercase DER SHA-256 pin):
HOST="epidermis-sandbox-marshland.ngrok-free.dev"
openssl s_client -servername "$HOST" -connect "$HOST:443" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

openssl s_client -servername "$HOST" -connect "$HOST:443" </dev/null 2>/dev/null \
  | openssl x509 -outform DER \
  | openssl dgst -sha256 -hex
```

### Step 2: Roll Primary & Previous Pins Across Clients

Clients that support dual-pin rotation accept both a **primary** pin and a **previous/backup** pin so rolling updates do not break in-flight builds:

1. **Before rotation (planned self-hosted cert renewal):**
   - Generate or stage the next certificate, compute its 64-hex leaf DER SHA-256 pin (`NEW_PIN`).
   - Ship a lockstep client release setting `primary = NEW_PIN` and `previous = CURRENT_PIN` (or vice versa during overlap) across:
     - `nighthawk-android-wallet` (`gradle.properties` / `LIGHTWALLET_TLS_PIN_SHA256` + `LIGHTWALLET_TLS_PIN_PREVIOUS_SHA256` if configured)
     - `nighthawk-ios-wallet` (`project.pbxproj` / `LightwalletTlsPin.swift`)
     - `nighthawk-desktop` (default pin constants + `prefs.json` override)
     - `moonshine` (default testnet pin constant)
     - `docs/VERSION_LOCKSTEP.md` and Mac Studio `~/.local/share/darkfi/studio-lwd-endpoint.env`
   - Deploy the new certificate on the server and restart `lightwalletd` / TLS terminator.
2. **After unexpected upstream rotation (e.g., Let's Encrypt `*.ngrok-free.dev` auto-renewal):**
   - Compute `NEW_PIN` with Step 1 immediately.
   - Move the expired pin to `previous` (or retire it once expired) and set `primary = NEW_PIN` in all four clients, `VERSION_LOCKSTEP.md`, and `studio-lwd-endpoint.env`.
3. **Verify Fail-Closed Behavior:**
   - Confirm a client configured with `NEW_PIN` succeeds (`moonshine status` / `GetLightInfo`).
   - Confirm a client configured with a deliberately wrong 64-hex pin fails closed (non-zero exit, connection refused before gRPC RPCs execute).

> **Long-term hardening:** Before the `2027-02-22` certificate expiry, consider migrating off `*.ngrok-free.dev` wildcard leaf pinning to a dedicated Nighthawk-controlled domain behind nginx/HAProxy with pinned SPKI or controlled ACME renewal windows.
