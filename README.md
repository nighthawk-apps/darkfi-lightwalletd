# darkfi-lightwalletd

Privacy-preserving light wallet server for the DarkFi network. Serves compact blocks, UnifOMR digests, and transaction relay to mobile and desktop light wallets over gRPC.

## Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Run](#run)
- [gRPC API](#grpc-api)
- [Features](#features)
- [Infrastructure sizing](#infrastructure-sizing)
- [Related projects](#related-projects)
- [License](#license)

---

## Architecture

```
┌─────────────┐     gRPC (port 9067)     ┌─────────────────────┐     JSON-RPC     ┌──────────┐
│  Mobile /    │ ◄────────────────────► │ darkfi-lightwalletd  │ ◄──────────────► │ darkfid  │
│  Moonshine   │    Compact Blocks       │  (cache + detector)  │    Full Blocks   │ (node)   │
│  Wallet      │    OMR Digests          │  sled cache          │                  │          │
└─────────────┘                          └─────────────────────┘                  └──────────┘
```

The server:

1. Subscribes to new blocks from `darkfid` via JSON-RPC
2. Strips ZK proofs, signatures, and PoW data into compact blocks
3. Caches compact blocks in a local sled database
4. Serves them to wallets over gRPC
5. Runs OMR detection — **UnifOMR (scheme `0x05`)** when `fhe-omr` is enabled (default)

**Production clients use this binary** with `fhe-omr` (default). See [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md), [`docs/verification-checklist.md`](docs/verification-checklist.md), and [`docs/connectivity-triage.md`](docs/connectivity-triage.md).

---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Rust** stable (edition 2021) | [rustup](https://rustup.rs/) |
| **`protoc`** | On `PATH` (`tonic-build` in `build.rs`) |
| **`darkfi` checkout** | Sibling `../darkfi` (fetched by build script) |
| **Running `darkfid`** | JSON-RPC endpoint for full blocks |

Recommended layout after `./scripts/build.sh`:

```text
~/GitHub/
  darkfi/                 # fetched to sibling ../darkfi
  darkfi-lightwalletd/    # this repo
  moonshine/
  new-nighthawk-android-wallet/
  nighthawk-ios-wallet/
```

```bash
brew install protobuf                # macOS
sudo apt install protobuf-compiler   # Debian/Ubuntu
```

---

## Build

Independent clone (pulls `darkfi` next to this repo, then builds):

```bash
./scripts/build.sh
# Binary: ./target/release/darkfi-lightwalletd
```

`scripts/fetch-darkfi.sh` clones/updates the sibling checkout pinned by
`scripts/darkfi.rev`. Overrides:

```bash
DARKFI_DIR=/path/to/darkfi DARKFI_GIT_REF=<commit> ./scripts/fetch-darkfi.sh
./scripts/build.sh --no-default-features   # without UnifOMR / FHE
```

If `../darkfi` already exists (e.g. you develop the full Nighthawk tree):

```bash
cargo build --release
cargo test
```

---

## Run

### Configure

Copy [`lightwalletd.toml.example`](lightwalletd.toml.example) and set **`network`**
to `testnet` or `mainnet` explicitly. Invalid TOML, missing files, or a
`chain_name` that disagrees with `network` **exits the process** (no silent
fallback to defaults).

```toml
darkfid_endpoint = "tcp://127.0.0.1:18345"   # testnet; mainnet often 8345
# SECURITY: cleartext ONLY on loopback. Public binds REQUIRE TLS.
grpc_listen = "127.0.0.1:9067"
cache_path = "~/.local/share/darkfi/lightwalletd_cache"
poll_interval = 10
chain_name = "darkfi-testnet"
network = "testnet"                          # or "mainnet"

# Public / non-loopback example:
# grpc_listen = "0.0.0.0:9067"
# tls_cert_path = "~/.config/darkfi/lightwalletd.crt"
# tls_key_path = "~/.config/darkfi/lightwalletd.key"
```

Ops notes:

- `~` in `cache_path` / TLS paths is expanded via `$HOME`
- Default cache root is **scoped by network**:
  `…/lightwalletd_cache/testnet` or `…/lightwalletd_cache/mainnet`
  so compact blocks for the two networks never share a sled DB
- Chain poller stores compact blocks from `darkfid` into that cache and serves them over gRPC
- UnifOMR detection keys must carry the matching network byte (`0x00` mainnet / `0x01` testnet)

### TLS (required off-loopback)

Cleartext on non-loopback hosts is **refused at startup**.

```bash
# Self-signed (LAN / Mac Studio) or Let's Encrypt (public DNS):
./scripts/generate_tls_cert.sh self-signed --domain studio.local
# ./scripts/generate_tls_cert.sh letsencrypt --domain lw.example.com --email ops@example.com

# Emits certs + LIGHTWALLET_TLS_PIN_SHA256 (leaf DER SHA-256) under scripts/certs/
```

Full pin guide: [`docs/TLS_PINNING.md`](docs/TLS_PINNING.md).

### Start

```bash
# Ensure darkfid is up on darkfid_endpoint (same network as config.network)
cargo run --release -- --config lightwalletd.toml
# or: ./target/release/darkfi-lightwalletd --config lightwalletd.toml
```

### Point clients

| Client | How |
|--------|-----|
| Moonshine | `server_url = "http://127.0.0.1:9067"` (or `https://…` behind a trusted path) |
| Android | App settings / `-PLIGHTWALLET_TLS_PIN_SHA256=<64hex>` for remote HTTPS |
| iOS | `LIGHTWALLET_TLS_PIN_SHA256` build setting / UserDefaults override |

Clients must use the same `network` / `chain_name` family as this server.

---

## gRPC API

Defined in `proto/lightwallet.proto`.

| RPC | Purpose |
|-----|---------|
| `GetLightInfo` | Version, tip, `omr_supported` |
| `GetBlock` / `GetBlockRange` | Compact blocks |
| `GetCompactBlocksAtHeights` | Sparse compact blocks |
| `GetChainTip` | Tip height + hash |
| `SendTransaction` | Broadcast + optional `omr_clue` → `clue_accepted` |
| `RegisterOmrClue` | Transitional clue register (peer-bound) |
| `GetUnifOmrDigest` | UnifOMR Round 1 (scheme `0x05`) |
| `FetchPirBatch` | UnifOMR Round 2 |
| `RegisterCluePublicKey` / `GetCluePublicKey` | UnifOMR send-path registry |
| `GetOmrCapabilities` | Scheme + limits (`unifomr` when `fhe-omr`) |
| `GetNullifiers` / `GetNoteCommitments` | Spend / commitment sync |

`OmrDigestRequest`:

- `detection_key` — legacy single key
- `detection_keys` — multi-address (preferred when N > 1)
- Multi-key response framing: repeated `[u32 LE len][digest bytes]`

### Wire constants

| Field | Values |
|-------|--------|
| Network | Mainnet `0x00` · Testnet `0x01` |
| Scheme | **UnifOMR `0x05` (only)** |
| Multi-address | Cap **16** keys; SIMD slots = block heights |

---

## Features

### Transport & access control

| Feature | Status | Notes |
|---------|--------|-------|
| **TLS off-loopback (S6)** | ✅ | Cleartext only on `127.0.0.1` / `::1` / `localhost` |
| **Optional PEM TLS** | ✅ | `tls_cert_path` + `tls_key_path` |
| **OMR rate limit** | ✅ | `omr_rate_limit_per_min` |
| **Clue rate limit** | ✅ | Tighter on `RegisterOmrClue` |
| **Detection key size cap** | ✅ | Reject oversized UnifOMR keys (~48 MiB) |
| **Max block range** | ✅ | Caps range RPCs (DoS) |

### Compact blocks & cache

| Feature | Status | Notes |
|---------|--------|-------|
| **Proof/signature stripping** | ✅ | Compact blocks only |
| **Empty-height FHE slots (S19)** | ✅ | Every height in range occupies a SIMD slot |
| **Skip note clone when clue present (P2)** | ✅ | Detector uses `omr_clue` when set |
| **Clue hint TTL (S21)** | ✅ | Orphan hints expire (**24h**) |
| **First-empty / indexed clue apply (S20)** | ✅ | One clue → first empty output or explicit index |
| **No per-hint sled.flush (P8)** | ✅ | Flush with block insert / shutdown |

### OMR detection

| Feature | Status | Notes |
|---------|--------|-------|
| **UnifOMR (0x05, default w/ `fhe-omr`)** | ✅ | `GetUnifOmrDigest` + RLWE clues |
| **FetchPirBatch** | ✅ | Length-prefixed SealPIR-style limbs |
| **RegisterCluePublicKey / GetCluePublicKey** | ✅ | Decoy directory; **250 ms** timing pad |
| **FHE any-match (S1)** | ✅ | Per-clue layers, client OR |
| **Multi-key digest (S17)** | ✅ | Cap **16** |
| **spawn_blocking OMR (P1)** | ✅ | Off the async gRPC worker |
| **Timing pad** | ✅ | Min response time on UnifOMR + clue-dir |
| **UnifOMR clue validate** | ✅ | Size + parse + noise bound |

### Transaction / clue path

| Feature | Status | Notes |
|---------|--------|-------|
| **SendTransaction + omr_clue** | ✅ | Hint keyed by tx hash (**24h** TTL) |
| **clue_accepted (S22)** | ✅ | Tx may succeed while clue is rejected |
| **RegisterOmrClue peer bind (S12)** | ✅ | Prior `SendTransaction` from same peer within **24h** |
| **Envelope parse** | ✅ | Wire OMR envelope can supply FHE clue |

### UnifOMR (scheme 0x05)

- Requires this binary with `fhe-omr` (default feature)
- Cross-client crypto parity: RLWE `n=1024`, signed AHE, `CLUE_ERROR_BOUND=2`, length-prefixed SealPIR limbs
- Flow: RegisterCluePublicKey → GetClue → SendTransaction(omr_clue) → GetUnifOmrDigest → FetchPirBatch
- Empty OMR → clients may supplemental trial-decrypt (decoy directory ≠ failure)
- Clients default to `http://127.0.0.1:9067`; `network` / `chain_name` must match wallets
- Clue hints from `SendTransaction` live **24h** until the confirming block is indexed
- Limits: [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md)

| Item | Status |
|------|--------|
| Crypto parity LWD ↔ moonshine ↔ iOS ↔ Android (`n=1024`) | ✅ |
| Registration matrix + digest round-trip | ✅ |
| PIR assemble / CompactBlock reassembly | ✅ |
| Clue noise bound vs `R_PRIME` | ✅ |
| Clue hint 24h TTL · GetClue 250ms pad | ✅ |
| Decoy directory `found` channel | ✅ |
| Funded broadcast → confirm → PIR e2e | ⏳ needs live `darkfid` |
| Paper Param2 structural params (`n,q,h,r,D,ℓ`) | ✅ active — see `docs/unifomr_mvp_limits.md`; archived MVP in `docs/unifomr_mvp_archive.md` |
| Paper FP/FN rates | ❌ not claimed until digest mod-switch + measured FP |

### Privacy invariants

| Invariant | Status |
|-----------|--------|
| No wallet accounts / session identity | ✅ |
| Do not log detection keys or match heights | ✅ |
| Sanitize darkfid errors to clients | ✅ |

---

## Infrastructure sizing

| Resource | 1k users | 10k | 100k |
|----------|----------|-----|------|
| CPU | 2 | 8 | 32+ (detector pool) |
| RAM | 4 GB | 16 GB | 64+ GB |
| Storage | 50 GB SSD | 200 GB | 1 TB NVMe |
| Bandwidth | ~50 Mbps | ~500 Mbps | ~5 Gbps |

---

## Related projects

| Project | Role |
|---------|------|
| [moonshine](../moonshine) | CLI light wallet |
| [new-nighthawk-android-wallet](../new-nighthawk-android-wallet) | Android |
| [nighthawk-ios-wallet](../nighthawk-ios-wallet) | iOS |

---

## License

Copyright (C) 2026 Nighthawk Apps — **AGPL-3.0-or-later** (see [`LICENSE`](LICENSE) and [`COPYRIGHT`](COPYRIGHT)).
