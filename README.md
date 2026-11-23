# darkfi-lightwalletd

Privacy-preserving light wallet server for the DarkFi network. The default binary serves compact blocks for trial decryption. Experimental UnifOMR is a separate build (`--features fhe-omr`).

**0.3.12.** UnifOMR worker count, detection-key pool, and upload deadline are config knobs. A darkfid error during reorg search no longer wipes the cache. An interrupted rewind resumes on startup, and O2 recipient memos are kept. Aligns with Nighthawk Android/iOS 3.01.19, desktop 3.1.19, and Moonshine 3.1.19. DarkFi pin for wallets is `6e61deb26` (contains `9d7ceaf77`); build sibling checkout notes below still accept that pin.

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
5. Serves those compact records for wallet trial decryption. Experimental UnifOMR detection runs only when the binary is built with `fhe-omr`.

**Production clients use the default binary** (no `fhe-omr`). See [`docs/verification-checklist.md`](docs/verification-checklist.md) and [`docs/connectivity-triage.md`](docs/connectivity-triage.md). UnifOMR limits stay in [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md).

---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| **Rust** stable (edition 2021) | [rustup](https://rustup.rs/) |
| **`protoc`** | On `PATH` (`tonic-build` in `build.rs`) |
| **`darkfi-nighthawk-testnet`** | Sibling directory **literally named** `../darkfi-nighthawk-testnet` at pin `9d7ceaf77` (nighthawk24 `nighthawk-testnet`). Upstream DarkFi is [git.dark.fi/darkrenaissance/darkfi](https://git.dark.fi/darkrenaissance/darkfi), not the GitHub mirror. That pin is not on git.dark.fi, so a master checkout is not enough. Reuse Android `nighthawk-android-wallet/third_party/darkfi` with `ln -sfn`. |
| **Running `darkfid`** | JSON-RPC endpoint for full blocks |

Recommended layout after `./scripts/build.sh`:

```text
~/GitHub/
  darkfi-nighthawk-testnet/   # pin 9d7ceaf77 — or symlink to Android third_party/darkfi
  darkfi-lightwalletd/        # this repo
  moonshine/
  nighthawk-android-wallet/
  nighthawk-ios-wallet/
```

```bash
# Clean setup on a new Mac:
brew install protobuf

# Sibling darkfi checkout at required pin (9d7ceaf77):
git -C ../darkfi worktree add --detach ../darkfi-nighthawk-testnet origin/nighthawk-testnet
# Or reuse the Android pin instead of a worktree:
# ln -sfn nighthawk-android-wallet/third_party/darkfi darkfi-nighthawk-testnet
```

---

## Build

Independent clone (pulls `darkfi-nighthawk-testnet` next to this repo, then builds):

```bash
./scripts/build.sh
# Binary: ./target/release/darkfi-lightwalletd
```

`scripts/fetch-darkfi.sh` clones/updates the sibling checkout pinned by
`scripts/darkfi.rev` (`9d7ceaf77da7ccfd29ead3ba168fab284decd8c8`). Overrides:

```bash
DARKFI_DIR=/path/to/darkfi-nighthawk-testnet DARKFI_GIT_REF=<commit> ./scripts/fetch-darkfi.sh
./scripts/build.sh --features fhe-omr      # experimental UnifOMR / FHE
```

If `../darkfi-nighthawk-testnet` already exists (symlink to Android `third_party/darkfi` is OK):

```bash
cargo build --release --all-features
# Unit tests do not need compiled contract *.zk.bin (no test-harness dep).
cargo test --release --lib
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
# Remote Mac Studio deploy helper supports STUDIO_SSH_TARGET, STUDIO_REPO_DIR, LWD_NGROK_DOMAIN, and LWD_PORT overrides:
# STUDIO_SSH_TARGET=hawk@mac-studio ./scripts/deploy-studio-lwd.sh --remote
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
| `GetOmrCapabilities` | Disabled in the default build. `unifomr` only with `--features fhe-omr` |
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
| **Trial decrypt compact blocks (default)** | ✅ | `GetCompactOutputBodies`, nullifiers, DAO calls |
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
| **SendTransaction + omr_clue** | ✅ | Hint keyed by tx hash and output index (**24h** TTL). `extra_omr_clues` covers the sender's other outputs |
| **clue_accepted (S22)** | ✅ | Tx may succeed while clue is rejected |
| **RegisterOmrClue peer bind (S12)** | ✅ | Prior `SendTransaction` from same peer within **24h** |
| **Envelope parse** | ✅ | Wire OMR envelope can supply FHE clue |

### UnifOMR (scheme 0x05)

- Experimental. Build with `--features fhe-omr`. The default binary does not serve it.
- Cross-client crypto parity: RLWE `n=1024`, signed AHE, `CLUE_ERROR_BOUND=2`, length-prefixed SealPIR limbs
- Flow: RegisterCluePublicKey → GetClue → SendTransaction(omr_clue) → GetUnifOmrDigest → FetchPirBatch
- Empty OMR → clients may supplemental trial-decrypt (decoy directory ≠ failure)
- Clients default to `http://127.0.0.1:9067`; `network` / `chain_name` must match wallets
- Clue hints from `SendTransaction` live **24h** until the confirming block is indexed
- Limits: [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md)
- Sync speed (snapshots, padded ranges, detection-key pool, tip subscribe): [`docs/wallet-sync-speed-plan.md`](docs/wallet-sync-speed-plan.md)

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

Two different loads. **Trial decryption** (default binary) is cheap per client.
**UnifOMR** (`--features fhe-omr`) is dominated by Param2 detection keys
(~120 MiB each on the wire; see [`docs/unifomr_mvp_limits.md`](docs/unifomr_mvp_limits.md))
and by the process-wide FHE worker pool (`fhe_workers`, default **2**).

Configurable caps (see `lightwalletd.toml.example`):

| Cap | Default | Config key |
|-----|---------|------------|
| Max TCP connections | 512 | `max_connections` |
| Max streams / connection | 256 | `max_streams_per_conn` |
| Concurrent block-range streams | 200 | `MAX_BLOCK_RANGE_STREAMS` (code) |
| OMR RPCs / min / IP | 30 | `omr_rate_limit_per_min` |
| Concurrent FHE digests | 2 | `fhe_workers` |
| Concurrent PIR workers | `max(fhe_workers, 4)` | derived from `fhe_workers` |
| Detection-key upload budget | 512 MiB | `upload_budget_mib` |
| Det-key upload deadline | 300 s | `upload_deadline_s` |
| Pooled detection keys | ≤4096 handles, **8 GiB** | `detection_pool_handles`, `detection_pool_mib` |
| Det-key / request | ≤160 MiB | `max_detection_key_bytes` |
| Compact-block range | ≤10 000 heights | `max_range_per_request` |

### Trial decryption (default binary) — minimum host specs

“Simultaneous” = active gRPC streams (compact blocks / tip poll), not UnifOMR digests.

| Resource | **100 clients** (hosting floor) | **1000 clients** (simultaneous) |
|----------|----------------------------------|---------------------------------|
| CPU | **4 cores** | **8–16 cores** |
| RAM | **8 GB** | **16–32 GB** |
| Storage | **100 GB SSD** (compact cache) | **200–500 GB NVMe** |
| NIC | **100–200 Mbps** | **500 Mbps–1 Gbps** |
| Config | defaults fine | set `max_connections ≥ 1024` (or LB in front); keep block-range permits ≥ concurrent catch-up clients |

### UnifOMR-enabled (`--features fhe-omr`) — minimum host specs

UnifOMR stays **opt-in** on clients. Size for detection-key RAM and FHE CPU, not only TCP fan-out.

| Resource | **100 UnifOMR-capable clients** | **1000 UnifOMR-capable clients** |
|----------|----------------------------------|----------------------------------|
| CPU | **8+ cores**; set `fhe_workers` ≈ `cores/2` (keep ≥2 free for gRPC) | **Multi-node.** Default `fhe_workers=2` per process; 1000 concurrent digests need a fleet or much larger `fhe_workers` + CPU |
| RAM | **32 GB** (8 GiB key pool + 512 MiB upload budget + OS + sled) | **64 GB+ per node**, or raise `detection_pool_mib` / accept per-request uploads when the pool is full |
| Storage | **200 GB NVMe** | **500 GB–1 TB NVMe** per node |
| NIC | **1 Gbps** (~120 MiB/key; four uploads ≈500 Mbps) | **10 Gbps aggregate** across nodes, or edge-terminate TLS/gRPC |
| Practical concurrent digests | ≈`fhe_workers` in flight; ≈`upload_budget_mib / 120` uploads; ≈`detection_pool_mib / 120` pooled keys | Same **per node**. Plan ~15–30 digest-capable nodes if every client digests often, or keep UnifOMR rare and rely on trial decrypt |

Hard limits until the crypto path shrinks keys:

1. **One Param2 detection key ≈ 120 MiB.** Symmetric seed encryption (`det_sk.try_encrypt`) can cut that roughly in half (~60 MiB) with no server change; still experimental.
2. **`fhe_workers` (default 2)** serializes digests. Raising it without matching CPU makes the box thrash. PIR concurrency is `max(fhe_workers, 4)`.
3. **OMR rate limit 30/min/IP** also covers `FetchPirBatch`. Shared Tor exits share that budget; PIR-per-limb loops can exhaust it (see [`docs/fable-5.1-audit-unifomr-sync-source.md`](docs/fable-5.1-audit-unifomr-sync-source.md)).
4. **1000 simultaneous UnifOMR digests on one box is not realistic** with Param2. Size 1000 for *connections* on the trial-decrypt path; size UnifOMR for *active digests* (tens per node).

Lab / self-host starting point (≤100 wallets, few digests at once): 8-core ARM or x86, 32 GB RAM, 200 GB NVMe, 1 Gbps, `request_timeout_s ≥ 1800`, `fhe_workers=4`, reverse-proxy body ≥ 160 MB (`docs/deploy-hardening.md`).

Measured on this Mac (Apple Silicon, `cargo test --release --features fhe-omr --lib measure_hosting_timings -- --ignored`, 2026-11-23):

| Op | Result |
|----|--------|
| Detection key size | **125 863 941 B (~120.0 MiB)**, 1024 CTs |
| `from_wallet` | 21 ms |
| `build_detection_key` | 759 ms |
| `parse_detection_key` | 219 ms |
| Encode one full SIMD chunk (`D=4096`) | 495 ms total (275 ms eval after parse) |
| Digest size (1 chunk) | 81 997 B |
| Decrypt digest slots | 0.42 ms |
| PIR evaluate 1 / 2 stripes (one limb) | 0.63 ms / 1.25 ms |
| PIR query CT | 122 910 B |
| Money-tree append 1000 coins (Sinsemilla) | 70 ms |

So UnifOMR hosting cost is **key upload + FHE encode**, not Merkle hashing. With `fhe_workers=2`, a single box sustains on the order of a few digests per second for one-chunk windows, not hundreds.

### Compact-block Money-tree fast sync (Sinsemilla, not Pedersen)

DarkFi’s Money Merkle tree uses **Sinsemilla** `MerkleCRH` (`darkfi` `MerkleNode::combine`, Orchard-style), not Sapling Pedersen hashes. Compact blocks carry a Pedersen **value commitment** (`value_commit`) for spend proofs; light clients append `coin` field elements into the tree via `MerkleNode::from` / `from_bytes`.

What is already good enough for production trial-decrypt sync:

- Tip tree on lightwalletd keeps the dummy `ZERO` leaf so roots match wallets (`cache.rs` `empty_tip_tree`).
- Clients refuse non-canonical coin bytes instead of silently shifting leaves.
- Supplemental UnifOMR trial decrypt can walk compact blocks with `append_commitments = false` so the tree is not double-appended.
- Checkpoints / `GetNoteCommitments` replay are the catch-up path; see [`docs/wallet-sync-speed-plan.md`](docs/wallet-sync-speed-plan.md).

Worthwhile cross-client optimizations (shared Rust in `darkfi-mobile-ffi` / Moonshine, not per-UI):

| Idea | Why | Risk |
|------|-----|------|
| Historical Merkle snapshots every 1024 heights | Avoids replaying `0..=birthday` coin appends | Proto / disk; already designed in the sync-speed plan |
| Batch `MerkleNode::combine` / fewer tree flushes per window | BridgeTree append is cheap; sled serialize of the full tree is not | Keep one flush per window |
| Verify `value_commit` after AEAD decrypt (Pedersen open) | Catches a malicious LWD that swaps notes | Extra CPU on match only; not on every compact output |
| Do not re-upload a 120 MiB UnifOMR det-key every 5 s poll | Dominates sync more than Merkle hashing | Unlinkability trade-off; use the detection-key pool |

---

## Related projects

| Project | Role |
|---------|------|
| [moonshine](../moonshine) | CLI light wallet |
| [nighthawk-android-wallet](../nighthawk-android-wallet) | Android |
| [nighthawk-ios-wallet](../nighthawk-ios-wallet) | iOS |

---

## License

Copyright (C) 2026 Nighthawk Apps — **AGPL-3.0-or-later** (see [`LICENSE`](LICENSE) and [`COPYRIGHT`](COPYRIGHT)).
