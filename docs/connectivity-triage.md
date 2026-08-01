# Connectivity triage & client handling matrix

Operational guide for **darkfid → darkfi-lightwalletd → wallets** (moonshine, iOS/Android FFI).

## Stack

```
darkfid (P2P :18340, RPC :18345)
    ↓ JSON-RPC poll
darkfi-lightwalletd (gRPC :9067, sled cache)
    ↓ GetLightInfo / GetUnifOmrDigest / FetchPirBatch / SendTransaction
moonshine | iOS | Android (darkfi-mobile-ffi)
```

---

## Live triage checklist

| Check | Command / signal | Healthy |
|-------|------------------|---------|
| darkfid RPC | `printf '%s\n' '{"jsonrpc":"2.0","method":"ping","params":[],"id":1}' \| nc -w2 127.0.0.1 18345` | `"result":"pong"` |
| darkfid tip | `blockchain.last_confirmed_block` | Height increases over time |
| P2P seeds | darkfid log: `Connected seed`, handshake to `lilith*.dark.fi:18340` | Seeds reachable |
| LWD gRPC | `lsof -iTCP:9067 -sTCP:LISTEN` | Listening |
| LWD ↔ darkfid | No repeating `Poll failed` in LWD log | Poller connects |
| Tip alignment | LWD `Cache contains blocks up to height X` ≈ darkfid tip | Within a few blocks |
| Config | `lwd-testnet.toml` uses **`cache_path`** (not `cache_db`) | Path intentional |

### Common failures (observed)

1. **darkfid down** — LWD `Poll failed: Connection refused :18345`. Cache serves **stale** blocks; UnifOMR digests reflect old state only.
2. **Tip regression** — darkfid tip **10**, LWD cache **5300** (fresh darkfid DB + old cache). Fixed: poller rewinds when `remote < cached`.
3. **Wrong TOML key** — `cache_db` ignored → default `~/.local/share/darkfi/lightwalletd_cache` used instead of `/tmp/...`.
4. **darkfid “synced” at low height** — Alpha testnet may report `Blockchain synced!` at small tip; verify peers (`node0.testnet.dark.fi`) and allow time for block download.
5. **Empty hostlist** — Normal on first run; grows after successful peer addr exchange.
6. **Peer `tiprequest` errors** — Some peers drop; outbound slots retry. Not fatal if ≥1 synced peer exists.

### Reset when chains diverge

```bash
# Stop daemons, wipe mismatched state, resync
pkill darkfid darkfi-lightwalletd
rm -rf ~/.local/share/darkfi/darkfid/testnet   # darkfid chain + p2p
rm -rf /tmp/darkfi-lwd-testnet-cache           # LWD cache (if using testnet toml)
# restart darkfid, wait for sync, then LWD
```

---

## Scenario matrix — what clients should do

| Scenario | Symptom | LWD | Moonshine | iOS / Android FFI |
|----------|---------|-----|-----------|-------------------|
| **LWD unreachable** | gRPC connect fail | — | Sync error; no tip advance | Exponential backoff (5s→300s); retry loop |
| **LWD up, darkfid down** | GetLightInfo OK; stale tip; poller errors | Serves cache | OMR on stale range; may miss new txs | Same; `is_backend_catching_up` false |
| **darkfid catching up** | Tip jumps >100 blocks / 5min | Poll ingests batches | — | OMR failures **not counted**; trial fallback allowed |
| **OMR RPC transient** | `Unavailable` / `Internal` | Retryable | Moonshine: **hard fail**, no silent trial (use `--force-trial`) | Retry OMR until `max_omr_failures` (5), then trial decrypt |
| **OMR digest decrypt fail** | Bad/unifomr bytes | — | Hard fail (no height-list fallback) | Hard fail on UnifOMR path |
| **Empty OMR matches** | 0 heights in window | Normal | **Supplemental full-window trial decrypt** | Same (unless `strict_omr_only`) |
| **Unregistered recipient** | GetClue decoy PK | Always `found=true` | GenClue as UnifOMR | Same; receiver relies on **trial decrypt** if OMR misses |
| **Malformed clue PK** | Deserialize error | — | Fail send / no clue | Fail send / no clue |
| **No LWD URL (send)** | — | — | Cannot build UnifOMR clue | Cannot build UnifOMR clue |
| **PIR empty / decode fail** | Round-2 error | — | Err; gap trial if configured | Err; gap trial decrypt |
| **Reorg** | Tip hash change | Cache rewind ~10 blocks | Tip regression rewind (checklist) | `update_chain_tip_hash` → DB rewind + UI callback |
| **Rate limit** | `ResourceExhausted` | Per-IP OMR/clue limits | Retry as transient | Classified `Unavailable`, retryable |
| **Strict OMR mode** | User/opt-in privacy | — | N/A | After max failures → **Error** status, no trial |

---

## Client implementation references

- **gRPC error classification:** `darkfi-mobile-ffi/src/lightwallet_client.rs` — `GrpcErrorKind`, `is_retryable()`.
- **Sync loop / fallback:** `darkfi-mobile-ffi/src/sync.rs` — OMR first, trial after threshold, backend catch-up exemption.
- **Sync engine policy:** `darkfi-mobile-ffi/src/lightwallet_sync.rs` — `record_omr_failure`, `choose_sync_type`, backoff.
- **Moonshine (stricter):** `moonshine/src/sync.rs` — OMR failure **blocks** tip advance unless `--force-trial`.
- **Send path clues:** `darkfi-mobile-ffi/src/transactions.rs` — directory → UnifOMR only (no legacy scheme fallback).
- **LWD poller:** `darkfi-lightwalletd/src/chain_poller.rs` — backoff, reorg, tip regression rewind.

---

## UI / product expectations

1. **Never show “synced” when LWD unreachable** — surface `Degraded` / retry state.
2. **Reorg** — show callback message; history may lose recent unconfirmed sends.
3. **Send without LWD** — UnifOMR clue requires LWD directory + broadcast path; fail closed.
4. **Testnet 0.3-alpha** — run local `darkfid` with `network = "testnet"`; point wallet/LWD at `tcp://127.0.0.1:18345` / `http://127.0.0.1:9067`.
5. **Physical device** — `adb reverse tcp:18345 tcp:18345` and `tcp:9067 tcp:9067` for loopback presets.
