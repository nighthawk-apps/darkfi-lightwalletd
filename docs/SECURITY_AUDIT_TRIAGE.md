# Security Audit Triage (2026-08-03)

Validated against this Rust/tonic rewrite and the Nighthawk clients. The external audit mixed a Go `zcash/lightwalletd` threat model with this stack.

## Not applicable / already fixed

| Claim | Verdict |
|-------|---------|
| GHSA mutex/`GetMempoolTx` exclude-list backports (F-01..F-06) | **N/A** — no mempool RPC; not a Go fork |
| gRPC reflection enabled by default | **Already off** |
| Moonshine Electrum / AsyncStorage / BitID | **Wrong product** (local moonshine is DarkFi CLI) |
| Desktop Electron `contextIsolation` / updater | **Wrong stack** (Tauri 2) |
| iOS Keychain `WhenUnlockedThisDeviceOnly` | **Already set** |
| Android `allowBackup` | **Already hardened** |
| ChaCha DM nonce reuse (FT-13) | **False** — fresh random nonce |
| `tx_inspect` “accepts” unknown contracts (FT-09) | **False** as consensus risk — UI labels only |
| Block range unbounded | **Already capped** at 10 000 blocks |

## Confirmed gaps (remediated in this workstream)

| ID | Component | Issue |
|----|-----------|-------|
| FT-01 | LWD + clients | `GetCluePublicKey` returned unverified clue PK |
| DoS | LWD | No app-level `SendTransaction` size cap; `GetTransaction` hash unbound |
| DoS | LWD | Missing accept/stream concurrency + keepalive; rate limits only on OMR |
| Ops | LWD→darkfid | No RPC connect timeout / DNS pin |
| FT-06 | Clients | Pin-only verifier ignored hostname/expiry |
| FT-02..FT-12 | Clients | Envelope bounds, OMR downgrade, Tor default, secret hygiene, etc. |

See also: [deploy-hardening.md](deploy-hardening.md), [TLS_PINNING.md](TLS_PINNING.md).
