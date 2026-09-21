# Nighthawk audit — desktop 3.0.14, moonshine 3.0.14, lightwalletd 0.2.1

Read-only; no files changed. Line numbers are from the current working trees (including uncommitted edits).

---

## 1. DESKTOP — `/Users/adi/GitHub/nighthawk-app-desktop`

### MUST-FIX before release

| # | Location | Issue | Fix |
|---|---|---|---|
| D1 | `src/web/components/main-app.ts:67-71` + `src-tauri/src/secure_store.rs:261-281` | Any error from `openWallet()` (LWD unreachable, bad TLS-pin hex, keychain hiccup) drops the UI into **onboarding** even though a vault exists. Clicking "Create new wallet" → `persist_and_open` → `create_vault` → `write_vault_files` **unconditionally overwrites `vault.dat`/`vault.meta.json`**, destroying the existing seed with no confirmation. | In `main-app.ts`, when `exists === true` and open fails, show an error/retry screen, never `phase = "onboarding"`. In `write_vault_files`, refuse if `vault_ready()` unless caller passed an explicit `overwrite` flag (only `wipe_wallet` path). |
| D2 | `src-tauri/src/commands.rs:392-501, 590-703, 846-855` | Every wallet command except `open_wallet` is a **sync `fn`** → Tauri 2 runs it on the main thread. `wallet_refresh`, `send_drk` (ZK proving), `dao_propose_transfer`, `dao_vote`, `estimate_fee`, `create_wallet`/`restore_wallet` (`open_handle`), `chat_start` freeze the window for seconds–minutes, and `with_wallet` holds `state.wallet` (parking_lot) for the whole FFI call so `app_status`/`mine_status`/`set_prefs` also block. | Mark these `#[tauri::command(async)]` (or `pub async fn` + `spawn_blocking`, like `open_wallet` at 363-377), and clone the `Arc<DarkfiWalletHandle>` out of the mutex before calling into FFI. |
| D3 | `src-tauri/src/wallets.rs:134-148` | `remove_profile` never checks `wallet_id` is in the registry (unlike `switch_profile`:111) and then `remove_dir_all(app_root()/wallets/<wallet_id>)`. A traversal id (`../../Documents`) from IPC deletes arbitrary user directories. | Validate `wallet_id` matches `^w\d+$` / exists in `reg.wallets` before `retain` + `remove_dir_all`; also canonicalize and assert `starts_with(app_root().join("wallets"))`. |
| D4 | `src-tauri/src/wallets.rs:85-106`, `commands.rs:811` | `wallets_create` switches active profile paths (`apply_wallet_profile`) but does **not** clear `state.wallet` or `secure_store::clear_session()` (cf. `wallets_switch` 820-829). The old handle keeps syncing into the now-inactive profile dir, and `backup_mnemonic` returns the *old* seed while `wallet_exists()` reports the new profile. | In `wallets_create` command: kill miner, `*state.wallet.lock()=None`, `clear_session()`, then `create_profile`. |
| D5 | `src-tauri/src/paths.rs:31-33`, `prefs.rs:66` vs `README.md:18,115`, `ARCHITECTURE.md:5`, `README.md:14` | Release defaults are dev leftovers: mainnet `default_lwd()` = `http://127.0.0.1:9067` ("MacBook Pro loopback"), `use_tor: false` while README says Tor is on by default, README/ARCHITECTURE say vault is "PBKDF2 / not OS keyring" but `secure_store.rs:181-189` requires the OS keychain. | Set real mainnet LWD URL + `default_lwd_tls_pin`, set `use_tor: true` (or fix docs), update README:14/18/115 and ARCHITECTURE:5. |

### SHOULD-FIX soon

| # | Location | Issue | Fix |
|---|---|---|---|
| D6 | `secure_store.rs:129-131, 283-308` | `key_matches_meta` accepts `key_hash == hex(raw AES key)` — legacy vaults keep the **plaintext vault key in `vault.meta.json`** beside the ciphertext and are never migrated. | On successful open with a raw-key meta, rewrite via `write_vault_files` (fingerprint form). |
| D7 | `secure_store.rs:290-292`, `161-177` | The fallback loop in `decrypt_payload` calls `file_master_key()`, which **creates and writes a new random `vault.key`** if none exists — contradicting the "never write master key beside ciphertext" rule at 179-189 and leaving junk key files. | Split into `read_file_master_key()` (no create) for the read/fallback path. |
| D8 | `secure_store.rs` (whole), `dm_store.rs:28-36` | No zeroization: `[u8;32]` keys, `Session.mnemonic`, `wallet_pass` live until dropped. `zeroize` isn't a dependency. | Add `zeroize`, wrap keys/`Session` fields in `Zeroizing`. |
| D9 | `commands.rs:729-751`, `chat-screen.ts:454, 844` | `dm_generate_keypair`/`dm_load_keypair` hand the ChaChaBox **secret key to the webview** and every `dm_encrypt/decrypt` round-trips it. Any XSS gets the DM secret. | Keep the secret in Rust; expose only `public_b58` and do encrypt/decrypt server-side keyed by session. |
| D10 | `commands.rs:1219-1221`, `secure_store.rs:404-406` | `backup_mnemonic` requires only an "unlocked session", which is auto-unlocked at launch. Combined with no PIN, any injected JS can `invoke("backup_mnemonic")`. | Gate on a fresh OS auth (Touch ID / keychain ACL prompt) or an explicit user confirmation dialog from Rust (`tauri::dialog`), not from JS. |
| D11 | `commands.rs:286-290` | `create_wallet`/`restore_wallet` accept `lightwallet_url` and store it **without `validate_lwd_url`** (unlike `set_prefs`/`set_lwd_url`). | Call `validate_lwd_url(&url)?` in `persist_and_open`. |
| D12 | `commands.rs:1091-1113` | `stratum_url` from prefs is unvalidated; xmrig config sets `"tls": false`, so the **wallet deposit address is sent in cleartext** to whatever host the pref points to, not via Tor. | Require loopback or `tls:true` for non-loopback stratum; reject other schemes. |
| D13 | `commands.rs:1036-1049` | `mine_status` `read_to_string` of the entire `xmrig.log` every 5 s poll; the log is unbounded. | Read only the last N KiB (`seek` from end) or rotate the log. |
| D14 | `commands.rs:901, 923` | `save_prefs(...).map_err(\|e\| e.to_string())` — not `map_err` (redaction). Only two unredacted returns in the file. | Use `map_err(map_err)`. |
| D15 | `commands.rs:1187-1216` | `validate_lwd_url`: `host_str()` for IPv6 returns `[::1]`, so `::1` never matches loopback; `http://[::1]:9067` is rejected, `https://[fc00::1]` (private) is allowed. | Use `parsed.host()` enum + `Ipv6Addr::is_loopback()/is_unique_local()`. |
| D16 | `wallets.rs:87` | Profile id `format!("w{}", now_secs())` collides if two profiles are created within one second. | Use `format!("w{}-{}", secs, random_u32)` or a counter. |
| D17 | `src-tauri/capabilities/default.json:9`, `lib.rs:29` | `shell:allow-open` + `tauri_plugin_shell` are enabled but the frontend never imports `@tauri-apps/plugin-shell`; opener already covers `<a target=_blank>`. Redundant privileged surface. | Drop the shell plugin and permission. |
| D18 | `tauri.conf.json:25` | CSP `connect-src` allows `http://127.0.0.1:* http://localhost:*` — the webview never talks to LWD directly. No `frame-src 'none'`/`form-action 'self'`. | `connect-src 'self'`; add `frame-src 'none'; form-action 'self'`. |
| D19 | `settings-screen.ts:404`, `:312-316` | About says "Nighthawk Desktop **0.1.0**"; strict-OMR help text says "Off by default" while `prefs.rs:45-47` defaults to `true`. | Inject version from `package.json`/`app.getVersion()`; fix copy. |
| D20 | `settings-screen.ts:385-398` | Seed shown in DOM indefinitely and copied to clipboard with no auto-clear. | Auto-hide after ~60 s; clear clipboard after copy (or warn). |
| D21 | `src-tauri/Cargo.toml:45`, `binaries/` | Path dep `../../new-nighthawk-android-wallet/rust/darkfi-mobile-ffi` is machine-specific; only `xmrig-aarch64-apple-darwin` sidecar exists while `externalBin` is declared → non-arm64-mac `tauri build` fails. No `.github/workflows`. | Document/fetch script for FFI path; add per-target sidecars or make `externalBin` target-conditional. |
| D22 | `src-tauri/Cargo.toml:37, 30, 21, 46` | `argon2`, `hmac`, `thiserror`, `blake3`, `async-stream` declared but unused in `src-tauri/src`. | Remove. |
| D23 | `chat-screen.ts:561-567` | Chat URLs from untrusted peers render as `<a target=_blank>`; opener plugin opens them in the system browser on click. Regex restricts to `https?://`, so not XSS, but drive-by phishing from chat. | Confirm-before-open, or route through a Rust command that shows the URL. |

### Verified OK
- No `unsafeHTML`/`innerHTML`; all user/peer content goes through Lit text bindings (`chat-screen.ts:557-573`, `wallet-screen.ts:344-355`, `mine-screen.ts:220`).
- `seal()` nonces random per encryption (`secure_store.rs:207-208`, `dm_store.rs:40-41`); `mix_master` is HMAC-style over a random 256-bit master, 1 PBKDF2 round is fine.
- Reorg callback → `wallet://reorg` emit (`commands.rs:131-144`); darkirc callback → `chat://message` (95-115); `strict_omr_only` default `true` and passed to `DrkBootstrapConfig` (184) and applied live in `set_prefs` (229).
- TLS-pin plumbing validates 32-byte multiples ≤128 (158-171). `darkfid_rpc_url` default `None`.
- xmrig spawn: args are fixed flags + JSON config file; threads clamped 1..=64; child killed on `wipe`/`switch`/`Exit` (`lib.rs:91-98`). `parse_hashrate` rejects non-finite/absurd values.
- No PIN by design; `has_pin` always false. No secrets in `tracing` output; e2e restore helper is `cfg(debug_assertions)` only.
- `amount.ts` bigint parsing/formatting correct, test covers the 0.29 trap; `payment-uri.ts` memo base64 + 255-byte cap + control-char rejection matches FFI `MAX_PAYMENT_MEMO_BYTES`.
- Deps: lockfile has `lit@3.3.3`, `vite@6.4.3`, `typescript@5.6.3`, `@tauri-apps/api@2.11.1` matching `package.json`; devtools not enabled in release (no `devtools` feature); no updater configured (so no updater key risk).

---

## 2. MOONSHINE — `/Users/adi/GitHub/moonshine`

### MUST-FIX before release

| # | Location | Issue | Fix |
|---|---|---|---|
| M1 | `src/wallet.rs:173-205` then `:208-212` | `Wallet::create` opens the DB, generates the mnemonic, **stores the secret key**, and only then checks `stderr().is_terminal()`. When stderr is not a TTY it returns Err — the wallet now exists (re-running says "already exists") and the seed was **never displayed and is unrecoverable**. | Move the TTY check to the top of `create()` (before `WalletDb::open`), or delete the DB files on refusal. |
| M2 | `src/config.rs:57` vs `:37-48`, `tor.rs:19-35`, README | `Config::default()` sets `use_tor: false`; `default_use_tor()` (=true) only applies to files that omit the key. Every fresh install writes `use_tor = false` to `config.toml` → **Tor off by default**, contradicting docs. Also `server_url` default is the dev loopback. | `use_tor: default_use_tor()` in `Default`; ship a real default server URL + pin or make first-run require `config --server-url`. |
| M3 | `src/main.rs:536-540` | `&m[..m.len().min(32)]` slices a user memo at byte 32 → **panic on non-ASCII memo** (char-boundary). Same class: `&to[..24]` at 516. | `m.chars().take(32).collect::<String>()`; same for `to`. |
| M4 | `src/main.rs:752` | `let token_id = *DARK_TOKEN_ID;` regardless of `--token`. Inputs are filtered to the requested token (721-732) but the output note is always DRK → custom-token sends build an invalid/unbalanced tx. | Reject `--token` ≠ DRK until supported, or parse the token id hex into `TokenId`. |

### SHOULD-FIX soon

| # | Location | Issue | Fix |
|---|---|---|---|
| M5 | `src/secret_wrap.rs:132-146` | Argon2id uses the **constant salt `PASS_DOMAIN`** (no per-wallet salt) → precomputation across wallets for user-chosen passphrases. | Store a random 16-byte salt in `wallet_meta` and pass it as the Argon2 salt. |
| M6 | `src/secret_wrap.rs:43-104` | Home-rolled blake3-XOR stream + 16-byte truncated MAC while `chacha20poly1305` is already a dependency. | Replace `wrap_secret/unwrap_secret` with XChaCha20-Poly1305 (keep MSK1 read path for migration). |
| M7 | `src/secret_wrap.rs:84-87` | `unwrap_secret` accepts any non-`MSK1` blob as plaintext forever (no migration cutoff). | Migrate plaintext rows on open and then reject un-wrapped rows. |
| M8 | `src/secret_wrap.rs:200-213`, `db.rs:39-58` | `.wrapkey` and `.pass` sit beside the DB (0600); the wrap key is also stored in `wallet_meta` wrapped under the same passphrase → the second layer adds nothing over SQLCipher. | Either drop `.wrapkey` and derive it from the passphrase, or document it as defence-in-depth only. |
| M9 | `src/main.rs:417, 436` | `amount_atomic + fee_atomic` and `input_total += value` are unchecked `u64` adds. | `checked_add` with an error. |
| M10 | `src/main.rs:634-640, 680` | `pallas::Base::decode(...).unwrap()`, `hex::decode(&tok_id).unwrap().try_into().unwrap()`, `copy_from_slice` on DB blobs → panics on a corrupted/legacy row (e.g. a `"DRK"` string token_id as in `pruning.rs` tests). | Return `Err` on decode failure / wrong length. |
| M11 | `src/main.rs:816-822, 865-870` | `mark_note_spent(...).unwrap_or(0)` swallows DB errors after broadcast; a failed mark yields only a warning and allows a double-spend attempt. | Propagate the error and print the affected nullifiers. |
| M12 | `src/client.rs:229-231, 307-309` | `Endpoint::timeout` only; no `connect_timeout`. A stalled remote TCP connect hangs until OS timeout. | Add `.connect_timeout(Duration::from_secs(30))`. |
| M13 | `src/sync.rs:281-282` | Comment says "Default: trial-decrypt … `--strict-omr` keeps UnifOMR-only" — inverted vs `main.rs:1098` (`strict_omr = !allow_trial && !force_trial`). | Fix the comment. |
| M14 | `.github/workflows/ci.yml:41-44, 78-81, 120-123, 161-164` | `darkfi-lightwalletd` is checked out with no `ref` → CI builds against floating master (non-reproducible). | Pin `ref:` to a SHA/tag like `DARKFI_PIN`. |
| M15 | `src/wallet.rs:517-529` | `delete` leaves `last-tx.hex` (`write_last_tx`) behind. | Add `last_tx_path(name)` to `extras`. |

### Verified OK
- `mnemonic.rs`: `DERIVE_CONTEXT = "nighthawk-drk-v1"` and derivation loop (`:59-84`) identical to `darkfi-mobile-ffi/src/mnemonic.rs:23-46`; PBKDF2 salt `"darkfi"`+2048 rounds and `"Seed version"` prefix check match; entropy sampling `% 2^242` from 248 random bits is uniform.
- `rand::rng()` (rand 0.9) is `ThreadRng` — ChaCha12 reseeded from OS entropy; suitable for nonces/keys/passphrases (`secret_wrap.rs:62,170,210`).
- Mnemonic never printed to stdout; import refuses non-TTY stdin (`main.rs:243-247`); `wallet export` prints only the detection key.
- Sync: strict default, `--force-trial`/`--allow-trial` opt-in, `pad_block_range` clamps end to tip (`sync.rs:1467`), reorg path `invalidate_above_height` with `reset_for_rescan` fallback (`:155-194`), OMR-truncation `covered_end` clamp guarantees forward progress (`:241-245`).
- `client.rs`: remote requires `https://` **and** a pin (fail-closed, 197-216); Tor dial fails closed (259-264); `PinnedVerifier` hashes the leaf DER.
- `amount.rs` uses `decode_base10` (no floats); `memo.rs` byte-length check before `as u8`.
- Files written 0600 (`write_mode_0600*`), `PRAGMA secure_delete`, SQLCipher `PRAGMA key` via `pragma_update`.
- Pins consistent: `ci.yml:13`, `docs/darkfi-pin.md:13`, `README.md:5,30,59` all `d3062798…`; `build.rs` proto path matches lightwalletd.

---

## 3. LIGHTWALLETD — `/Users/adi/GitHub/darkfi-lightwalletd`

### MUST-FIX before release

| # | Location | Issue | Fix |
|---|---|---|---|
| L1 | `src/cache.rs:520-523` | Long-term **directory attestation signing key** generated with `SecretKey::random(&mut Pcg32::new(u64))` — a non-cryptographic PRNG seeded from only **8 random bytes (64-bit key space)**. Violates the "keys from a CSPRNG" invariant; brute-forceable in principle. Persisted, so all existing deployments are affected. | `SecretKey::random(&mut rand_core::OsRng)` (or 32 OS-random bytes → `from_bytes` with retry); add a key-rotation note since `directory_attest_pubkey` changes. |
| L2 | `src/server.rs:180-185, 302-323` | `peer_ip` takes the **leftmost** `X-Forwarded-For` hop when the TCP peer is a trusted proxy. With nginx `$proxy_add_x_forwarded_for` (appends), a client sends its own `X-Forwarded-For: 1.2.3.4` and controls the IP used for **all rate limiters and the S12 SendTransaction→RegisterOmrClue peer bind**. `docs/deploy-hardening.md:19-37` recommends exactly this proxy setup. | Walk the list from the right, skipping entries matching `trusted_proxies`, and use the first non-trusted hop; document `X-Forwarded-For` must be *set* (not appended) at the edge. |

### SHOULD-FIX soon

| # | Location | Issue | Fix |
|---|---|---|---|
| L3 | `src/server.rs:1250-1256` then `1259-1282` | `GetUnifOmrDigest` acquires one of **2** FHE permits at the header, then keeps it while the client streams up to 160 MiB. Two slow-loris clients hold both permits for up to `request_timeout_s` (default 1800 s) → OMR unavailable for everyone. | Wrap each `stream.next()` in a per-chunk `tokio::time::timeout` (e.g. 30 s) and a total upload deadline; or buffer to a spooled temp file before taking the permit. |
| L4 | `src/server.rs:452-467, 507-540, 882-886, 1067-1070` | `GetCompactBlocksAtHeights` (512 sled reads materialized), `GetChainTip`, `GetTreeState`, `GetLightInfo` have **no rate limit**; `GetChainTip`/`GetLightInfo` each proxy 1–2 darkfid RPCs → amplification against darkfid. | Add `check_rpc_rate_limit`; cache `block_target`/`difficulty` for ~poll_interval. |
| L5 | `src/main.rs:328-332` | Shutdown only on `ctrl_c`; **SIGTERM** (systemd `stop`, Docker) kills the process without `cache.flush()`. | Use `tokio::signal::unix::signal(SignalKind::terminate())` in a `select!` with `ctrl_c`. |
| L6 | `src/server.rs:209, 324-341` + `remember_send_peer` | Raw client IPs kept in memory for 24 h keyed by tx hash (`recent_send_peers`) — IP↔transaction linkage on the server. | Store `blake3(pepper ‖ ip)` with a per-process random pepper; compare hashes in `send_peer_matches`. |
| L7 | `src/cache.rs:304, 375, 534-558` | `prune_expired_omr_clue_hints` does a **full tree scan** on every `store_omr_clue_hint` and `has_omr_clue_hint` (called per SendTransaction / RegisterOmrClue). | Prune on a timer in the poller task; make the per-request path O(1). |
| L8 | `src/server.rs:1454-1471`, `pir_server.rs:332-340` | `FetchPirBatch` encodes up to 10 000 blocks (≤64 MiB) and `limb_column` calls `bytes_to_limbs(p)` (full conversion) per block just to pick one limb — all on the async runtime thread before `spawn_blocking`. | Compute only limb `limb_index` directly from bytes; move encoding + `limb_column` inside the `spawn_blocking`. |
| L9 | `src/rpc_client.rs:264-283` | Plain TCP only; URL scheme ignored. `darkfid_endpoint = "tcp+tls://…"` or a remote host silently gets cleartext JSON-RPC with no error. | In `Config::finalize` reject schemes other than `tcp://` and warn/refuse non-loopback darkfid hosts. |
| L10 | `src/chain_poller.rs:227` | `smol::Timer::after` inside a tokio task spins up a separate async-io reactor thread. | `tokio::time::sleep`. |
| L11 | `src/server.rs:1198, 1377, 1480, 1571` | `Status::internal(format!("… {e}"))` echoes sled/FHE/join error text to clients. | Log with `tracing::error!`, return a fixed message (as `cache_status` does). |
| L12 | `src/server.rs:1575-1593` | Non-`fhe-omr` build: decoy `clue_public_key` is 32 bytes while real registrations are ≥16 KiB → registration bit leaks via size. Default feature set is `fhe-omr`, so low impact. | Pad decoy to `clue_public_key_wire_len()` or refuse `GetCluePublicKey` without the feature. |
| L13 | `src/rpc_client.rs:307-309` | `read_line` into an unbounded `String` from darkfid. Trusted peer, but a huge block response is fully buffered. | `.take(limit)` reader or a size cap. |

### Verified OK
- `unifomr.rs:986,1005` `thread::sleep` is only reached via `encode_messages_padded` inside `spawn_blocking` (`server.rs:1349-1374`); `evaluate_padded` has no non-test callers. Not blocking runtime workers.
- Client-byte parsers (`deserialize_clue :395-431`, `deserialize_public_key :516-542`, `parse_detection_key :773-812`, `omr_envelope.rs:15-48`, `clue_ownership.rs:43-52`) length-check before every slice; the `try_into().unwrap()`s are on fixed-size sub-slices. `validate_unifomr_clue` enforces n/q bounds + checksum.
- DoS caps: `MAX_BLOCKS_PER_REQUEST`=10 000 via `height_span` (u64, `u32::MAX` safe), `MAX_SPARSE_HEIGHTS`=512, ≤16 detection keys, 160 MiB per-key and total, `MAX_PIR_STRIPES`=8, 4 MiB per PIR CT, 64 MiB PIR window, `max_tx_bytes` after envelope strip (`server.rs:687-693`), `omr_metadata_enc` ≤4096, clue-PK/proof ≤64 KiB, `key_version` plausibility window (`cache.rs:406-415`), monotonic key rotation (420-433).
- `GetCluePublicKey`: always `found=true`, same-size padded proof (`OWNERSHIP_PROOF_WIRE_LEN`), same signing key for real/decoy, fixed 250 ms deadline; pepper + attest secret persisted (`cache.rs:486-499, 507-525`).
- `GetUnifOmrDigest` reports `complete=false` on partial cache or message-cap truncation (`server.rs:1320-1334, 1355-1358, 1381`); network byte bound in `encode_messages` (`unifomr.rs:870-874`).
- Streaming `spawn_compact_range` reads one block at a time, aborts on holes/mixed forks; `GetCheckpointSnapshot`/`GetTreeState` are tip-only; `SubscribeBlocks` drops slow clients after 30 s.
- Reorg/IBD: `classify_tips` covers regression, hash mismatch, backend-catch-up hold; `fetch_range` checks `prev_hash` continuity; `rewind_to_common_ancestor` bounded at 10 000; genesis backfill. `rpc_client` has connect/write/read timeouts and DNS pinning; darkfid JSON is parsed fallibly (no unwraps).
- Rate limiter fails closed on poisoned mutex; connection cap via semaphore-gated accept; `concurrency_limit_per_connection`; TLS mandatory for non-loopback bind (`main.rs:261-299`).
- No peer IP logging in server/poller (`debug!` connection counters only). `CACHE_FORMAT_VERSION` checked at open. `scripts/darkfi.rev` = `d3062798…` matches moonshine's pin (uncommitted in both trees).