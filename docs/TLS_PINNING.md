# Lightwalletd TLS certificate pinning (S8)

Remote `https://` / `tcp+tls://` lightwalletd endpoints **require** a TLS pin.
Without it, Nighthawk clients **fail closed** at bootstrap / connect.

## What to pin

SHA-256 of the server's **leaf certificate DER** (not SPKI, not the public key).

```bash
# Preferred: provision + print pin in one step
./scripts/generate_tls_cert.sh self-signed --domain lw.local
# → writes scripts/certs/LIGHTWALLET_TLS_PIN_SHA256.txt + client-pins.env

./scripts/generate_tls_cert.sh letsencrypt \
  --domain lw.example.com --email ops@example.com
# optional: --webroot /var/www/html  (instead of standalone :80)

# Pin only (existing PEM or live host)
./scripts/print_tls_pin.sh --cert /path/to/server.crt
./scripts/print_tls_pin.sh --host lw.example.com:9067
```

Manual equivalent:

```bash
openssl x509 -in lightwalletd.crt -outform DER | openssl dgst -sha256 -hex
# → use the 64 hex chars (lowercase) as LIGHTWALLET_TLS_PIN_SHA256
```

## lightwalletd (server)

Cleartext is only allowed on loopback. For public binds set both:

```toml
grpc_listen = "0.0.0.0:9067"
tls_cert_path = "/path/to/certs/server.crt"
tls_key_path = "/path/to/certs/server.key"
```

A ready-to-merge snippet is written next to the certs as
`scripts/certs/lightwalletd-tls.snippet.toml`.

## Android

```bash
./gradlew :app:assembleDarkfimainnetRelease -PLIGHTWALLET_TLS_PIN_SHA256=<64hex>
```

Or `gradle.properties`:

```properties
LIGHTWALLET_TLS_PIN_SHA256=<64hex>
```

Runtime override (debug / settings): SharedPreferences
`darkfi_lightwallet_security` → key `lightwallet_tls_pin_sha256`.

## iOS

```
LIGHTWALLET_TLS_PIN_SHA256 = <64hex>
```

Info.plist key `LightwalletTlsPinSha256` expands `$(LIGHTWALLET_TLS_PIN_SHA256)`.

Runtime override: UserDefaults key `lightwallet_tls_pin_sha256`.

## Desktop

Settings → **LWD TLS pin**, or `prefs.json` field `lightwalletTlsPinSha256`
(64 hex). Bootstrap fails closed for remote HTTPS without a valid 32-byte pin.

## Loopback / localnet

Leave the pin empty and use `http://127.0.0.1:9067` (cleartext loopback only).

## Mac Studio e2e note

1. Generate certs on the Studio (`self-signed` for LAN, `letsencrypt` for public DNS).
2. Point `lightwalletd.toml` at `server.crt` / `server.key`.
3. Distribute the **same** `LIGHTWALLET_TLS_PIN_SHA256` to moonshine / Android / iOS / desktop.
4. Restart LWD, then run funded UnifOMR matrix tests.
