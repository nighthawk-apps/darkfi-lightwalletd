# Deploy Hardening for Public darkfi-lightwalletd

Application limits (connection cap, SendTransaction size, rate limits) are configured in TOML — see `lightwalletd.toml.example`. This document covers **ops-layer** defenses in front of a public bind.

## Recommended topology

```
Internet → DDoS scrubbing → HAProxy (L4 conn limits)
         → nginx (TLS 1.3 + gRPC rate limits)
         → darkfi-lightwalletd on 127.0.0.1:9068
         → darkfid on 127.0.0.1:18345
```

## HAProxy (L4)

- Cap new connections per IP (e.g. 20 / 10s) and concurrent per IP (e.g. 50).
- Enable SYN cookies; set client/server timeouts ≤ 30s for abandoned streams.

## nginx (L7 TLS termination)

- `ssl_protocols TLSv1.3;`
- `limit_conn` / `limit_req` per `$binary_remote_addr`
- `client_max_body_size 160m;` (Param2 UnifOMR det-keys are ~120 MiB; the default 4m will reject `GetUnifOmrDigest`)
- `grpc_read_timeout` / `grpc_send_timeout` ≤ 300s (must match `request_timeout_s`; Param2 FHE + Tor can exceed 60s)
- Proxy to `grpc://127.0.0.1:9068`

## Kernel / iptables

- `net.ipv4.tcp_syncookies=1`
- Rate-limit NEW TCP to the public gRPC port
- `rp_filter=1` against spoofing

## Application checklist

1. `grpc_listen = "127.0.0.1:9068"` behind the reverse proxy (or public bind **with** `tls_cert_path` + `tls_key_path`).
2. Set `[limits]` / rate-limit keys from `lightwalletd.toml.example`.
3. Point `darkfid_endpoint` at loopback; prefer IP pin at startup when a hostname is used.
4. Never run production with `omr_rate_limit_per_min = 0` on a public listen.
5. Publish the leaf-cert SHA-256 pin to wallet release builds ([TLS_PINNING.md](TLS_PINNING.md)).
6. Set `request_timeout_s = 300` (or higher) and ensure nginx/HAProxy `grpc_read_timeout` / `grpc_send_timeout` are ≥ 300s — Param2 det-keys are ~120 MiB and FHE processing over Tor needs the headroom.
