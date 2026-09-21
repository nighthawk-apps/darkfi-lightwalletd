# Fable 5.1 security audit — darkfi-lightwalletd

**Audit date:** 2026-09-20  
**Model:** Claude Fable 5.1  
**Review date:** 2026-09-21  
**Shipped revision:** `2a935b9` (v0.2.2)  

Full auditor transcripts (unchanged):

- [`fable-5.1-audit-desktop-moonshine-lwd-source.md`](fable-5.1-audit-desktop-moonshine-lwd-source.md) — subagent `7747fe26`
- [`fable-5.1-audit-unifomr-explore-source.md`](fable-5.1-audit-unifomr-explore-source.md) — subagent `0659fd0c`
- [`fable-5.1-audit-unifomr-sync-source.md`](fable-5.1-audit-unifomr-sync-source.md) — subagent `dbde00de`

---

## MUST-FIX status (this repo)

| ID | Finding | Status | Evidence |
|----|---------|--------|----------|
| L1 | Directory attest key from Pcg32, not CSPRNG | **FIXED** | `cache.rs` persists `unifomr_dir_attest_sk_v2` from OsRng |
| L2 | X-Forwarded-For took leftmost hop | **FIXED** | `server.rs` `client_ip_from_forwarded` walks RTL; `trusted_proxies` |
| L-PIR | PIR limbs hit OMR rate limit (30/min) | **FIXED** | Separate `pir_rate_limiter` at 600/min |
| L-TIP | GetBlockRange no tip clamp | **FIXED** | `get_block_range` clamps `end = end.min(tip)` |
| L-SIG | SIGTERM without graceful path | **FIXED** | `main.rs` handles SIGTERM + Ctrl-C |
| Doc R′ | Checklist claimed interim `R_PRIME=32768` | **FIXED** | `verification-checklist.md` / `unifomr_mvp_limits.md` say `r′=149` |
| Doc key_version | Docs said u32 LE | **FIXED** | `unifomr_mvp_limits.md` documents `key_version (u64 LE)` |
| Funded e2e | Live UnifOMR matrix checklist | **PENDING** | Process gate — see `verification-checklist.md` |

## SHOULD-FIX (deferred)

FHE permit held during large body upload; unlimited some RPCs; raw IPs in `recent_send_peers`; PIR on async worker; cleartext darkfid scheme ignore; decoy size leak; unbounded `read_line` from darkfid — see source audit § L3–L13.

## Deploy note

Mac Studio (2026-09-20): launchd `org.darkfi.lightwalletd` runs 0.2.2; ngrok `epidermis-sandbox-marshland.ngrok-free.dev` → `127.0.0.1:9067` unchanged.
