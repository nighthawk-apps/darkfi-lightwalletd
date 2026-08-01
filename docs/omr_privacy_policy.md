# OMR Privacy Policy

UnifOMR-only (`scheme=0x05`).

## Session unlinkability

- UnifOMR detection keys are fresh BFV ciphertexts each request; ciphertext
  bytes differ even for the same wallet.
- Clue-directory lookups always return `found=true` with fixed-length decoys
  and a timing pad so registration status does not leak.

## Timing / size padding

- Block range requests are padded to power-of-2 buckets (`pad_block_range`).
- UnifOMR digest evaluation uses a minimum processing delay so match count
  does not leak via latency.
- PIR stripe responses are length-prefixed.

## Fallback policy

1. Attempt UnifOMR via `GetUnifOmrDigest` + `FetchPirBatch`.
2. On OMR miss / failure threshold → trial decrypt compact blocks from
   lightwalletd (not darkfid). This covers decoy-directory recipients.
3. Direct `darkfid.scan_blocks` is disabled on the mobile production path.

## At-rest notes

- Wallet secrets and seed material remain in the platform secure store /
  OS keychain; never logged.
