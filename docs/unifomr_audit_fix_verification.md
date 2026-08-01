# UnifOMR audit fix — verification checklist results

Date: 2026-07-12

## Automated (ran)

| Check | Result |
|-------|--------|
| lightwalletd `omr_envelope` (O2 only) | PASS (2 tests) |
| lightwalletd `unifomr` e2e match/non-match | PASS (5 tests) |
| lightwalletd `pir_server` | PASS (2 tests) |
| lightwalletd `omr_clue` hint/output index tests | PASS (filtered cache tests) |
| moonshine `cargo check` | PASS |
| mobile-ffi `transactions` (large clue, registered pk decrypt) | PASS |
| mobile-ffi `omr_envelope` / `unifomr` / `memo` / `batch_pir` | PASS |
| Android mobile-ffi `cargo check --lib` | PASS |

## Checklist mapping

1. **Receiver registered; moonshine UnifOMR send** — crypto path verified (`test_registered_clue_matches_receiver_detection_sk` + moonshine `GetCluePublicKey`). **Needs live LWD e2e.**
2. **Receiver registered; mobile send after fix** — send now calls `GetCluePublicKey` + `build_omr_clue_from_pk`; `O2` envelope holds full clue. **Needs live e2e.**
3. **Receiver not registered** — decoy directory + supplemental trial decrypt. **Needs live e2e for discovery.**
4. **Sender history after broadcast** — unchanged `mark_tx_spend` path; **runtime verify.**
5. **Empty OMR short window** — mobile: `scan_range > 0` triggers trial; moonshine: empty → full-window trial. **Code review PASS; live soak recommended.**
6. **Gaps ≤100** — threshold lowered to **> 10**. **Code review PASS.**
7. **Android reorg invalidate txs** — ported `invalidate_transactions_above`. **Unit/DB verify on device.**
8. **Clue on payment output 0** — `omr_clue_output_index: 0` on Send/Register. **Server stores Some(index).**
9. **No DEMO clue in production send** — `build_omr_clue` gated `#[cfg(test)]`.

## Still requires live network / device

- Full Android↔iOS↔moonshine matrix on standalone `darkfi-lightwalletd`
- Duplicate-note soak after gap trial
- Background/foreground sync
- Nested LWD not used in release configs
