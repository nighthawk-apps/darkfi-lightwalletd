/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * Batch PIR over BFV for UnifOMR Round 2 (ePrint 2026/910).
 * Re-exports shared primitives from `blackhawk-unifomr::batch_pir` and adds
 * O(1)-per-height `payload_limb` extraction for server PIR windows.
 */

#![cfg(feature = "fhe-omr")]

pub use blackhawk_unifomr::batch_pir::{
    assemble_payloads, bytes_to_limbs, decode_length_prefixed_limbs, derive_pir_seed,
    limbs_to_bytes, padded_limb_count, pir_payload_limb_count, sealpir_stripe_count,
    BatchPirClient, BatchPirServer, MAX_PIR_LIMBS, MAX_PIR_PAYLOAD_BYTES, MAX_PIR_STRIPES,
    PIR_LIMB_BYTES, UNIFOMR_PIR_DOMAIN,
};

fn chunk_to_limb(chunk: &[u8]) -> u64 {
    let mut buf = [0u8; PIR_LIMB_BYTES];
    buf[..chunk.len()].copy_from_slice(chunk);
    u16::from_le_bytes(buf) as u64
}

/// Limb `limb_index` of `bytes_to_limbs(data)` without materializing all limbs.
///
/// Oversized payloads report a length of `MAX_PIR_PAYLOAD_BYTES + 1` so limb 0
/// stays below `t` (clients reject any length above the cap identically).
pub fn payload_limb(data: &[u8], limb_index: usize) -> u64 {
    if limb_index == 0 {
        return data.len().min(MAX_PIR_PAYLOAD_BYTES + 1) as u64;
    }
    let off = (limb_index - 1).saturating_mul(PIR_LIMB_BYTES);
    match data.get(off..) {
        Some(rest) if !rest.is_empty() => chunk_to_limb(&rest[..rest.len().min(PIR_LIMB_BYTES)]),
        _ => 0,
    }
}

/// Build one PIR db column: limb `limb_index` of each height's payload (0 if missing/short).
pub fn limb_column(payloads: &[Vec<u8>], limb_index: usize) -> Vec<u64> {
    payloads
        .iter()
        .map(|p| payload_limb(p, limb_index))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::Ciphertext;
    use fhe_traits::{DeserializeParametrized, Serialize};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn padded_limb_count_hides_exact_size() {
        assert_eq!(padded_limb_count(1), 8);
        assert_eq!(padded_limb_count(9), 16);
        assert_eq!(padded_limb_count(MAX_PIR_LIMBS), MAX_PIR_LIMBS);
    }

    #[test]
    fn test_batch_pir_single_select() {
        let client = BatchPirClient::from_seed([9u8; 32]).unwrap();
        let server = BatchPirServer::with_unifomr_params().unwrap();
        let mut db = vec![0u64; 100];
        for (i, slot) in db.iter_mut().enumerate() {
            *slot = 1000 + i as u64;
        }
        let qs = client.generate_sealpir_queries(&[42], 100).unwrap();
        assert_eq!(qs.len(), 1);
        let resp = server.evaluate_sealpir_stripes(&qs, &db, 100).unwrap();
        let slots = client.decrypt_sealpir_stripes(&resp, 100).unwrap();
        assert_eq!(slots[42], 1042);
        assert_eq!(slots[0], 0);
    }

    #[test]
    fn test_sealpir_cross_stripe() {
        let client = BatchPirClient::from_seed([3u8; 32]).unwrap();
        let server = BatchPirServer::with_unifomr_params().unwrap();
        let degree = client.params.degree();
        let window = degree + 50;
        let mut db = vec![0u64; window];
        for (i, slot) in db.iter_mut().enumerate() {
            *slot = 7_000 + i as u64;
        }
        let target = degree + 17;
        let qs = client.generate_sealpir_queries(&[target], window).unwrap();
        assert_eq!(qs.len(), 2);
        let resp = server.evaluate_sealpir_stripes(&qs, &db, window).unwrap();
        let slots = client.decrypt_sealpir_stripes(&resp, window).unwrap();
        assert_eq!(slots[target], 7_000 + target as u64);
        assert_eq!(slots[0], 0);
    }

    #[test]
    fn test_limb_roundtrip() {
        let data = b"hello compact block payload";
        let limbs = bytes_to_limbs(data);
        assert_eq!(limbs[0], data.len() as u64);
        let back = decode_length_prefixed_limbs(&limbs);
        assert_eq!(back, data);
    }

    #[test]
    fn test_limb_roundtrip_trailing_zeros() {
        let mut data = b"compact".to_vec();
        data.extend_from_slice(&[0u8; 5]);
        let limbs = bytes_to_limbs(&data);
        let cols: Vec<Vec<u64>> = (0..limbs.len()).map(|i| vec![limbs[i]]).collect();
        let got = assemble_payloads(&[0], &cols);
        assert_eq!(got[0], data);
    }

    #[test]
    fn test_limb_format_constants() {
        assert_eq!(MAX_PIR_PAYLOAD_BYTES, 65_534);
        assert_eq!(pir_payload_limb_count(0), None);
        assert_eq!(pir_payload_limb_count(1), Some(2));
        assert_eq!(pir_payload_limb_count(3), Some(3));
        assert_eq!(
            pir_payload_limb_count(MAX_PIR_PAYLOAD_BYTES as u64),
            Some(MAX_PIR_LIMBS)
        );
        assert_eq!(
            pir_payload_limb_count(MAX_PIR_PAYLOAD_BYTES as u64 + 1),
            None
        );
        assert_eq!(bytes_to_limbs(&[0x34, 0x12, 0xFF]), vec![3, 0x1234, 0x00FF]);
    }

    #[test]
    fn test_limbs_below_plaintext_modulus() {
        use rand::RngCore;
        let t = crate::unifomr::pir_bfv_params().unwrap().plaintext();
        let mut data = vec![0u8; MAX_PIR_PAYLOAD_BYTES + 128];
        StdRng::seed_from_u64(0x8C1B).fill_bytes(&mut data);
        data[..64].fill(0xFF);
        let limbs = bytes_to_limbs(&data);
        assert_eq!(limbs.len(), 1 + data.len().div_ceil(PIR_LIMB_BYTES));
        for (i, &limb) in limbs.iter().enumerate() {
            assert!(limb < t, "limb {i} = {limb} >= t = {t}");
        }
        assert_eq!(payload_limb(&data, 0), MAX_PIR_PAYLOAD_BYTES as u64 + 1);
        assert_eq!(payload_limb(&data, 1), limbs[1]);

        let payloads = vec![
            data[..MAX_PIR_PAYLOAD_BYTES].to_vec(),
            data[..1001].to_vec(),
            Vec::new(),
        ];
        let expected: Vec<Vec<u64>> = payloads.iter().map(|p| bytes_to_limbs(p)).collect();
        for i in [0usize, 1, 500, 1024, MAX_PIR_LIMBS - 1, MAX_PIR_LIMBS] {
            let col = limb_column(&payloads, i);
            for (p, exp) in expected.iter().enumerate() {
                assert_eq!(
                    col[p],
                    exp.get(i).copied().unwrap_or(0),
                    "payload {p} limb {i}"
                );
            }
            assert!(col.iter().all(|&v| v < t));
        }
        let big = vec![0xFFu8; 2 * 1_032_193];
        assert_eq!(payload_limb(&big, 0), MAX_PIR_PAYLOAD_BYTES as u64 + 1);
    }

    #[test]
    fn test_pir_bfv_roundtrip_compact_block() {
        use prost::Message;
        let output = crate::proto::CompactOutput {
            coin: vec![0x11; 32],
            encrypted_note: vec![0xFF; 2800],
            value_commit: vec![0xFE; 33],
            token_commit: vec![0x7F; 32],
            omr_clue: Vec::new(),
            omr_metadata_enc: vec![0xFF; 64],
            func_code: 0,
        };
        let block = |height: u32| crate::proto::CompactBlock {
            height,
            hash: vec![height as u8; 32],
            prev_hash: vec![0xFF; 32],
            timestamp: 1_780_000_000 + height as u64,
            txs: vec![crate::proto::CompactTx {
                tx_hash: vec![0xEE; 32],
                outputs: vec![output.clone()],
                nullifiers: vec![vec![0xFF; 32]],
                fee: u64::MAX,
            }],
        };
        let payloads: Vec<Vec<u8>> = (0..3).map(|h| block(100 + h).encode_to_vec()).collect();
        let target = 1usize;
        let window = payloads.len();
        let limbs = bytes_to_limbs(&payloads[target]);
        assert!((3000..3300).contains(&payloads[target].len()));
        assert!(
            limbs.contains(&0xFFFF),
            "payload must exercise 0xFFFF limbs"
        );

        let client = BatchPirClient::from_seed([0x5Cu8; 32]).unwrap();
        let server = BatchPirServer::with_unifomr_params().unwrap();
        let queries = client.generate_sealpir_queries(&[target], window).unwrap();
        let parsed = server.parse_queries(&queries).unwrap();
        let needed = pir_payload_limb_count(limbs[0]).unwrap();
        let limb_dbs: Vec<Vec<u64>> = (0..padded_limb_count(needed))
            .map(|limb_index| limb_column(&payloads, limb_index))
            .collect();
        let resps = server
            .evaluate_parsed_limb_range(&parsed, &limb_dbs, window)
            .unwrap();
        let cols: Vec<Vec<u64>> = resps
            .iter()
            .map(|resp| client.decrypt_sealpir_stripes(resp, window).unwrap())
            .collect();
        let got = assemble_payloads(&[target], &cols);
        assert_eq!(got[0], payloads[target]);
        let decoded = crate::proto::CompactBlock::decode(got[0].as_slice()).unwrap();
        assert_eq!(decoded.height, 101);
    }

    #[test]
    fn test_pir_rejects_non_fresh_query() {
        let client = BatchPirClient::from_seed([0x71u8; 32]).unwrap();
        let server = BatchPirServer::with_unifomr_params().unwrap();
        let db = vec![1u64; 4];
        let q = client.generate_query(0, 4).unwrap();
        assert!(server.evaluate_limb_bytes(&q, &db).is_ok());

        let mut ct = Ciphertext::from_bytes(&q, &client.params).unwrap();
        let squared = &ct * &ct;
        assert_eq!(squared.len(), 3);
        assert!(server
            .evaluate_limb_bytes(&squared.to_bytes(), &db)
            .is_err());

        ct.switch_to_level(1).unwrap();
        let err = server.evaluate_limb_bytes(&ct.to_bytes(), &db).unwrap_err();
        assert!(err.contains("level"), "{err}");
    }
}
