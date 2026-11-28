/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * UnifOMR — paper-faithful Oblivious Message Retrieval (ePrint 2026/910),
 * shared via `blackhawk-unifomr` with `clue_ownership` and lightwalletd
 * `NoteForDetection` helpers layered on top.
 */

#![cfg(feature = "fhe-omr")]

pub use blackhawk_unifomr::*;

// Re-export ownership helpers so callers can use `unifomr::sign_clue_pk_ownership`.
pub use crate::clue_ownership::{
    clue_pk_ownership_message, decoy_ownership_proof, directory_attest_message,
    pad_ownership_proof, sign_clue_pk_ownership, sign_directory_attestation, unpad_ownership_proof,
    verify_clue_pk_ownership, verify_directory_attestation, CLUE_PK_OWNERSHIP_DOMAIN,
    DIRECTORY_ATTEST_DOMAIN, OWNERSHIP_PROOF_WIRE_LEN,
};

/// Convert cache notes into UnifOMR clue notes.
pub fn block_notes_from_detection(
    block_notes: &[(u32, Vec<crate::omr_detector::NoteForDetection>)],
) -> Vec<(u32, Vec<ClueNote>)> {
    block_notes
        .iter()
        .map(|(h, notes)| {
            (
                *h,
                notes
                    .iter()
                    .map(|n| ClueNote {
                        omr_clue: n.omr_clue.clone(),
                    })
                    .collect(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::time::Instant;

    #[test]
    fn test_rlwe_encrypt_zeros_decrypts_small_error() {
        let mut r = StdRng::seed_from_u64(7);
        let sk = RlweSecretKey::random(&mut r);
        let pk = RlwePublicKey::from_secret(&sk, &mut r);
        let ct = pk.encrypt_zeros(&mut r);
        let err = sk.decrypt_error(&ct);
        let max_abs = err.iter().map(|e| e.unsigned_abs()).max().unwrap();
        assert!(
            max_abs < R_PRIME,
            "pertinent clue error too large: {max_abs} (R_PRIME={R_PRIME})"
        );
    }

    #[test]
    fn test_clue_wire_roundtrip() {
        let mut r = StdRng::seed_from_u64(9);
        let sk = RlweSecretKey::random(&mut r);
        let pk = RlwePublicKey::from_secret(&sk, &mut r);
        let ct = pk.encrypt_zeros(&mut r);
        let bytes = serialize_clue(&ct);
        validate_unifomr_clue(&bytes).unwrap();
        let ct2 = deserialize_clue(&bytes).unwrap();
        assert_eq!(ct.a, ct2.a);
        assert_eq!(ct.b, ct2.b);
    }

    #[test]
    fn test_poison_clue_rejected() {
        let mut bad = vec![0u8; 100];
        bad[0] = CLUE_VERSION;
        bad[1] = SCHEME_UNIFOMR;
        assert!(validate_unifomr_clue(&bad).is_err());
    }

    #[test]
    fn test_unifomr_e2e_partial_decrypt_match() {
        let wallet = [0x42u8; 32];
        let client = UnifOmrClient::from_wallet(&wallet, 0x01).unwrap();
        let det_key = client.build_detection_key(0x01).unwrap();
        let (_, pk) = clue_keypair_from_wallet(&wallet, 0x01).unwrap();
        let mut r = StdRng::seed_from_u64(100);
        let mut r_other = StdRng::seed_from_u64(200);
        let (_, pk_other) = clue_keypair_from_wallet(&[0x99u8; 32], 0x01).unwrap();
        let messages: Vec<RlweCiphertext> = vec![
            pk_other.encrypt_zeros(&mut r_other),
            pk.encrypt_zeros(&mut r),
            pk_other.encrypt_zeros(&mut r_other),
        ];
        let slot_heights = vec![10u32, 20u32, 30u32];
        let detector = UnifOmrDetector::new(0x01).unwrap();
        let digest = detector.encode_messages(&det_key, &messages).unwrap();
        let slots = client.decrypt_digest_slots(&digest).unwrap();
        let matches = UnifOmrClient::range_check_matches(&slots, &slot_heights).unwrap();
        assert_eq!(matches, vec![20]);
    }

    #[test]
    fn decoy_key_version_matches_wallet_constant() {
        assert_eq!(decoy_key_version(), 1);
    }

    /// Measure release-mode UnifOMR / PIR / Merkle-append timings for hosting sizing.
    #[test]
    #[ignore = "measurement run; results cited in README Infrastructure sizing"]
    fn measure_hosting_timings() {
        use darkfi_sdk::crypto::{MerkleNode, MerkleTree};
        use darkfi_sdk::pasta::pallas;

        let wallet = [0x42u8; 32];
        let t0 = Instant::now();
        let client = UnifOmrClient::from_wallet(&wallet, 0x01).unwrap();
        let from_wallet_ms = t0.elapsed().as_secs_f64() * 1e3;

        let t1 = Instant::now();
        let det_key = client.build_detection_key(0x01).unwrap();
        let build_det_ms = t1.elapsed().as_secs_f64() * 1e3;

        let detector = UnifOmrDetector::new(0x01).unwrap();
        let t2 = Instant::now();
        let (_net, parsed) = parse_detection_key(&det_key, &detector.params).unwrap();
        let parse_det_ms = t2.elapsed().as_secs_f64() * 1e3;

        let (_, pk) = clue_keypair_from_wallet(&wallet, 0x01).unwrap();
        let mut r = StdRng::seed_from_u64(0x1234);
        let sample_ct = pk.encrypt_zeros(&mut r);
        let degree = detector.params.degree();
        let messages: Vec<RlweCiphertext> = vec![sample_ct; degree];

        let t3a = Instant::now();
        let prepared = detector.prepare_window(&messages).unwrap();
        let prepare_ms = t3a.elapsed().as_secs_f64() * 1e3;

        let t3b = Instant::now();
        let digest = detector.evaluate_prepared(&parsed, &prepared).unwrap();
        let eval_prepared_ms = t3b.elapsed().as_secs_f64() * 1e3;

        let t4 = Instant::now();
        let slots = client.decrypt_digest_slots(&digest).unwrap();
        let decrypt_ms = t4.elapsed().as_secs_f64() * 1e3;

        let pir_client = crate::pir_server::BatchPirClient::from_seed([7u8; 32]).unwrap();
        let pir_server = crate::pir_server::BatchPirServer::with_unifomr_params().unwrap();
        let q1 = pir_client.generate_sealpir_queries(&[42], degree).unwrap();
        let db1 = vec![0x1234u64; degree];
        let parsed_q1 = pir_server.parse_queries(&q1).unwrap();
        let limb_dbs1 = vec![db1.clone(); 16];
        let t5 = Instant::now();
        let _ = pir_server
            .evaluate_parsed_limb_range(&parsed_q1, &limb_dbs1, degree)
            .unwrap();
        let pir_16limbs_1stripe_ms = t5.elapsed().as_secs_f64() * 1e3;
        let pir_1stripe_ms = pir_16limbs_1stripe_ms / 16.0;

        let q2 = pir_client
            .generate_sealpir_queries(&[42], degree * 2)
            .unwrap();
        let db2 = vec![0x1234u64; degree * 2];
        let t6 = Instant::now();
        for _ in 0..10 {
            let _ = pir_server
                .evaluate_sealpir_stripes(&q2, &db2, degree * 2)
                .unwrap();
        }
        let pir_2stripe_ms = t6.elapsed().as_secs_f64() * 1e3 / 10.0;

        let mut tree = MerkleTree::new(100);
        tree.append(MerkleNode::from(pallas::Base::from(0u64)));
        let _ = tree.mark();
        let t7 = Instant::now();
        for i in 1u64..=1000 {
            tree.append(MerkleNode::from(pallas::Base::from(i)));
        }
        let merkle_1000_ms = t7.elapsed().as_secs_f64() * 1e3;
        let tree_bytes = darkfi_serial::serialize(&tree).len();

        println!("MEASURE_DET_KEY_BYTES={}", det_key.len());
        println!("MEASURE_DET_KEY_PARSED_BYTES={}", parsed.approx_bytes());
        println!("MEASURE_DIGEST_1CHUNK_BYTES={}", digest.len());
        println!("MEASURE_SLOTS={}", slots.len());
        println!("MEASURE_FROM_WALLET_MS={from_wallet_ms:.2}");
        println!("MEASURE_BUILD_DET_KEY_MS={build_det_ms:.2}");
        println!("MEASURE_PARSE_DET_KEY_MS={parse_det_ms:.2}");
        println!("MEASURE_PREPARE_1CHUNK_MS={prepare_ms:.2}");
        println!("MEASURE_EVAL_PREPARED_1CHUNK_MS={eval_prepared_ms:.2}");
        println!("MEASURE_DECRYPT_1CHUNK_MS={decrypt_ms:.2}");
        println!("MEASURE_PIR_1STRIPE_LIMB_MS={pir_1stripe_ms:.2}");
        println!("MEASURE_PIR_16LIMBS_1STRIPE_MS={pir_16limbs_1stripe_ms:.2}");
        println!("MEASURE_PIR_2STRIPE_LIMB_MS={pir_2stripe_ms:.2}");
        println!("MEASURE_PIR_QUERY_CT_BYTES={}", q1[0].len());
        println!("MEASURE_MERKLE_1000_APPEND_MS={merkle_1000_ms:.2}");
        println!("MEASURE_MERKLE_TREE_SERIAL_BYTES={tree_bytes}");
    }
}
