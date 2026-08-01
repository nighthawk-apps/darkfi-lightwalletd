/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! UnifOMR smoke tests (clue validation + detector roundtrip).
//!
//! Full gRPC matrix lives in `e2e_unifomr_matrix`.

#![cfg(feature = "fhe-omr")]

use darkfi_lightwalletd::unifomr::{
    clue_keypair_from_wallet, serialize_clue, validate_unifomr_clue, ClueNote, UnifOmrClient,
    UnifOmrDetector, SCHEME_UNIFOMR,
};
use rand::rng;

#[test]
fn validate_unifomr_clue_rejects_empty() {
    assert!(validate_unifomr_clue(&[]).is_err());
}

#[test]
fn validate_unifomr_clue_roundtrip_with_client() {
    let wallet = [0x11u8; 32];
    let (_, pk) = clue_keypair_from_wallet(&wallet, 0x01).expect("keypair");
    let clue = serialize_clue(&pk.encrypt_zeros(&mut rng()));
    validate_unifomr_clue(&clue).expect("valid UnifOMR clue must pass");
}

#[test]
fn unifomr_detector_scheme_and_digest_roundtrip() {
    assert_eq!(SCHEME_UNIFOMR, 0x05);
    let det = UnifOmrDetector::new(0x01);
    assert_eq!(det.scheme(), "unifomr");

    let wallet = [0x42u8; 32];
    let client = UnifOmrClient::from_wallet(&wallet, 0x01).expect("client");
    let (_, pk) = clue_keypair_from_wallet(&wallet, 0x01).expect("keypair");
    let clue = serialize_clue(&pk.encrypt_zeros(&mut rng()));
    let det_key = client.build_detection_key(0x01).expect("det key");

    let notes = vec![(100u32, vec![ClueNote { omr_clue: clue }])];
    let digest = det.evaluate(&det_key, &notes).expect("evaluate");
    let slots = client.decrypt_digest_slots(&digest).expect("decrypt");
    let matches = UnifOmrClient::range_check_matches(&slots, 100, 100);
    assert!(matches.contains(&100), "pertinent height must match");
}
