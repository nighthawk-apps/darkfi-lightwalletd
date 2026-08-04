/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * Clue-PK ownership proofs for RegisterCluePublicKey (Schnorr over payment SK).
 *
 * v2 binds the network byte and a client-chosen monotonic `key_version`
 * (unix seconds) into the signed message, so proofs cannot be replayed
 * across networks and stale registrations cannot overwrite newer ones.
 */

/// Domain-separated message prefix for clue-PK ownership proofs (v2).
pub const CLUE_PK_OWNERSHIP_DOMAIN: &[u8] = b"DarkFi-UnifOMR-CluePK-v2";

/// Fixed wire length for `CluePublicKey.ownership_proof` responses.
/// Layout: `u16 LE proof_len || proof || random/zero pad`.
/// Keeps decoy and real responses the same size (registration-bit privacy).
pub const OWNERSHIP_PROOF_WIRE_LEN: usize = 128;

/// Encode a Schnorr ownership proof into a fixed-length wire blob.
pub fn pad_ownership_proof(proof: &[u8]) -> Result<Vec<u8>, String> {
    if proof.len() > OWNERSHIP_PROOF_WIRE_LEN - 2 {
        return Err(format!(
            "ownership proof too large: {} (max {})",
            proof.len(),
            OWNERSHIP_PROOF_WIRE_LEN - 2
        ));
    }
    let mut out = vec![0u8; OWNERSHIP_PROOF_WIRE_LEN];
    out[..2].copy_from_slice(&(proof.len() as u16).to_le_bytes());
    out[2..2 + proof.len()].copy_from_slice(proof);
    // Remaining bytes stay zero for real proofs; decoys overwrite all.
    Ok(out)
}

/// Extract the real proof bytes from a padded wire blob.
pub fn unpad_ownership_proof(wire: &[u8]) -> Result<&[u8], String> {
    if wire.len() < 2 {
        return Err("ownership proof wire too short".into());
    }
    let len = u16::from_le_bytes([wire[0], wire[1]]) as usize;
    if len == 0 || 2 + len > wire.len() {
        return Err("ownership proof length invalid".into());
    }
    Ok(&wire[2..2 + len])
}

/// Random decoy proof blob (same length as padded real proofs).
pub fn decoy_ownership_proof() -> Vec<u8> {
    let mut out = vec![0u8; OWNERSHIP_PROOF_WIRE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut out);
    out
}

/// Build the signed message for RegisterCluePublicKey ownership proofs.
///
/// `domain || network || key_version (u64 LE) || payment_pubkey || clue_public_key`
pub fn clue_pk_ownership_message(
    network: u8,
    key_version: u64,
    payment_pubkey: &[u8],
    clue_public_key: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        CLUE_PK_OWNERSHIP_DOMAIN.len() + 9 + payment_pubkey.len() + clue_public_key.len(),
    );
    msg.extend_from_slice(CLUE_PK_OWNERSHIP_DOMAIN);
    msg.push(network);
    msg.extend_from_slice(&key_version.to_le_bytes());
    msg.extend_from_slice(payment_pubkey);
    msg.extend_from_slice(clue_public_key);
    msg
}

/// Sign `RegisterCluePublicKey` with the payment [`darkfi_sdk::crypto::SecretKey`].
pub fn sign_clue_pk_ownership(
    payment_sk: &darkfi_sdk::crypto::SecretKey,
    network: u8,
    key_version: u64,
    payment_pubkey: &[u8; 32],
    clue_public_key: &[u8],
) -> Vec<u8> {
    use darkfi_sdk::crypto::schnorr::SchnorrSecret;
    use darkfi_serial::serialize;
    let msg = clue_pk_ownership_message(network, key_version, payment_pubkey, clue_public_key);
    let sig = payment_sk.sign(&msg);
    serialize(&sig)
}

/// Verify a clue-PK ownership proof against a 32-byte payment public key.
pub fn verify_clue_pk_ownership(
    network: u8,
    key_version: u64,
    payment_pubkey: &[u8; 32],
    clue_public_key: &[u8],
    ownership_proof: &[u8],
) -> Result<(), String> {
    use darkfi_sdk::crypto::schnorr::SchnorrPublic;
    use darkfi_sdk::crypto::PublicKey;
    use darkfi_serial::deserialize;
    // Accept fixed wire padding from GetCluePublicKey (u16 LE len || proof || pad).
    let proof_bytes = if ownership_proof.len() == OWNERSHIP_PROOF_WIRE_LEN {
        unpad_ownership_proof(ownership_proof)?
    } else {
        ownership_proof
    };
    let pk = PublicKey::from_bytes(*payment_pubkey)
        .map_err(|e| format!("invalid payment pubkey: {e}"))?;
    let sig: darkfi_sdk::crypto::schnorr::Signature = deserialize(proof_bytes)
        .map_err(|e| format!("invalid ownership proof encoding: {e}"))?;
    let msg = clue_pk_ownership_message(network, key_version, payment_pubkey, clue_public_key);
    if !pk.verify(&msg, &sig) {
        return Err("clue public key ownership proof verification failed".into());
    }
    Ok(())
}
