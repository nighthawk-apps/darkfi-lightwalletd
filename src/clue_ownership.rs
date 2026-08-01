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
    let pk = PublicKey::from_bytes(*payment_pubkey)
        .map_err(|e| format!("invalid payment pubkey: {e}"))?;
    let sig: darkfi_sdk::crypto::schnorr::Signature = deserialize(ownership_proof)
        .map_err(|e| format!("invalid ownership proof encoding: {e}"))?;
    let msg = clue_pk_ownership_message(network, key_version, payment_pubkey, clue_public_key);
    if !pk.verify(&msg, &sig) {
        return Err("clue public key ownership proof verification failed".into());
    }
    Ok(())
}
