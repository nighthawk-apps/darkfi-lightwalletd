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

//! Compact block types for the lightwallet server.
//!
//! These are the Rust-native representations of compact blocks, designed to
//! carry only the wallet-relevant subset of a DarkFi block:
//!
//! - **CompactOutput**: Coin commitment + encrypted note + Pedersen commitments
//!   (value, token). Clients trial-decrypt the encrypted note using DH + ChaCha20Poly1305.
//!
//! - **CompactTx**: Transaction hash + outputs + nullifiers. Nullifiers are used
//!   by clients to detect when their coins have been spent.
//!
//! - **CompactBlock**: Block header metadata + compact transactions.
//!   No ZK proofs, no Schnorr signatures, no PoW data.

use serde::{Deserialize, Serialize};

/// A compact representation of a single transaction output.
///
/// Contains only the data a wallet needs for trial decryption and
/// coin tracking. Strips ZK proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactOutput {
    /// Coin commitment: `Poseidon(pk_x, pk_y, value, token_id, spend_hook, user_data, blind)`
    /// 32 bytes (pallas::Base field element)
    pub coin: [u8; 32],

    /// Serialized `AeadEncryptedNote` — contains `ephem_public` (PublicKey) and
    /// `ciphertext` (encrypted MoneyNote). Clients attempt trial decryption
    /// with each of their secret keys via DH + ChaCha20Poly1305.
    pub encrypted_note: Vec<u8>,

    /// Pedersen commitment for the output value (compressed pallas::Point)
    pub value_commit: Vec<u8>,

    /// Commitment for the token ID (pallas::Base, 32 bytes)
    pub token_commit: [u8; 32],

    /// OMR detection data derived server-side from the encrypted note's
    /// ephemeral public key. Always empty in current implementation — the
    /// OMR detector extracts the key directly from `encrypted_note`.
    pub omr_clue: Vec<u8>,

    /// Recipient-encrypted OMR metadata (scheme + clue seed + user memo).
    /// Encrypted with recipient's pubkey via DH + ChaCha20Poly1305.
    /// LWD stores and merges opaquely; cannot decrypt.
    #[serde(default)]
    pub omr_metadata_enc: Vec<u8>,
}

/// A compact representation of a single transaction within a block.
///
/// Contains outputs (for note discovery) and nullifiers (for spend detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactTx {
    /// Transaction hash (blake3, 32 bytes)
    pub tx_hash: [u8; 32],

    /// Money contract outputs
    pub outputs: Vec<CompactOutput>,

    /// Revealed nullifiers from Money contract inputs
    /// Each nullifier is 32 bytes (pallas::Base)
    pub nullifiers: Vec<[u8; 32]>,

    /// Fee paid (if parseable from the FeeV1 call)
    pub fee: u64,
}

/// A compact representation of a DarkFi block.
///
/// Stripped of:
/// - ZK proofs (from each ContractCall)
/// - Schnorr signatures (from the block and each transaction)
/// - PoW data (Monero merge mining blobs etc.)
/// - Non-Money contract calls (for v1; extensible later)
///
/// Retains:
/// - Block metadata (height, hash, prev_hash, timestamp)
/// - Per-tx: outputs (coin + encrypted note + commitments), nullifiers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlock {
    /// Block height
    pub height: u32,

    /// Block header hash (blake3, 32 bytes)
    pub hash: [u8; 32],

    /// Previous block header hash (blake3, 32 bytes)
    pub prev_hash: [u8; 32],

    /// Block creation timestamp (unix seconds)
    pub timestamp: u64,

    /// Compact transactions in this block
    pub txs: Vec<CompactTx>,
}

impl CompactBlock {
    /// Convert this compact block to its protobuf representation.
    pub fn to_proto(&self) -> crate::proto::CompactBlock {
        crate::proto::CompactBlock {
            height: self.height,
            hash: self.hash.to_vec(),
            prev_hash: self.prev_hash.to_vec(),
            timestamp: self.timestamp,
            txs: self
                .txs
                .iter()
                .map(|tx| crate::proto::CompactTx {
                    tx_hash: tx.tx_hash.to_vec(),
                    outputs: tx
                        .outputs
                        .iter()
                        .map(|o| crate::proto::CompactOutput {
                            coin: o.coin.to_vec(),
                            encrypted_note: o.encrypted_note.clone(),
                            value_commit: o.value_commit.clone(),
                            token_commit: o.token_commit.to_vec(),
                            omr_clue: o.omr_clue.clone(),
                            omr_metadata_enc: o.omr_metadata_enc.clone(),
                        })
                        .collect(),
                    nullifiers: tx.nullifiers.iter().map(|n| n.to_vec()).collect(),
                    fee: tx.fee,
                })
                .collect(),
        }
    }
}
