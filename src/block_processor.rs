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

//! Block processor: converts full `BlockInfo` from darkfid into `CompactBlock`.
//!
//! This is the core transformation logic. For each transaction in a block, we:
//! 1. Identify Money contract calls (by contract ID)
//! 2. Parse the call data to determine the MoneyFunction variant
//! 3. Extract outputs (coin + encrypted note) and nullifiers
//! 4. Build a CompactTx with only the wallet-relevant data
//!
//! The processor understands all MoneyFunction variants:
//! - FeeV1: 1 input (nullifier) + 1 output
//! - TransferV1: N inputs (nullifiers) + M outputs
//! - GenesisMintV1: M outputs (no nullifiers)
//! - PoWRewardV1: 1 output (no nullifiers)
//! - TokenMintV1: 1 output (no nullifiers)
//! - BurnV1: N inputs (nullifiers, no outputs)
//! - AuthTokenMintV1, AuthTokenFreezeV1: no wallet-relevant data

use darkfi::blockchain::block_store::BlockInfo;
use darkfi_money_contract::{
    model::{
        MoneyBurnParamsV1, MoneyFeeParamsV1, MoneyGenesisMintParamsV1, MoneyPoWRewardParamsV1,
        MoneyTokenMintParamsV1, MoneyTransferParamsV1,
    },
    MoneyFunction,
};
use darkfi_sdk::crypto::pasta_prelude::PrimeField;
use darkfi_sdk::crypto::MONEY_CONTRACT_ID;
use darkfi_serial::{deserialize_async, deserialize_async_partial, serialize};
use tracing::{debug, trace, warn};

use crate::{
    compact_block::{CompactBlock, CompactOutput, CompactTx},
    error::{LightWalletError, Result},
};

/// Process a full `BlockInfo` from darkfid into a `CompactBlock`.
///
/// This strips:
/// - ZK proofs from each ContractCall
/// - Schnorr signatures from the block and transactions
/// - PoW data from the block header
/// - Non-Money contract call details (for v1)
///
/// And extracts:
/// - Per-output: coin commitment, AeadEncryptedNote, value/token commitments
/// - Per-input: nullifier
/// - Block metadata: height, hash, prev_hash, timestamp
pub async fn process_block(block: &BlockInfo) -> Result<CompactBlock> {
    let header = &block.header;
    let block_hash = header.hash();
    let height = header.height;

    debug!(
        target: "lightwalletd::block_processor",
        "Processing block at height {height}, hash {}",
        block_hash.as_string()
    );

    let mut compact_txs = Vec::with_capacity(block.txs.len());

    for tx in &block.txs {
        let tx_hash = tx.hash();
        let mut outputs = Vec::new();
        let mut nullifiers = Vec::new();
        let fee: u64 = 0;

        // Iterate through the transaction's contract calls
        for call_leaf in &tx.calls {
            let call = &call_leaf.data;
            let contract_id = call.contract_id;

            // We only process Money contract calls in v1
            if contract_id != *MONEY_CONTRACT_ID {
                trace!(
                    target: "lightwalletd::block_processor",
                    "Skipping non-Money contract call (contract: {contract_id})"
                );
                continue;
            }

            let data = &call.data;
            if data.is_empty() {
                warn!(
                    target: "lightwalletd::block_processor",
                    "Empty call data for Money contract in tx {}",
                    tx_hash
                );
                continue;
            }

            // The first byte is the MoneyFunction discriminant
            let func = match MoneyFunction::try_from(data[0]) {
                Ok(f) => f,
                Err(_) => {
                    warn!(
                        target: "lightwalletd::block_processor",
                        "Unknown MoneyFunction discriminant 0x{:02x} in tx {}",
                        data[0], tx_hash
                    );
                    continue;
                }
            };

            match func {
                MoneyFunction::FeeV1 => {
                    // FeeV1 uses data[9..] for params (first 9 bytes are function
                    // discriminant + gas cost)
                    let params: MoneyFeeParamsV1 =
                        deserialize_async(&data[9..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize FeeV1 params: {e}"
                            ))
                        })?;

                    nullifiers.push(params.input.nullifier.inner().to_repr());

                    if !params.output.tx_local {
                        outputs.push(output_to_compact(&params.output)?);
                    }
                }

                MoneyFunction::TransferV1 => {
                    let params: MoneyTransferParamsV1 =
                        deserialize_async(&data[1..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize TransferV1 params: {e}"
                            ))
                        })?;

                    for input in &params.inputs {
                        nullifiers.push(input.nullifier.inner().to_repr());
                    }

                    for output in &params.outputs {
                        if !output.tx_local {
                            outputs.push(output_to_compact(output)?);
                        }
                    }
                }

                MoneyFunction::GenesisMintV1 => {
                    let params: MoneyGenesisMintParamsV1 =
                        deserialize_async(&data[1..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize GenesisMintV1 params: {e}"
                            ))
                        })?;

                    for output in &params.outputs {
                        if !output.tx_local {
                            outputs.push(output_to_compact(output)?);
                        }
                    }
                }

                MoneyFunction::PoWRewardV1 => {
                    let (params, _): (MoneyPoWRewardParamsV1, _) =
                        deserialize_async_partial(&data[1..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize PoWRewardV1 params: {e}"
                            ))
                        })?;

                    if !params.output.tx_local {
                        outputs.push(output_to_compact(&params.output)?);
                    }
                }

                MoneyFunction::TokenMintV1 => {
                    let params: MoneyTokenMintParamsV1 =
                        deserialize_async(&data[1..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize TokenMintV1 params: {e}"
                            ))
                        })?;

                    outputs.push(CompactOutput {
                        coin: params.coin.to_bytes(),
                        encrypted_note: serialize(&params.enc_note),
                        value_commit: Vec::new(), // TokenMint doesn't have value_commit
                        token_commit: [0u8; 32],  // TokenMint doesn't have token_commit
                        omr_clue: vec![],         // TokenMint doesn't have OMR clue
                        omr_metadata_enc: vec![],
                    });
                }

                MoneyFunction::BurnV1 => {
                    let params: MoneyBurnParamsV1 =
                        deserialize_async(&data[1..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize BurnV1 params: {e}"
                            ))
                        })?;

                    for input in &params.inputs {
                        nullifiers.push(input.nullifier.inner().to_repr());
                    }
                    // BurnV1 has no outputs
                }

                MoneyFunction::AuthTokenMintV1 | MoneyFunction::AuthTokenFreezeV1 => {
                    // These don't produce wallet-relevant outputs or nullifiers
                    trace!(
                        target: "lightwalletd::block_processor",
                        "Skipping {:?} call (no wallet-relevant data)",
                        func
                    );
                }
            }
        }

        // Only include transactions that have wallet-relevant data
        if !outputs.is_empty() || !nullifiers.is_empty() {
            compact_txs.push(CompactTx {
                tx_hash: *tx_hash.inner(),
                outputs,
                nullifiers,
                fee,
            });
        }
    }

    let compact_block = CompactBlock {
        height,
        hash: *block_hash.inner(),
        prev_hash: *header.previous.inner(),
        timestamp: header.timestamp.inner(),
        txs: compact_txs,
    };

    debug!(
        target: "lightwalletd::block_processor",
        "Processed block {height}: {} compact txs ({} outputs, {} nullifiers)",
        compact_block.txs.len(),
        compact_block.txs.iter().map(|t| t.outputs.len()).sum::<usize>(),
        compact_block.txs.iter().map(|t| t.nullifiers.len()).sum::<usize>(),
    );

    Ok(compact_block)
}

/// Convert a Money contract `Output` to a `CompactOutput`.
///
/// The `omr_clue` field is left empty — the OMR detector derives detection
/// data server-side from the ephemeral public key embedded in the encrypted
/// note. This keeps all OMR/OMD logic within `darkfi-lightwalletd` without
/// requiring modifications to the upstream Money contract.
fn output_to_compact(output: &darkfi_money_contract::model::Output) -> Result<CompactOutput> {
    use darkfi_sdk::crypto::pasta_prelude::PrimeField;

    Ok(CompactOutput {
        coin: output.coin.to_bytes(),
        encrypted_note: serialize(&output.note),
        value_commit: serialize(&output.value_commit),
        token_commit: output.token_commit.to_repr(),
        // OMR clue is derived server-side from encrypted_note's ephemeral key.
        // No upstream contract modification needed.
        omr_clue: vec![],
        omr_metadata_enc: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkfi::blockchain::{BlockInfo, Header, HeaderHash};
    use darkfi::tx::Transaction;
    use darkfi::util::time::Timestamp;
    use darkfi_sdk::crypto::schnorr::Signature;
    use darkfi_sdk::crypto::ContractId;
    use darkfi_sdk::dark_tree::DarkLeaf;
    use darkfi_sdk::tx::ContractCall;

    // Helper to generate a block header with a specific height/timestamp.
    fn make_header(height: u32) -> Header {
        Header::new(
            HeaderHash::new([0u8; 32]),
            height,
            0,
            Timestamp::from_u64(1000 + height as u64),
        )
    }

    fn make_empty_block(height: u32) -> BlockInfo {
        BlockInfo {
            header: make_header(height),
            txs: vec![],
            signature: Signature::dummy(),
        }
    }

    /// Wrap a single `ContractCall` into a `Transaction` with no proofs/sigs.
    fn tx_with_call(contract_id: ContractId, data: Vec<u8>) -> Transaction {
        Transaction {
            calls: vec![DarkLeaf {
                data: ContractCall { contract_id, data },
                parent_index: None,
                children_indexes: vec![],
            }],
            proofs: vec![],
            signatures: vec![],
        }
    }

    /// A contract id that is guaranteed not to be the Money contract.
    fn non_money_contract_id() -> ContractId {
        ContractId::from_bytes([0u8; 32]).unwrap()
    }

    // ── Block metadata ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_process_empty_block() {
        let block = make_empty_block(42);
        let compact = process_block(&block).await.unwrap();

        assert_eq!(compact.height, 42);
        assert_eq!(compact.timestamp, 1042);
        assert!(compact.txs.is_empty());
    }

    #[tokio::test]
    async fn test_block_metadata_matches_header() {
        let block = make_empty_block(12_345);
        let compact = process_block(&block).await.unwrap();

        assert_eq!(compact.height, 12_345);
        assert_eq!(compact.timestamp, 1000 + 12_345);
        // Hash / prev_hash are copied straight from the header.
        assert_eq!(compact.hash, *block.header.hash().inner());
        assert_eq!(compact.prev_hash, *block.header.previous.inner());
    }

    #[tokio::test]
    async fn test_distinct_heights_produce_distinct_hashes() {
        let a = process_block(&make_empty_block(1)).await.unwrap();
        let b = process_block(&make_empty_block(2)).await.unwrap();
        assert_ne!(a.hash, b.hash, "different heights must hash differently");
        assert_eq!(a.height, 1);
        assert_eq!(b.height, 2);
    }

    #[tokio::test]
    async fn test_multiple_blocks_processed_independently() {
        for h in [0u32, 7, 100, 999_999] {
            let compact = process_block(&make_empty_block(h)).await.unwrap();
            assert_eq!(compact.height, h);
            assert!(compact.txs.is_empty());
        }
    }

    // ── Contract-call filtering ──────────────────────────────────────────

    #[tokio::test]
    async fn test_non_money_call_is_skipped() {
        // A tx whose only call targets a non-Money contract yields no
        // wallet-relevant data, so it is dropped from the compact block.
        let tx = tx_with_call(non_money_contract_id(), vec![0x00, 0x01, 0x02]);
        let mut block = make_empty_block(5);
        block.txs.push(tx);

        let compact = process_block(&block).await.unwrap();
        assert!(
            compact.txs.is_empty(),
            "non-Money tx should be filtered out"
        );
    }

    #[tokio::test]
    async fn test_money_call_with_empty_data_is_skipped() {
        // Money contract call but empty payload — must be handled gracefully
        // (logged + skipped) without erroring.
        let tx = tx_with_call(*MONEY_CONTRACT_ID, vec![]);
        let mut block = make_empty_block(6);
        block.txs.push(tx);

        let compact = process_block(&block).await.unwrap();
        assert!(compact.txs.is_empty());
    }

    #[tokio::test]
    async fn test_unknown_money_function_is_skipped() {
        // 0xFF is not a valid MoneyFunction discriminant → skipped, no panic.
        let tx = tx_with_call(*MONEY_CONTRACT_ID, vec![0xFF, 0xAA, 0xBB]);
        let mut block = make_empty_block(7);
        block.txs.push(tx);

        let compact = process_block(&block).await.unwrap();
        assert!(compact.txs.is_empty());
    }

    #[tokio::test]
    async fn test_mixed_block_only_keeps_relevant_txs() {
        // One non-Money tx + one unknown-money-func tx → both filtered.
        let mut block = make_empty_block(8);
        block
            .txs
            .push(tx_with_call(non_money_contract_id(), vec![0x01]));
        block.txs.push(tx_with_call(*MONEY_CONTRACT_ID, vec![0xFE]));

        let compact = process_block(&block).await.unwrap();
        assert!(compact.txs.is_empty());
    }
}
