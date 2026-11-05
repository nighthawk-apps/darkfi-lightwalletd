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
use darkfi_dao_contract::{
    model::{
        DaoAuthMoneyTransferParams, DaoExecParams, DaoMintParams, DaoProposeParams, DaoVoteParams,
    },
    DaoFunction,
};
use darkfi_money_contract::{
    model::{
        MoneyAuthTokenFreezeParamsV1, MoneyAuthTokenMintParamsV1, MoneyBurnParamsV1,
        MoneyFeeParamsV1, MoneyGenesisMintParamsV1, MoneyPoWRewardParamsV1, MoneyTokenMintParamsV1,
        MoneyTransferParamsV1,
    },
    MoneyFunction,
};
use darkfi_sdk::crypto::pasta_prelude::PrimeField;
use darkfi_sdk::crypto::{DAO_CONTRACT_ID, MONEY_CONTRACT_ID};
use darkfi_serial::{deserialize, deserialize_async, deserialize_async_partial, serialize};
use tracing::{debug, trace, warn};

use crate::{
    compact_block::{
        CompactBlock, CompactDaoCallRecord, CompactFuncEvent, CompactOutput, CompactTx,
    },
    error::{LightWalletError, Result},
};

/// Reject chain-supplied counts before they become allocations.
const MAX_TXS_PER_BLOCK: usize = 100_000;
const MAX_CALLS_PER_TX: usize = 10_000;

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

    if block.txs.len() > MAX_TXS_PER_BLOCK {
        return Err(LightWalletError::ProcessingError(format!(
            "block {height} has {} transactions (cap {MAX_TXS_PER_BLOCK})",
            block.txs.len()
        )));
    }
    let mut compact_txs = Vec::with_capacity(block.txs.len());
    let mut dao_calls = Vec::new();
    let mut func_events = Vec::new();

    for tx in &block.txs {
        if tx.calls.len() > MAX_CALLS_PER_TX {
            return Err(LightWalletError::ProcessingError(format!(
                "block {height} transaction has {} calls (cap {MAX_CALLS_PER_TX})",
                tx.calls.len()
            )));
        }
        let tx_hash = tx.hash();
        let mut outputs = Vec::new();
        let mut nullifiers = Vec::new();
        let fee: u64 = 0;

        // Iterate through the transaction's contract calls
        for call_leaf in &tx.calls {
            let call = &call_leaf.data;
            let contract_id = call.contract_id;
            let data = &call.data;

            if contract_id == *DAO_CONTRACT_ID {
                match compact_dao_call(tx_hash.inner(), data) {
                    Ok(Some(record)) => dao_calls.push(record),
                    Ok(None) => {}
                    Err(e) => {
                        warn!(
                            target: "lightwalletd::block_processor",
                            "Skipping DAO call in tx {}: {e}",
                            tx_hash
                        );
                    }
                }
                continue;
            }

            // Money outputs, nullifiers, and auth-token history.
            if contract_id != *MONEY_CONTRACT_ID {
                trace!(
                    target: "lightwalletd::block_processor",
                    "Skipping non-Money contract call (contract: {contract_id})"
                );
                continue;
            }

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
                        outputs.push(output_to_compact(&params.output, data[0])?);
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
                            outputs.push(output_to_compact(output, data[0])?);
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
                            outputs.push(output_to_compact(output, data[0])?);
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
                        outputs.push(output_to_compact(&params.output, data[0])?);
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
                        func_code: data[0],
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

                MoneyFunction::AuthTokenMintV1 => {
                    let _: MoneyAuthTokenMintParamsV1 =
                        deserialize_async(&data[1..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize AuthTokenMintV1 params: {e}"
                            ))
                        })?;
                    func_events.push(CompactFuncEvent {
                        tx_hash: *tx_hash.inner(),
                        func_code: data[0],
                    });
                }
                MoneyFunction::AuthTokenFreezeV1 => {
                    let _: MoneyAuthTokenFreezeParamsV1 =
                        deserialize_async(&data[1..]).await.map_err(|e| {
                            LightWalletError::ProcessingError(format!(
                                "Failed to deserialize AuthTokenFreezeV1 params: {e}"
                            ))
                        })?;
                    func_events.push(CompactFuncEvent {
                        tx_hash: *tx_hash.inner(),
                        func_code: data[0],
                    });
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
        dao_calls,
        func_events,
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
fn output_to_compact(
    output: &darkfi_money_contract::model::Output,
    func_code: u8,
) -> Result<CompactOutput> {
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
        func_code,
    })
}

/// Keep the DAO fields a light client can decrypt. Proofs stay on the transaction.
fn compact_dao_call(tx_hash: &[u8; 32], data: &[u8]) -> Result<Option<CompactDaoCallRecord>> {
    if data.is_empty() {
        return Ok(None);
    }
    let func = match DaoFunction::try_from(data[0]) {
        Ok(func) => func,
        Err(_) => return Ok(None),
    };
    let (bulla, payload) = match func {
        DaoFunction::Mint => {
            let params: DaoMintParams = deserialize(&data[1..])
                .map_err(|e| LightWalletError::ProcessingError(format!("DAO mint params: {e}")))?;
            (
                params.dao_bulla.to_bytes().to_vec(),
                serialize(&params.dao_pubkey),
            )
        }
        DaoFunction::Propose => {
            let params: DaoProposeParams = deserialize(&data[1..]).map_err(|e| {
                LightWalletError::ProcessingError(format!("DAO propose params: {e}"))
            })?;
            (
                params.proposal_bulla.to_bytes().to_vec(),
                serialize(&(params.token_commit, params.note)),
            )
        }
        DaoFunction::Vote => {
            let params: DaoVoteParams = deserialize(&data[1..])
                .map_err(|e| LightWalletError::ProcessingError(format!("DAO vote params: {e}")))?;
            let nullifiers: Vec<_> = params
                .inputs
                .iter()
                .map(|input| input.vote_nullifier)
                .collect();
            (
                params.proposal_bulla.to_bytes().to_vec(),
                serialize(&(params.note, nullifiers)),
            )
        }
        DaoFunction::Exec => {
            let params: DaoExecParams = deserialize(&data[1..])
                .map_err(|e| LightWalletError::ProcessingError(format!("DAO exec params: {e}")))?;
            (
                params.proposal_bulla.to_bytes().to_vec(),
                serialize(&(params.early_exec as u8)),
            )
        }
        DaoFunction::AuthMoneyTransfer => {
            let params: DaoAuthMoneyTransferParams = deserialize(&data[1..]).map_err(|e| {
                LightWalletError::ProcessingError(format!("DAO auth transfer params: {e}"))
            })?;
            (
                Vec::new(),
                serialize(&(params.enc_attrs, params.dao_change_attrs)),
            )
        }
    };
    Ok(Some(CompactDaoCallRecord {
        tx_hash: *tx_hash,
        kind: func as u32,
        bulla,
        payload,
    }))
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
        assert!(compact.dao_calls.is_empty());
    }

    fn dummy_note() -> darkfi_sdk::crypto::note::AeadEncryptedNote {
        use darkfi_sdk::crypto::{PublicKey, SecretKey};
        use darkfi_sdk::pasta::pallas;
        darkfi_sdk::crypto::note::AeadEncryptedNote {
            ciphertext: vec![0x11, 0x22, 0x33, 0x44],
            ephem_public: PublicKey::from_secret(SecretKey::from(pallas::Base::from(4u64))),
        }
    }

    #[tokio::test]
    async fn test_token_mint_keeps_func_code_and_note() {
        use darkfi_money_contract::model::{Coin, MoneyTokenMintParamsV1};
        use darkfi_sdk::pasta::pallas;

        let coin = Coin::from(pallas::Base::from(3u64));
        let enc_note = dummy_note();
        let params = MoneyTokenMintParamsV1 {
            coin,
            enc_note: enc_note.clone(),
        };
        let mut data = vec![MoneyFunction::TokenMintV1 as u8];
        data.extend(serialize(&params));
        let mut block = make_empty_block(9);
        block.txs.push(tx_with_call(*MONEY_CONTRACT_ID, data));

        let compact = process_block(&block).await.unwrap();
        assert_eq!(compact.txs.len(), 1);
        let output = &compact.txs[0].outputs[0];
        assert_eq!(output.func_code, MoneyFunction::TokenMintV1 as u8);
        assert_eq!(output.coin, coin.to_bytes());
        assert_eq!(output.encrypted_note, serialize(&enc_note));
        assert!(output.value_commit.is_empty());
        assert!(compact.txs[0].nullifiers.is_empty());
    }

    #[tokio::test]
    async fn test_auth_token_mint_is_history_without_a_coin() {
        use darkfi_money_contract::model::MoneyAuthTokenMintParamsV1;
        use darkfi_money_contract::model::TokenId;
        use darkfi_sdk::crypto::{PublicKey, SecretKey};
        use darkfi_sdk::pasta::pallas;

        let params = MoneyAuthTokenMintParamsV1 {
            token_id: TokenId::from(pallas::Base::from(8u64)),
            mint_pubkey: PublicKey::from_secret(SecretKey::from(pallas::Base::from(5u64))),
        };
        let mut data = vec![MoneyFunction::AuthTokenMintV1 as u8];
        data.extend(serialize(&params));
        let mut block = make_empty_block(10);
        block.txs.push(tx_with_call(*MONEY_CONTRACT_ID, data));

        let compact = process_block(&block).await.unwrap();
        assert!(compact.txs.is_empty(), "auth mint has no coin to append");
        assert_eq!(compact.func_events.len(), 1);
        assert_eq!(
            compact.func_events[0].func_code,
            MoneyFunction::AuthTokenMintV1 as u8
        );
    }

    #[tokio::test]
    async fn test_dao_propose_survives_without_proofs_or_inputs() {
        use darkfi_dao_contract::model::{DaoProposeParams, DaoProposeParamsInput};
        use darkfi_dao_contract::DaoFunction;
        use darkfi_money_contract::model::Nullifier;
        use darkfi_sdk::crypto::{MerkleNode, PublicKey, SecretKey};
        use darkfi_sdk::pasta::group::Group;
        use darkfi_sdk::pasta::pallas;
        use darkfi_serial::deserialize;

        let note = dummy_note();
        let dropped = Nullifier::from(pallas::Base::from(0xABCDu64));
        let params = DaoProposeParams {
            dao_merkle_root: MerkleNode::from(pallas::Base::from(1u64)),
            merkle_coin_root: MerkleNode::from(pallas::Base::from(2u64)),
            smt_null_root: pallas::Base::from(3u64),
            token_commit: pallas::Base::from(7u64),
            proposal_bulla: darkfi_dao_contract::model::DaoProposalBulla::from(pallas::Base::from(
                9u64,
            )),
            note: note.clone(),
            inputs: vec![DaoProposeParamsInput {
                value_commit: pallas::Point::generator(),
                input_nullifier: dropped,
                signature_public: PublicKey::from_secret(SecretKey::from(pallas::Base::from(6u64))),
            }],
        };
        let mut data = vec![DaoFunction::Propose as u8];
        data.extend(serialize(&params));
        let tx = tx_with_call(*DAO_CONTRACT_ID, data);
        let mut block = make_empty_block(11);
        block.txs.push(tx);

        let compact = process_block(&block).await.unwrap();
        assert!(compact.txs.is_empty());
        assert_eq!(compact.dao_calls.len(), 1);
        let call = &compact.dao_calls[0];
        assert_eq!(call.kind, u32::from(DaoFunction::Propose as u8));
        assert_eq!(call.bulla, params.proposal_bulla.to_bytes());
        let (token_commit, kept_note): (pallas::Base, darkfi_sdk::crypto::note::AeadEncryptedNote) =
            deserialize(&call.payload).unwrap();
        assert_eq!(token_commit, params.token_commit);
        assert_eq!(kept_note, note);
        let raw = serialize(&dropped);
        assert!(
            !call
                .payload
                .windows(raw.len())
                .any(|window| window == raw.as_slice()),
            "proposal inputs are stripped"
        );
    }
}
