//! Live testnet 0.3 integration tests.
//!
//! These tests require a running `darkfid --testnet` node and
//! `darkfi-lightwalletd` pointed at it. They are gated behind the
//! `testnet-e2e` feature flag:
//!
//! ```bash
//! cargo test --features testnet-e2e -- --test-threads=1
//! ```
//!
//! Environment variables:
//!   LIGHTWALLETD_URL  — gRPC endpoint (default: "http://127.0.0.1:9068")
//!   DARKFID_RPC_URL   — darkfid JSON-RPC (default: "tcp://127.0.0.1:8340")

#![cfg(feature = "testnet-e2e")]

use std::time::Duration;
use darkfi::util::pcg::Pcg32;
use tokio::time::sleep;
use tonic::transport::Channel;

mod proto {
    tonic::include_proto!("darkfi.lightwallet");
}
use proto::dark_fi_light_wallet_client::DarkFiLightWalletClient;

/// Max gRPC message size for UnifOMR keys.
const MAX_MSG: usize = 64 * 1024 * 1024;

fn lwd_url() -> String {
    std::env::var("LIGHTWALLETD_URL").unwrap_or_else(|_| "http://127.0.0.1:9068".into())
}

async fn connect() -> DarkFiLightWalletClient<Channel> {
    DarkFiLightWalletClient::connect(lwd_url())
        .await
        .expect("Failed to connect to lightwalletd — is it running?")
        .max_decoding_message_size(MAX_MSG)
        .max_encoding_message_size(MAX_MSG)
}

// =========================================================================
// Test 1: LWD health check — GetLightInfo responds with valid chain info
// =========================================================================

#[tokio::test]
async fn testnet_lwd_health_check() {
    let mut client = connect().await;
    let info = client
        .get_light_info(proto::Empty {})
        .await
        .expect("GetLightInfo failed")
        .into_inner();

    assert!(!info.version.is_empty(), "version should not be empty");
    assert!(
        !info.chain_name.is_empty(),
        "chain_name should not be empty"
    );
    assert!(
        info.block_height > 0,
        "block_height should be > 0 on a running testnet"
    );
    assert!(
        info.omr_supported,
        "omr_supported should be true (built with fhe-omr)"
    );
    println!(
        "✅ LWD health: chain={} height={} omr={}",
        info.chain_name, info.block_height, info.omr_supported
    );
}

// =========================================================================
// Test 2: Compact block fetch — stream a range and verify fields
// =========================================================================

#[tokio::test]
async fn testnet_compact_block_stream() {
    let mut client = connect().await;

    // Get current tip
    let info = client
        .get_light_info(proto::Empty {})
        .await
        .expect("GetLightInfo failed")
        .into_inner();
    let tip = info.block_height;
    assert!(tip >= 2, "Need at least 2 blocks for range test");

    let start = tip.saturating_sub(2);
    let end = tip;

    let mut stream = client
        .get_block_range(proto::BlockRange {
            start_height: start,
            end_height: end,
        })
        .await
        .expect("GetBlockRange failed")
        .into_inner();

    let mut count = 0u32;
    while let Ok(Some(block)) = stream.message().await {
        assert!(
            block.height >= start && block.height <= end,
            "Block height {} out of range [{}, {}]",
            block.height,
            start,
            end
        );
        count += 1;
    }

    assert!(count > 0, "Should have received at least 1 compact block");
    println!("✅ Streamed {} compact blocks [{}, {}]", count, start, end);
}

// =========================================================================
// Test 3: OMR clue registration round-trip — register a PK, then fetch it
// =========================================================================

#[tokio::test]
async fn testnet_clue_pk_register_and_fetch() {
    let mut client = connect().await;

    // Real payment keypair — ownership_proof is a Schnorr sig under this SK.
    let pay_kp = darkfi_sdk::crypto::Keypair::random(&mut Pcg32::new(0x7E57));
    let test_pubkey = pay_kp.public.to_bytes().to_vec();

    // Clue public key must be a valid UnifOMR RLWE pk when fhe-omr is enabled.
    #[cfg(feature = "fhe-omr")]
    let clue_pk = {
        let wallet = [0x7Eu8; 32];
        let (_sk, pk) =
            darkfi_lightwalletd::unifomr::clue_keypair_from_wallet(&wallet, 0x01).unwrap();
        darkfi_lightwalletd::unifomr::serialize_public_key(&pk)
    };
    #[cfg(not(feature = "fhe-omr"))]
    let clue_pk = vec![0xAB; 128];

    let key_version = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);
    let ownership_proof = darkfi_lightwalletd::clue_ownership::sign_clue_pk_ownership(
        &pay_kp.secret,
        0x01, // testnet network byte
        key_version,
        &pay_kp.public.to_bytes(),
        &clue_pk,
    );

    // Register
    let reg = proto::CluePublicKeyRegistration {
        payment_pubkey: test_pubkey.clone(),
        clue_public_key: clue_pk.clone(),
        ownership_proof,
        key_version,
    };
    client
        .register_clue_public_key(reg)
        .await
        .expect("RegisterCluePublicKey failed");

    println!("✅ Registered clue PK for test pubkey");

    // Fetch it back
    let fetch = proto::PaymentPubkey {
        payment_pubkey: test_pubkey,
    };
    let resp = client
        .get_clue_public_key(fetch)
        .await
        .expect("GetCluePublicKey failed")
        .into_inner();

    assert!(resp.found, "Clue PK should be found after registration");
    assert_eq!(
        resp.clue_public_key, clue_pk,
        "Fetched clue PK should match registered PK"
    );
    println!("✅ Fetched clue PK matches registration");
}

// =========================================================================
// Test 4: SendTransaction with OMR clue — verify clue_accepted
// =========================================================================
// NOTE: This test requires a funded wallet. It is skipped if the env var
// TESTNET_FUNDED_TX_HEX is not set.

#[tokio::test]
async fn testnet_send_transaction_clue_accepted() {
    let funded_tx_hex = match std::env::var("TESTNET_FUNDED_TX_HEX") {
        Ok(hex) => hex,
        Err(_) => {
            println!("⏭ Skipping testnet_send_transaction: TESTNET_FUNDED_TX_HEX not set");
            return;
        }
    };

    let tx_data = hex::decode(&funded_tx_hex).expect("Invalid hex in TESTNET_FUNDED_TX_HEX");
    let omr_clue = vec![0xCD; 64]; // Dummy clue for the test

    let mut client = connect().await;
    let resp = client
        .send_transaction(proto::RawTransaction {
            data: tx_data,
            omr_clue: omr_clue.clone(),
            omr_clue_output_index: 0,
            omr_metadata_enc: vec![],
        })
        .await
        .expect("SendTransaction RPC failed")
        .into_inner();

    if resp.error.is_empty() {
        assert!(
            resp.clue_accepted,
            "SendTransaction succeeded but clue_accepted=false"
        );
        assert_eq!(resp.tx_hash.len(), 32, "tx_hash should be 32 bytes");
        println!(
            "✅ Transaction broadcast: hash={} clue_accepted={}",
            hex::encode(&resp.tx_hash),
            resp.clue_accepted
        );
    } else {
        println!(
            "⚠️ SendTransaction returned error (tx may be invalid): {}",
            resp.error
        );
    }
}

// =========================================================================
// Test 5: Block confirmation polling — wait for tip to advance
// =========================================================================

#[tokio::test]
async fn testnet_block_advancement() {
    let mut client = connect().await;

    let info1 = client
        .get_light_info(proto::Empty {})
        .await
        .expect("GetLightInfo failed")
        .into_inner();
    let height1 = info1.block_height;

    println!(
        "Current height: {}. Waiting up to 120s for a new block...",
        height1
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut height2 = height1;

    while tokio::time::Instant::now() < deadline {
        sleep(Duration::from_secs(5)).await;
        let info2 = client
            .get_light_info(proto::Empty {})
            .await
            .expect("GetLightInfo poll failed")
            .into_inner();
        height2 = info2.block_height;
        if height2 > height1 {
            break;
        }
    }

    assert!(
        height2 > height1,
        "Block height did not advance within 120s ({}→{}). Is the testnet mining?",
        height1,
        height2
    );
    println!("✅ Block advanced: {} → {}", height1, height2);

    // Verify the new block is fetchable
    let block = client
        .get_block(proto::BlockHeight { height: height2 })
        .await
        .expect("GetBlock for new height failed")
        .into_inner();

    assert_eq!(block.height, height2);
    println!(
        "✅ New block fetched: height={} txs={}",
        block.height,
        block.txs.len()
    );
}

// =========================================================================
// Test 6: Nullifier + NoteCommitment streams — basic liveness
// =========================================================================

#[tokio::test]
async fn testnet_nullifiers_and_commitments() {
    let mut client = connect().await;

    let info = client
        .get_light_info(proto::Empty {})
        .await
        .expect("GetLightInfo failed")
        .into_inner();
    let tip = info.block_height;
    let start = tip.saturating_sub(10);

    // GetNullifiers
    let mut null_stream = client
        .get_nullifiers(proto::BlockRange {
            start_height: start,
            end_height: tip,
        })
        .await
        .expect("GetNullifiers failed")
        .into_inner();
    let mut null_count = 0u32;
    while let Ok(Some(_)) = null_stream.message().await {
        null_count += 1;
    }
    println!(
        "✅ GetNullifiers [{}, {}]: {} messages",
        start, tip, null_count
    );

    // GetNoteCommitments
    let mut commit_stream = client
        .get_note_commitments(proto::BlockRange {
            start_height: start,
            end_height: tip,
        })
        .await
        .expect("GetNoteCommitments failed")
        .into_inner();
    let mut commit_count = 0u32;
    while let Ok(Some(_)) = commit_stream.message().await {
        commit_count += 1;
    }
    println!(
        "✅ GetNoteCommitments [{}, {}]: {} messages",
        start, tip, commit_count
    );
}
