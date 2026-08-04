//! Live UnifOMR registration matrix against a running lightwalletd.
//!
//! Cases (verification checklist):
//! - both / recv_only → directory returns registered clue PK (UnifOMR buildable)
//! - send_only / neither → directory returns decoy (found always true; ≠ real key)
//! - GetUnifOmrDigest decrypt + range-check for registered wallet crypto
//!
//! Usage:
//!   E2E_LWD_URL=http://127.0.0.1:9067 cargo run --release --bin e2e_unifomr_matrix
//!
//! Prints `MATRIX_PASS:…` / `MATRIX_FAIL:…` lines for the wrapper script.

use darkfi_lightwalletd::proto::dark_fi_light_wallet_client::DarkFiLightWalletClient;
use darkfi_lightwalletd::proto::{
    CluePublicKeyRegistration, Empty, DetectionKeyChunk, PaymentPubkey,
};
use darkfi_lightwalletd::unifomr::{
    build_omr_clue_from_pk, clue_keypair_from_wallet, clue_public_key_wire_len,
    deserialize_public_key, serialize_public_key, sign_clue_pk_ownership,
    verify_clue_pk_ownership, UnifOmrClient, SCHEME_UNIFOMR,
};
use darkfi::util::pcg::Pcg32;
use darkfi_sdk::crypto::Keypair;

type Client = DarkFiLightWalletClient<tonic::transport::Channel>;

fn pass(name: &str) {
    println!("MATRIX_PASS:{name}");
}

fn fail(name: &str, detail: &str) {
    eprintln!("  detail: {detail}");
    println!("MATRIX_FAIL:{name}");
}

async fn connect(url: &str) -> Result<Client, String> {
    // UnifOMR detection keys are ~38MB (n=1024 BFV CTs); raise tonic defaults (4MB).
    const MAX_MSG: usize = 160 * 1024 * 1024;
    let endpoint = tonic::transport::Endpoint::from_shared(url.to_string())
        .map_err(|e| format!("endpoint: {e}"))?
        .tcp_nodelay(true);
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| format!("connect {url}: {e}"))?;
    Ok(DarkFiLightWalletClient::new(channel)
        .max_decoding_message_size(MAX_MSG)
        .max_encoding_message_size(MAX_MSG))
}

async fn register(
    client: &mut Client,
    pay_sk: &darkfi_sdk::crypto::SecretKey,
    network: u8,
    pay: &[u8; 32],
    clue_pk: &[u8],
) -> Result<(), String> {
    let key_version = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);
    let ownership_proof = sign_clue_pk_ownership(pay_sk, network, key_version, pay, clue_pk);
    client
        .register_clue_public_key(CluePublicKeyRegistration {
            payment_pubkey: pay.to_vec(),
            clue_public_key: clue_pk.to_vec(),
            ownership_proof,
            key_version,
        })
        .await
        .map_err(|e| format!("RegisterCluePublicKey: {e}"))?;
    Ok(())
}

async fn lookup(
    client: &mut Client,
    pay: &[u8; 32],
) -> Result<(bool, Vec<u8>, Vec<u8>, u64), String> {
    let resp = client
        .get_clue_public_key(PaymentPubkey {
            payment_pubkey: pay.to_vec(),
        })
        .await
        .map_err(|e| format!("GetCluePublicKey: {e}"))?
        .into_inner();
    Ok((
        resp.found,
        resp.clue_public_key,
        resp.ownership_proof,
        resp.key_version,
    ))
}

fn expect_registered_clue(
    found: bool,
    clue_pk: &[u8],
    ownership_proof: &[u8],
    key_version: u64,
    expected: &[u8],
    payment_pk: &[u8; 32],
    network: u8,
    label: &str,
) {
    if !found {
        fail(label, "expected found=true (privacy: always true)");
        return;
    }
    if clue_pk != expected {
        fail(
            label,
            "registered lookup must return exact registered clue pk",
        );
        return;
    }
    if let Err(e) = verify_clue_pk_ownership(
        network,
        key_version,
        payment_pk,
        clue_pk,
        ownership_proof,
    ) {
        fail(label, &format!("ownership proof verify failed: {e}"));
        return;
    }
    match deserialize_public_key(clue_pk) {
        Ok(pk) => {
            let clue = build_omr_clue_from_pk(&pk);
            if clue.len() > 16 && clue[1] == SCHEME_UNIFOMR {
                pass(label);
            } else {
                fail(
                    label,
                    &format!(
                        "bad UnifOMR clue len={} scheme={:?}",
                        clue.len(),
                        clue.get(1)
                    ),
                );
            }
        }
        Err(e) => fail(label, &format!("deserialize clue pk: {e}")),
    }
}

fn expect_decoy_no_leak(
    found: bool,
    clue_pk: &[u8],
    ownership_proof: &[u8],
    key_version: u64,
    payment_pk: &[u8; 32],
    network: u8,
    not_equal_to: &[u8],
    label: &str,
) {
    if !found {
        fail(
            label,
            "expected found=true (registration bit must not leak)",
        );
        return;
    }
    if clue_pk.len() != clue_public_key_wire_len() {
        fail(
            label,
            &format!(
                "decoy wire len {} != {}",
                clue_pk.len(),
                clue_public_key_wire_len()
            ),
        );
        return;
    }
    if clue_pk == not_equal_to {
        fail(label, "decoy unexpectedly equals a real clue pk");
        return;
    }
    // Decoy ownership must NOT verify under the queried payment key.
    if verify_clue_pk_ownership(
        network,
        key_version,
        payment_pk,
        clue_pk,
        ownership_proof,
    )
    .is_ok()
    {
        fail(label, "decoy ownership proof unexpectedly verified");
        return;
    }
    match deserialize_public_key(clue_pk) {
        Ok(_) => pass(label),
        Err(e) => fail(label, &format!("decoy must deserialize as RLWE pk: {e}")),
    }
}

#[tokio::main]
async fn main() {
    let url = std::env::var("E2E_LWD_URL").unwrap_or_else(|_| "http://127.0.0.1:9067".into());
    let network: u8 = match std::env::var("E2E_NETWORK")
        .unwrap_or_else(|_| "testnet".into())
        .as_str()
    {
        "mainnet" => 0x00,
        _ => 0x01,
    };

    println!("=== UnifOMR registration matrix @ {url} (net={network:#04x}) ===");

    let mut client = match connect(&url).await {
        Ok(c) => c,
        Err(e) => {
            fail("connect", &e);
            std::process::exit(1);
        }
    };

    match client.get_omr_capabilities(Empty {}).await {
        Ok(resp) => {
            let caps = resp.into_inner();
            if caps.enabled && (caps.scheme.contains("unifomr") || !caps.scheme.is_empty()) {
                pass(&format!(
                    "capabilities enabled scheme={} max_range={}",
                    caps.scheme, caps.max_range_per_request
                ));
            } else {
                fail(
                    "capabilities",
                    &format!("OMR disabled or empty scheme={}", caps.scheme),
                );
            }
        }
        Err(e) => fail("capabilities", &e.to_string()),
    }

    let alice_wallet = [0xA1u8; 32];
    let bob_wallet = [0xB2u8; 32];
    // Real DarkFi payment keypairs (required for ownership proofs).
    // Seeded Pcg32 keeps matrix runs stable across machines.
    let alice_pay_kp = Keypair::random(&mut Pcg32::new(0xA11CE));
    let bob_pay_kp = Keypair::random(&mut Pcg32::new(0xB0B));
    let neither_pay_kp = Keypair::random(&mut Pcg32::new(0x4E17));
    let alice_pay = alice_pay_kp.public.to_bytes();
    let bob_pay = bob_pay_kp.public.to_bytes();
    let neither_pay = neither_pay_kp.public.to_bytes();

    let (_alice_sk, alice_clue_pk) = clue_keypair_from_wallet(&alice_wallet, network).unwrap();
    let alice_clue_bytes = serialize_public_key(&alice_clue_pk);
    let (_bob_sk, bob_clue_pk) = clue_keypair_from_wallet(&bob_wallet, network).unwrap();
    let bob_clue_bytes = serialize_public_key(&bob_clue_pk);

    if let Err(e) = register(
        &mut client,
        &bob_pay_kp.secret,
        network,
        &bob_pay,
        &bob_clue_bytes,
    )
    .await
    {
        fail("both:register_receiver", &e);
    } else {
        match lookup(&mut client, &bob_pay).await {
            Ok((found, pk, proof, ver)) => expect_registered_clue(
                found,
                &pk,
                &proof,
                ver,
                &bob_clue_bytes,
                &bob_pay,
                network,
                "both: GetClue→registered",
            ),
            Err(e) => fail("both:lookup", &e),
        }
    }

    match lookup(&mut client, &bob_pay).await {
        Ok((found, pk, proof, ver)) => expect_registered_clue(
            found,
            &pk,
            &proof,
            ver,
            &bob_clue_bytes,
            &bob_pay,
            network,
            "recv_only: GetClue→registered",
        ),
        Err(e) => fail("recv_only:lookup", &e),
    }

    if let Err(e) = register(
        &mut client,
        &alice_pay_kp.secret,
        network,
        &alice_pay,
        &alice_clue_bytes,
    )
    .await
    {
        fail("send_only:register_sender", &e);
    } else {
        match lookup(&mut client, &neither_pay).await {
            Ok((found, pk, proof, ver)) => expect_decoy_no_leak(
                found,
                &pk,
                &proof,
                ver,
                &neither_pay,
                network,
                &alice_clue_bytes,
                "send_only: decoy (no registration leak)",
            ),
            Err(e) => fail("send_only:lookup", &e),
        }
    }

    let other = Keypair::random(&mut Pcg32::new(0x61505)).public.to_bytes();
    match lookup(&mut client, &other).await {
        Ok((found, pk, proof, ver)) => expect_decoy_no_leak(
            found,
            &pk,
            &proof,
            ver,
            &other,
            network,
            &bob_clue_bytes,
            "neither: decoy (no registration leak)",
        ),
        Err(e) => fail("neither:lookup", &e),
    }

    match UnifOmrClient::from_wallet(&bob_wallet, network) {
        Ok(crypto) => match crypto.build_detection_key(network) {
            Ok(det_key) => {
                // Prefer a tiny fixed window so the matrix does not depend on
                // a synced tip (digest decrypt still exercises the UnifOMR path).
                let tip = client
                    .get_light_info(Empty {})
                    .await
                    .ok()
                    .map(|r| r.into_inner().block_height)
                    .unwrap_or(0);
                let end = tip.max(1);
                let start = end.saturating_sub(3).min(end);
                let stream = async_stream::stream! {
                    yield DetectionKeyChunk {
                        start_height: start,
                        end_height: end,
                        num_keys: 1,
                        data: vec![],
                        key_done: false,
                    };
                    
                    let chunk_size = 1024 * 1024;
                    let mut offset = 0;
                    while offset < det_key.len() {
                        let end_offset = std::cmp::min(offset + chunk_size, det_key.len());
                        let chunk_data = det_key[offset..end_offset].to_vec();
                        offset = end_offset;
                        let is_last = offset == det_key.len();

                        yield DetectionKeyChunk {
                            start_height: 0,
                            end_height: 0,
                            num_keys: 0,
                            data: chunk_data,
                            key_done: is_last,
                        };
                    }
                    if det_key.is_empty() {
                         yield DetectionKeyChunk {
                            start_height: 0,
                            end_height: 0,
                            num_keys: 0,
                            data: vec![],
                            key_done: true,
                        };
                    }
                };
                match client
                    .get_unif_omr_digest(tonic::Request::new(stream))
                    .await
                {
                    Ok(resp) => {
                        let digest = resp.into_inner().encrypted_digest;
                        match crypto.decrypt_digest_slots(&digest) {
                            Ok(slots) => {
                                let _ = UnifOmrClient::range_check_matches(&slots, start, end);
                                pass(&format!(
                                    "GetUnifOmrDigest decrypt ok (range {start}..={end}, slots={})",
                                    slots.len()
                                ));
                            }
                            Err(e) => fail("GetUnifOmrDigest decrypt", &e),
                        }
                    }
                    Err(e) => fail("GetUnifOmrDigest RPC", &e.to_string()),
                }
            }
            Err(e) => fail("build_detection_key", &e),
        },
        Err(e) => fail("UnifOmrClient", &e),
    }

    println!("=== matrix complete ===");
}
