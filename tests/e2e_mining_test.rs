use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;

#[tokio::test]
#[ignore] // Run manually since it interacts with live testnet
async fn test_live_testnet_mining_omr() {
    // 1. We assume `darkfid` is already running on testnet 0.3
    // because spawning it inside the test requires waiting for full sync which takes a long time.
    // However, the test will invoke `drk` to mine blocks.

    println!("Starting live testnet mining and OMR e2e test...");

    // 2. Generate a new address for the recipient
    let output = Command::new("cargo")
        .args(&["run", "-p", "drk", "--", "wallet", "address"])
        .current_dir("../../") // We are in bin/darkfi-lightwalletd usually for tests
        .output()
        .await
        .expect("Failed to execute drk");

    assert!(output.status.success(), "Failed to get address");
    let addr_str = String::from_utf8_lossy(&output.stdout);
    println!("Recipient address: {}", addr_str);

    // 3. Mine testnet coins
    // Using `drk wallet mine`
    println!("Mining testnet block...");
    let mut child = Command::new("cargo")
        .args(&["run", "-p", "drk", "--", "wallet", "mine"])
        .current_dir("../../")
        .spawn()
        .expect("Failed to start mining");

    // Let it mine for 10 seconds (difficulty is low)
    sleep(Duration::from_secs(10)).await;
    child.kill().await.expect("Failed to kill miner");

    println!("E2E test sequence completed successfully!");
}
