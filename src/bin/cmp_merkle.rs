//! Compare LWD Money Merkle reconstruction against darkfid `coin_roots`.
//! Temporary e2e diagnostic — not a shipping binary.

use std::collections::{BTreeMap, HashSet};

use darkfi::util::encoding::base64;
use darkfi_sdk::crypto::{MerkleNode, MerkleTree};
use darkfi_sdk::pasta::group::ff::Field;
use darkfi_sdk::pasta::pallas;
use darkfi_serial::{deserialize_async, Decodable};
use futures::StreamExt;
use tinyjson::JsonValue;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use darkfi_lightwalletd::proto::dark_fi_light_wallet_client::DarkFiLightWalletClient;
use darkfi_lightwalletd::proto::{BlockRange, Empty};

const MONEY: &str = "BZHKGQ26bzmBithTQYTJtjo2QdCqpkR9tjSBopT4yf4o";
const DARKFID: &str = "127.0.0.1:18345";
const LWD: &str = "http://127.0.0.1:9067";

async fn rpc(method: &str, params: JsonValue, timeout_s: u64) -> Result<JsonValue, String> {
    let mut stream = timeout(Duration::from_secs(timeout_s), TcpStream::connect(DARKFID))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_nodelay(true);
    let req = darkfi::rpc::jsonrpc::JsonRequest::new(method, params);
    let req_str = req.stringify().map_err(|e| e.to_string())?;
    timeout(Duration::from_secs(timeout_s), async {
        stream.write_all(req_str.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| "write timeout".to_string())?
    .map_err(|e| format!("write: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    timeout(Duration::from_secs(timeout_s), reader.read_line(&mut line))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    let parsed: JsonValue = line.parse().map_err(|e| format!("json: {e}"))?;
    let map = parsed
        .get::<std::collections::HashMap<String, JsonValue>>()
        .ok_or("expected object")?;
    if let Some(err) = map.get("error") {
        return Err(format!("rpc error: {err:?}"));
    }
    map.get("result").cloned().ok_or_else(|| "no result".to_string())
}

async fn contract_state(tree: &str) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, String> {
    let result = rpc(
        "blockchain.get_contract_state",
        JsonValue::Array(vec![
            JsonValue::String(MONEY.to_string()),
            JsonValue::String(tree.to_string()),
        ]),
        180,
    )
    .await?;
    let b64 = result.get::<String>().ok_or("expected b64")?;
    let bytes = base64::decode(b64).ok_or("b64 decode")?;
    deserialize_async(&bytes)
        .await
        .map_err(|e| format!("deserialize {tree}: {e}"))
}

async fn contract_key(tree: &str, key: &[u8]) -> Result<Vec<u8>, String> {
    let result = rpc(
        "blockchain.get_contract_state_key",
        JsonValue::Array(vec![
            JsonValue::String(MONEY.to_string()),
            JsonValue::String(tree.to_string()),
            JsonValue::String(base64::encode(key).to_string()),
        ]),
        30,
    )
    .await?;
    let b64 = result.get::<String>().ok_or("expected b64")?;
    base64::decode(b64).ok_or_else(|| "b64 decode".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let confirmed = rpc(
        "blockchain.last_confirmed_block",
        JsonValue::Array(vec![]),
        15,
    )
    .await?;
    println!("darkfid last_confirmed: {confirmed:?}");

    let last_root_val = contract_key("info", b"last_coins_root").await?;
    println!(
        "darkfid last_coins_root ({} bytes): {}",
        last_root_val.len(),
        hex::encode(&last_root_val)
    );

    let coins_tree_val = contract_key("info", b"coins_tree").await?;
    println!("darkfid coins_tree blob: {} bytes", coins_tree_val.len());
    if coins_tree_val.len() >= 4 {
        let set_size = u32::from_le_bytes(coins_tree_val[0..4].try_into()?);
        println!("darkfid coins_tree set_size prefix: {set_size}");
        let mut cur = std::io::Cursor::new(&coins_tree_val[4..]);
        match MerkleTree::decode(&mut cur) {
            Ok(t) => {
                let r = t.root(0);
                println!(
                    "darkfid coins_tree.root(0): {:?}",
                    r.map(|n| hex::encode(n.to_bytes()))
                );
            }
            Err(e) => println!("darkfid coins_tree decode err: {e}"),
        }
    }

    println!("fetching darkfid coin_roots (may take a bit)...");
    let coin_roots = contract_state("coin_roots").await?;
    let mut roots: HashSet<Vec<u8>> = HashSet::new();
    for k in coin_roots.keys() {
        roots.insert(k.clone());
    }
    println!("darkfid coin_roots entries: {}", roots.len());
    println!(
        "last_coins_root in coin_roots: {}",
        roots.contains(&last_root_val)
    );

    let coins_db = contract_state("coins").await;
    match coins_db {
        Ok(m) => println!("darkfid coins db entries: {}", m.len()),
        Err(e) => println!("darkfid coins db fetch err: {e}"),
    }

    let mut lwd = DarkFiLightWalletClient::connect(LWD.to_string()).await?;
    let tip = lwd.get_chain_tip(Empty {}).await?.into_inner();
    println!("LWD tip height={} hash={}", tip.height, hex::encode(&tip.hash));

    let st = lwd
        .get_tree_state(darkfi_lightwalletd::proto::BlockHeight { height: tip.height })
        .await?
        .into_inner();
    let server_tree: MerkleTree = Decodable::decode(&mut std::io::Cursor::new(&st.tree_data))?;
    let lwd_root = server_tree.root(0).expect("lwd root");
    let lwd_root_bytes = lwd_root.to_bytes().to_vec();
    println!("LWD GetTreeState.root(0): {}", hex::encode(&lwd_root_bytes));
    println!(
        "LWD root == darkfid last_coins_root: {}",
        lwd_root_bytes == last_root_val
    );
    println!(
        "LWD root in darkfid coin_roots: {}",
        roots.contains(&lwd_root_bytes)
    );

    // Rebuild from GetNoteCommitments and find first height whose root is not on chain.
    let mut tree = MerkleTree::new(u32::MAX as usize);
    tree.append(MerkleNode::from(pallas::Base::ZERO));
    let _ = tree.mark();
    let empty_root = tree.root(0).unwrap().to_bytes().to_vec();
    println!(
        "dummy-only root: {} in coin_roots={}",
        hex::encode(&empty_root),
        roots.contains(&empty_root)
    );

    let mut appended = 0u64;
    let mut last_ok = 0u32;
    let mut diverged: Option<u32> = None;
    const CHUNK: u32 = 4096;
    let mut start = 0u32;
    while start <= tip.height {
        let end = start.saturating_add(CHUNK - 1).min(tip.height);
        let mut stream = lwd
            .get_note_commitments(BlockRange {
                start_height: start,
                end_height: end,
            })
            .await?
            .into_inner();
        let mut by_h: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();
        while let Some(item) = stream.next().await {
            let nc = item?;
            by_h.entry(nc.height).or_default().extend(nc.coins);
        }
        for (h, coins) in by_h {
            for coin in coins {
                if coin.len() != 32 {
                    continue;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&coin);
                let Some(node) = MerkleNode::from_bytes(arr) else {
                    println!("bad coin at height {h}: {}", hex::encode(&arr));
                    continue;
                };
                tree.append(node);
                appended += 1;
            }
            let r = tree.root(0).unwrap().to_bytes().to_vec();
            if !roots.contains(&r) {
                diverged = Some(h);
                println!(
                    "DIVERGE at height {h} after {appended} coins; root={}",
                    hex::encode(&r)
                );
                break;
            }
            last_ok = h;
        }
        if diverged.is_some() {
            break;
        }
        eprintln!("  scanned {end}/{} appended={appended} last_ok={last_ok}", tip.height);
        start = end.saturating_add(1);
        if start == 0 {
            break;
        }
    }

    let final_root = tree.root(0).unwrap().to_bytes().to_vec();
    println!("rebuilt appended={appended}");
    println!("rebuilt root: {}", hex::encode(&final_root));
    println!(
        "rebuilt == LWD GetTreeState: {}",
        final_root == lwd_root_bytes
    );
    println!(
        "rebuilt in coin_roots: {}",
        roots.contains(&final_root)
    );
    match diverged {
        Some(h) => println!("FIRST DIVERGENCE HEIGHT: {h}"),
        None => println!("no per-height divergence (roots always in coin_roots after each height)"),
    }
    Ok(())
}
