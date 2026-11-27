#[allow(unused_imports)]
use super::*;
use crate::compact_block::{CompactBlock, CompactOutput, CompactTx};

/// sled's db flock is released when the last tree drops, which can lag
/// a few milliseconds behind `drop` while other tests are saturating the
/// machine. Retry only that contention.
fn reopen_cache(path: &str) -> Cache {
    let mut last = None;
    for _ in 0..40 {
        match Cache::new(path) {
            Ok(cache) => return cache,
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("could not acquire lock") {
                    panic!("reopen {path}: {e}");
                }
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
    panic!("sled lock not released for {path}: {last:?}");
}

/// Generate a deterministic 32-byte coin value that is always a valid
/// canonical `pallas::Base` field element.  We hash the height with
/// blake3 and clear the top two bits so the value is < p (the pallas
/// base-field modulus is ~2^254, so clearing bits 255+254 is sufficient).
fn make_valid_coin(height: u32) -> [u8; 32] {
    let mut coin = *blake3::hash(&height.to_le_bytes()).as_bytes();
    coin[31] &= 0x3F; // clear top 2 bits → value < 2^254 < p
    coin
}

fn make_test_block(height: u32) -> CompactBlock {
    CompactBlock {
        height,
        hash: [height as u8; 32],
        prev_hash: [height.wrapping_sub(1) as u8; 32],
        timestamp: 1000 + height as u64,
        txs: vec![CompactTx {
            tx_hash: [height as u8; 32],
            outputs: vec![CompactOutput {
                coin: make_valid_coin(height),
                encrypted_note: vec![0xAA; 100],
                value_commit: vec![0xBB; 33],
                token_commit: [0xCC; 32],
                omr_clue: vec![],
                omr_metadata_enc: vec![],
                func_code: 0,
            }],
            nullifiers: vec![[height as u8; 32]],
            fee: 100,
        }],
        dao_calls: vec![],
        func_events: vec![],
    }
}

fn make_empty_block(height: u32) -> CompactBlock {
    CompactBlock {
        height,
        hash: [height as u8; 32],
        prev_hash: [height.wrapping_sub(1) as u8; 32],
        timestamp: 1000 + height as u64,
        txs: vec![],
        dao_calls: vec![],
        func_events: vec![],
    }
}

fn make_multi_output_block(height: u32, n_outputs: usize) -> CompactBlock {
    let outputs = (0..n_outputs)
        .map(|i| CompactOutput {
            coin: make_valid_coin(height.wrapping_add(i as u32).wrapping_mul(1000)),
            encrypted_note: vec![0xAA; 100],
            value_commit: vec![0xBB; 33],
            token_commit: [0xCC; 32],
            omr_clue: vec![],
            omr_metadata_enc: vec![],
            func_code: 0,
        })
        .collect();
    CompactBlock {
        height,
        hash: [height as u8; 32],
        prev_hash: [height.wrapping_sub(1) as u8; 32],
        timestamp: 1000 + height as u64,
        txs: vec![CompactTx {
            tx_hash: [height as u8; 32],
            outputs,
            nullifiers: vec![],
            fee: 100,
        }],
        dao_calls: vec![],
        func_events: vec![],
    }
}

#[test]
fn missing_tip_block_is_repaired_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    {
        let cache = Cache::new(&path).unwrap();
        cache.insert_compact_block(&make_test_block(0)).unwrap();
        cache.insert_compact_block(&make_test_block(1)).unwrap();
        cache.insert_compact_block(&make_test_block(2)).unwrap();
        assert_eq!(cache.get_tip().unwrap().unwrap().0, 2);
    }
    {
        let db = sled::open(&path).unwrap();
        let blocks = db.open_tree("lightwalletd_compact_blocks").unwrap();
        blocks.remove(2u32.to_be_bytes()).unwrap();
        db.flush().unwrap();
    }
    let cache = Cache::new(&path).unwrap();
    let (height, _) = cache.get_tip().unwrap().unwrap();
    assert_eq!(height, 1);
    assert!(cache.get_compact_block(2).unwrap().is_none());
    assert!(cache.get_compact_block(1).unwrap().is_some());
}

#[test]
fn tip_chain_facts_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    let hash = [7u8; 32];
    assert!(cache.tip_chain_facts_for(1, &hash).unwrap().is_none());
    cache.set_tip_chain_facts(1, &hash, 20, "123").unwrap();
    assert_eq!(
        cache.tip_chain_facts_for(1, &hash).unwrap().unwrap(),
        (20, "123".into())
    );
    assert!(cache.tip_chain_facts_for(2, &hash).unwrap().is_none());
    assert!(cache.tip_chain_facts_for(1, &[8u8; 32]).unwrap().is_none());
}

#[test]
fn interrupted_rewind_resumes_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    {
        let cache = Cache::new(&path).unwrap();
        cache.insert_compact_block(&make_test_block(0)).unwrap();
        cache.insert_compact_block(&make_test_block(1)).unwrap();
        cache.insert_compact_block(&make_test_block(2)).unwrap();
    }
    {
        let db = sled::open(&path).unwrap();
        let meta = db.open_tree(META_TREE).unwrap();
        meta.insert(META_REWINDING_TO, &1u32.to_be_bytes()).unwrap();
        db.flush().unwrap();
    }
    let cache = reopen_cache(&path);
    let (height, _) = cache.get_tip().unwrap().unwrap();
    assert_eq!(height, 1);
    assert!(cache.get_compact_block(2).unwrap().is_none());
    assert!(cache.get_compact_block(1).unwrap().is_some());
    assert!(cache.meta.get(META_REWINDING_TO).unwrap().is_none());
}

#[test]
fn first_missing_hash_finds_a_hole() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    cache.insert_compact_block(&make_test_block(0)).unwrap();
    cache.insert_compact_block(&make_test_block(1)).unwrap();
    cache.insert_compact_block(&make_test_block(3)).unwrap();
    assert_eq!(cache.first_missing_hash(0, 3).unwrap(), Some(2));
    assert_eq!(cache.first_missing_hash(0, 1).unwrap(), None);
}

#[test]
fn tip_fetched_unix_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    assert_eq!(cache.tip_fetched_unix().unwrap(), 0);
    cache.set_tip_fetched_unix(1_700_000_000).unwrap();
    assert_eq!(cache.tip_fetched_unix().unwrap(), 1_700_000_000);
}

#[test]
fn test_notes_range_includes_empty_heights() {
    // S19: empty / missing heights must still occupy a slot.
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    cache.insert_compact_block(&make_test_block(10)).unwrap();
    cache.insert_compact_block(&make_empty_block(11)).unwrap();
    cache.insert_compact_block(&make_test_block(12)).unwrap();

    let notes = cache.get_encrypted_notes_range(10, 13).unwrap();
    assert_eq!(notes.len(), 4);
    assert_eq!(notes[0].0, 10);
    assert_eq!(notes[0].1.len(), 1);
    assert_eq!(notes[1].0, 11);
    assert!(notes[1].1.is_empty());
    assert_eq!(notes[2].0, 12);
    assert_eq!(notes[2].1.len(), 1);
    assert_eq!(notes[3].0, 13);
    assert!(notes[3].1.is_empty());
}

#[test]
fn test_notes_range_skips_ciphertext_when_clue_present() {
    // P2: detector path only needs encrypted_note when omr_clue is empty.
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let mut with_clue = make_test_block(20);
    with_clue.txs[0].outputs[0].omr_clue = vec![0x11; 16];
    let mut no_clue = make_test_block(21);
    no_clue.txs[0].outputs[0].omr_clue.clear();

    cache.insert_compact_block(&with_clue).unwrap();
    cache.insert_compact_block(&no_clue).unwrap();

    let notes = cache.get_encrypted_notes_range(20, 21).unwrap();
    assert!(notes[0].1[0].encrypted_note.is_empty());
    assert!(!notes[0].1[0].omr_clue.is_empty());
    assert!(!notes[1].1[0].encrypted_note.is_empty());
    assert!(notes[1].1[0].omr_clue.is_empty());
}

#[test]
fn test_omr_clue_hint_first_writer_wins() {
    // S3: existing clue must not be overwritten.
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let tx_hash = [9u8; 32];
    let first = vec![0xAAu8; 16];
    let second = vec![0xBBu8; 16];
    cache
        .store_omr_clue_hint(&tx_hash, first.clone(), None)
        .unwrap();
    assert!(cache.has_omr_clue_hint(&tx_hash).unwrap());

    // Simulate server first-writer-wins: skip store when hint exists.
    if !cache.has_omr_clue_hint(&tx_hash).unwrap() {
        cache
            .store_omr_clue_hint(&tx_hash, second.clone(), None)
            .unwrap();
    }

    // Apply to block and verify first clue was kept.
    let mut block = make_multi_output_block(1, 1);
    block.txs[0].tx_hash = tx_hash;
    cache.apply_omr_clue_hints(&mut block).unwrap();
    assert_eq!(block.txs[0].outputs[0].omr_clue, first);
    assert_ne!(block.txs[0].outputs[0].omr_clue, second);
}

#[test]
fn test_omr_clue_hint_applies_to_first_empty_only() {
    // S20: one clue must not be copied onto every empty output.
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let clue = vec![0x42u8; 16];
    let tx_hash = [7u8; 32];
    cache
        .store_omr_clue_hint(&tx_hash, clue.clone(), None)
        .unwrap();

    let mut block = make_multi_output_block(1, 3);
    block.txs[0].tx_hash = tx_hash;
    cache.apply_omr_clue_hints(&mut block).unwrap();

    assert_eq!(block.txs[0].outputs[0].omr_clue, clue);
    assert!(block.txs[0].outputs[1].omr_clue.is_empty());
    assert!(block.txs[0].outputs[2].omr_clue.is_empty());
    assert!(
        cache.has_omr_clue_hint(&tx_hash).unwrap(),
        "hint kept until TTL"
    );

    // Re-applying to an already-merged block must not attach it again.
    cache.apply_omr_clue_hints(&mut block).unwrap();
    assert_eq!(block.txs[0].outputs[0].omr_clue, clue);
    assert!(block.txs[0].outputs[1].omr_clue.is_empty());
    assert!(block.txs[0].outputs[2].omr_clue.is_empty());
}

#[test]
fn test_same_clue_bytes_apply_to_each_named_output() {
    // Change and fee hints are encryptions to the same key and may share
    // bytes. Each named output still needs its own copy or that output
    // is absent from the digest.
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let clue = vec![0x42u8; 16];
    let tx_hash = [8u8; 32];
    cache
        .store_omr_clue_hint(&tx_hash, clue.clone(), Some(1))
        .unwrap();
    cache
        .store_omr_clue_hint(&tx_hash, clue.clone(), Some(2))
        .unwrap();

    let mut block = make_multi_output_block(1, 3);
    block.txs[0].tx_hash = tx_hash;
    cache.apply_omr_clue_hints(&mut block).unwrap();

    assert!(block.txs[0].outputs[0].omr_clue.is_empty());
    assert_eq!(block.txs[0].outputs[1].omr_clue, clue);
    assert_eq!(block.txs[0].outputs[2].omr_clue, clue);
}

#[test]
fn test_omr_clue_hint_survives_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..5 {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }
    let clue = vec![0x5Au8; 16];
    let mut block = make_multi_output_block(5, 2);
    let tx_hash = [0xE5u8; 32];
    block.txs[0].tx_hash = tx_hash;
    cache
        .store_omr_clue_hint(&tx_hash, clue.clone(), None)
        .unwrap();

    cache.insert_compact_block(&block).unwrap();
    let stored = cache.get_compact_block(5).unwrap().unwrap();
    assert_eq!(stored.txs[0].outputs[0].omr_clue, clue);

    cache.rewind_to_height(4).unwrap();
    assert!(cache.get_compact_block(5).unwrap().is_none());

    // darkfid re-serves the block without clues.
    cache.insert_compact_block(&block).unwrap();
    let stored = cache.get_compact_block(5).unwrap().unwrap();
    assert_eq!(stored.txs[0].outputs[0].omr_clue, clue);
    assert!(stored.txs[0].outputs[1].omr_clue.is_empty());
}

#[test]
fn test_omr_clue_hint_applies_to_explicit_output_index() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let clue = vec![0x99u8; 16];
    let tx_hash = [8u8; 32];
    cache
        .store_omr_clue_hint(&tx_hash, clue.clone(), Some(2))
        .unwrap();

    let mut block = make_multi_output_block(1, 3);
    block.txs[0].tx_hash = tx_hash;
    cache.apply_omr_clue_hints(&mut block).unwrap();

    assert!(block.txs[0].outputs[0].omr_clue.is_empty());
    assert!(block.txs[0].outputs[1].omr_clue.is_empty());
    assert_eq!(block.txs[0].outputs[2].omr_clue, clue);
}

#[test]
fn test_cache_insert_and_retrieve() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let block = make_test_block(42);
    cache.insert_compact_block(&block).unwrap();

    let retrieved = cache.get_compact_block(42).unwrap().unwrap();
    assert_eq!(retrieved.height, 42);
    assert_eq!(retrieved.hash, block.hash);
    assert_eq!(retrieved.txs.len(), 1);

    let tip = cache.get_tip().unwrap().unwrap();
    assert_eq!(tip.0, 42);
    assert_eq!(tip.1, block.hash);
}

#[test]
fn test_cache_range_query() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..10 {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }

    let range = cache.get_compact_blocks_range(3, 7).unwrap();
    assert_eq!(range.len(), 5);
    assert_eq!(range[0].height, 3);
    assert_eq!(range[4].height, 7);
}

#[test]
fn test_cache_rewind() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..10 {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }

    cache.rewind_to_height(5).unwrap();

    // Blocks 0-5 should exist
    assert!(cache.get_compact_block(5).unwrap().is_some());
    // Blocks 6-9 should be deleted
    assert!(cache.get_compact_block(6).unwrap().is_none());
    assert!(cache.get_compact_block(9).unwrap().is_none());

    let tip = cache.get_tip().unwrap().unwrap();
    assert_eq!(tip.0, 5);
}

#[test]
fn historical_genesis_insert_does_not_rewind_tip() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    cache.insert_compact_block(&make_test_block(1)).unwrap();
    cache.insert_compact_block(&make_test_block(2)).unwrap();
    assert_eq!(cache.get_tip().unwrap().unwrap().0, 2);

    cache.insert_compact_block(&make_test_block(0)).unwrap();
    assert_eq!(
        cache.get_tip().unwrap().unwrap().0,
        2,
        "backfilling height 0 must not rewind tip"
    );
    assert!(cache.get_compact_block(0).unwrap().is_some());
    let backfilled = cache.get_tip_tree_state().unwrap().unwrap().1;

    let dir_seq = tempfile::tempdir().unwrap();
    let sequential = Cache::new(dir_seq.path().to_str().unwrap()).unwrap();
    for h in 0..3 {
        sequential
            .insert_compact_block(&make_test_block(h))
            .unwrap();
    }
    assert_eq!(
        sequential.get_tip_tree_state().unwrap().unwrap().1,
        backfilled,
        "backfill must replay coins after the surviving snapshot"
    );
}

#[test]
fn test_cache_prune_below_height() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..20 {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }

    // Prune blocks below height 10
    cache.prune_below_height(10).unwrap();

    // Blocks 0-9 should be deleted
    for h in 0..10 {
        assert!(
            cache.get_compact_block(h).unwrap().is_none(),
            "Block {h} should have been pruned"
        );
    }

    // Blocks 10-19 should still exist
    for h in 10..20 {
        assert!(
            cache.get_compact_block(h).unwrap().is_some(),
            "Block {h} should still exist"
        );
    }

    // Tip should be unchanged
    let tip = cache.get_tip().unwrap().unwrap();
    assert_eq!(tip.0, 19);
}

#[test]
fn test_cache_prune_with_retention() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..100 {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }

    // Prune with retention window of 50 (tip=99, prune below 49)
    cache.prune_with_retention(50).unwrap();

    // Block 48 should be pruned
    assert!(cache.get_compact_block(48).unwrap().is_none());
    // Block 49 should still exist
    assert!(cache.get_compact_block(49).unwrap().is_some());
    // Block 99 should still exist
    assert!(cache.get_compact_block(99).unwrap().is_some());
}

#[test]
fn snapshot_retained_on_interval_and_tip_rewind_drops_higher_prune_keeps() {
    // CompactBlock does not carry the block header's money-tree root, so
    // snapshot state_root stays blake3(tree_data). See the server snapshot
    // test — do not invent a second root here.
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..=(MERKLE_SNAPSHOT_INTERVAL + 1) {
        cache.insert_compact_block(&make_empty_block(h)).unwrap();
    }
    let tip = MERKLE_SNAPSHOT_INTERVAL + 1;
    assert_eq!(cache.get_tip().unwrap().unwrap().0, tip);
    assert_eq!(
        cache.snapshot_heights().unwrap(),
        vec![0, MERKLE_SNAPSHOT_INTERVAL, tip],
        "interval boundary and the current tip, not every height"
    );
    let (meta_h, meta_tree) = cache.get_tip_tree_state().unwrap().unwrap();
    assert_eq!(meta_h, tip);
    assert_eq!(cache.merkle_snapshot(tip).unwrap().unwrap(), meta_tree);

    cache.rewind_to_height(1000).unwrap();
    assert_eq!(cache.get_tip().unwrap().unwrap().0, 1000);
    assert!(cache.get_compact_block(tip).unwrap().is_none());
    assert!(cache
        .merkle_snapshot(MERKLE_SNAPSHOT_INTERVAL)
        .unwrap()
        .is_none());
    assert!(cache.merkle_snapshot(tip).unwrap().is_none());
    assert_eq!(cache.snapshot_heights().unwrap(), vec![0, 1000]);
    assert!(cache.merkle_snapshot(0).unwrap().is_some());

    cache.prune_below_height(10).unwrap();
    assert!(
        cache.get_compact_block(0).unwrap().is_none(),
        "prune drops the compact block"
    );
    assert!(
        cache.merkle_snapshot(0).unwrap().is_some(),
        "prune keeps the snapshot"
    );
    assert!(cache.merkle_snapshot(1000).unwrap().is_some());
    assert_eq!(cache.snapshot_heights().unwrap(), vec![0, 1000]);
}

#[test]
fn test_cache_prune_zero_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    cache.insert_compact_block(&make_test_block(0)).unwrap();
    cache.prune_below_height(0).unwrap();

    // Block 0 should still exist
    assert!(cache.get_compact_block(0).unwrap().is_some());
}

#[test]
fn test_cache_overwrite_same_height() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let block_v1 = make_test_block(100);
    cache.insert_compact_block(&block_v1).unwrap();

    // Insert a different block at the same height (simulate reorg)
    let mut block_v2 = make_test_block(100);
    block_v2.hash = [0xFF; 32]; // different hash
    cache.insert_compact_block(&block_v2).unwrap();

    let retrieved = cache.get_compact_block(100).unwrap().unwrap();
    assert_eq!(retrieved.hash, [0xFF; 32], "latest insert should win");
}

#[test]
fn test_cache_range_ordering_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    // Insert out of order
    for h in [5u32, 3, 1, 4, 2] {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }

    let range = cache.get_compact_blocks_range(1, 5).unwrap();
    assert_eq!(range.len(), 5);
    for (i, block) in range.iter().enumerate() {
        assert_eq!(
            block.height,
            (i + 1) as u32,
            "blocks should be in ascending order"
        );
    }
}

#[test]
fn test_clue_public_key_roundtrip_strips_u64_version() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let payment_pk = [0x11u8; 32];
    // Realistic UnifOMR wire length (n=1024 → 4 + 16*1024); pattern must
    // not accidentally equal a 4-byte-strip mis-read of version||key.
    let clue_pk: Vec<u8> = (0..16_388u32).map(|i| (i % 251) as u8).collect();
    let key_version = 1_785_630_000u64; // LE: low 4 nonzero, high 4 zero
    let proof = vec![0xABu8; 64];

    cache
        .store_clue_public_key(&payment_pk, &clue_pk, key_version, &proof)
        .unwrap();
    let got = cache.get_clue_public_key(&payment_pk).unwrap().unwrap();
    assert_eq!(got, clue_pk, "must return clue_pk without framing");

    let (ver, got_proof, got_clue) = cache
        .get_clue_public_key_entry(&payment_pk)
        .unwrap()
        .unwrap();
    assert_eq!(ver, key_version);
    assert_eq!(got_proof, proof);
    assert_eq!(got_clue, clue_pk);

    // Same version + same key is idempotent.
    cache
        .store_clue_public_key(&payment_pk, &clue_pk, key_version, &proof)
        .unwrap();
    assert_eq!(
        cache.get_clue_public_key(&payment_pk).unwrap().unwrap(),
        clue_pk
    );
}

#[test]
fn empty_tip_tree_matches_wallet_zero_sentinel() {
    use darkfi_sdk::crypto::{MerkleNode, MerkleTree};
    use darkfi_sdk::pasta::group::ff::Field;
    use darkfi_sdk::pasta::pallas;
    let tip = Cache::empty_tip_tree();
    let mut wallet = MerkleTree::new(u32::MAX as usize);
    wallet.append(MerkleNode::from(pallas::Base::ZERO));
    assert_eq!(tip.root(0).unwrap(), wallet.root(0).unwrap());
}

#[test]
fn coin_to_merkle_node_accepts_canonical_bytes() {
    let coin = make_valid_coin(7);
    assert!(Cache::coin_to_merkle_node(&coin).is_ok());
    let mut bad = [0xFFu8; 32];
    bad[31] = 0xFF;
    // All-0xFF is not a canonical pallas::Base.
    assert!(Cache::coin_to_merkle_node(&bad).is_err());
}

#[test]
fn tip_merkle_reloads_across_restart() {
    let dir_fresh = tempfile::tempdir().unwrap();
    let dir_restart = tempfile::tempdir().unwrap();
    let fresh = Cache::new(dir_fresh.path().to_str().unwrap()).unwrap();
    for h in 0..6 {
        fresh.insert_compact_block(&make_test_block(h)).unwrap();
    }
    {
        let cache = Cache::new(dir_restart.path().to_str().unwrap()).unwrap();
        for h in 0..3 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }
        cache.flush().unwrap();
    }
    let restarted = reopen_cache(dir_restart.path().to_str().unwrap());
    for h in 3..6 {
        restarted.insert_compact_block(&make_test_block(h)).unwrap();
    }
    assert_eq!(
        fresh.get_tip_tree_state().unwrap(),
        restarted.get_tip_tree_state().unwrap()
    );
}

#[test]
fn expired_omr_clue_hint_dropped_on_read_without_full_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    let tx_hash = [0x42u8; 32];
    cache
        .store_omr_clue_hint(&tx_hash, vec![1, 2, 3], Some(0))
        .unwrap();
    assert!(cache.has_omr_clue_hint(&tx_hash).unwrap());
    cache.omr_hint_sweep_unix.store(u64::MAX, Ordering::Relaxed);
    cache
        .omr_clue_hint_meta
        .insert(tx_hash.as_slice(), &0u64.to_le_bytes())
        .unwrap();
    assert!(!cache.has_omr_clue_hint(&tx_hash).unwrap());
    assert!(!cache
        .omr_clue_hints
        .contains_key(tx_hash.as_slice())
        .unwrap());
    assert!(!cache.omr_clue_index_taken(&tx_hash, 0).unwrap());
}

#[test]
fn cache_format_stamped_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap();
    let cache = Cache::new(path).unwrap();
    let raw = cache
        .meta
        .get(META_CACHE_FORMAT)
        .unwrap()
        .expect("format key");
    let ver = u32::from_be_bytes(raw.as_ref().try_into().unwrap());
    assert_eq!(ver, CACHE_FORMAT_VERSION);
    drop(cache);
    let _reopen = reopen_cache(path);
}

#[test]
fn clue_key_version_one_replaces_proof_and_rejects_conflicts() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    let payment_pk = [0x22u8; 32];
    let clue = vec![1u8, 2, 3, 4];
    assert!(cache
        .store_clue_public_key(&payment_pk, &clue, 0, &[1])
        .is_err());
    cache
        .store_clue_public_key(&payment_pk, &clue, 1, &[9])
        .unwrap();
    cache
        .store_clue_public_key(&payment_pk, &clue, 1, &[8, 8])
        .unwrap();
    let (ver, proof, got) = cache
        .get_clue_public_key_entry(&payment_pk)
        .unwrap()
        .unwrap();
    assert_eq!(ver, 1);
    assert_eq!(proof, vec![8, 8]);
    assert_eq!(got, clue);
    assert!(cache
        .store_clue_public_key(&payment_pk, &[9], 1, &[1])
        .is_err());
    cache
        .store_clue_public_key(&payment_pk, &[7], 2, &[3])
        .unwrap();
    let (ver, _, got) = cache
        .get_clue_public_key_entry(&payment_pk)
        .unwrap()
        .unwrap();
    assert_eq!(ver, 2);
    assert_eq!(got, vec![7]);
    assert!(cache
        .store_clue_public_key(&payment_pk, &[7], 1, &[3])
        .is_err());
}

#[test]
fn obsolete_v1_attest_key_is_deleted_and_v2_rows_move() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap();
    {
        let db = sled::open(path).unwrap();
        let meta = db.open_tree(META_TREE).unwrap();
        meta.insert(b"unifomr_dir_attest_sk_v1", &[9u8; 32])
            .unwrap();
        meta.insert(b"unifomr_dir_attest_sk_v2", &[3u8; 32])
            .unwrap();
        meta.insert(b"unifomr_clue_dir_pepper_v1", &[4u8; 32])
            .unwrap();
        meta.insert(b"unifomr_clue_dir_pepper_anchor_v1", &1u64.to_le_bytes())
            .unwrap();
        let old = db.open_tree("lightwalletd_omr_clue_pubkeys_v2").unwrap();
        let mut value = Vec::new();
        value.extend_from_slice(b"v3");
        value.extend_from_slice(&1u64.to_le_bytes());
        value.extend_from_slice(&1u32.to_le_bytes());
        value.push(0xAB);
        value.push(0xCD);
        old.insert([1u8; 32], value).unwrap();
        db.flush().unwrap();
    }
    let cache = reopen_cache(path);
    assert!(cache
        .meta
        .get(b"unifomr_dir_attest_sk_v1")
        .unwrap()
        .is_none());
    assert!(cache
        .meta
        .get(b"unifomr_dir_attest_sk_v2")
        .unwrap()
        .is_none());
    assert_eq!(
        cache
            .meta
            .get(b"unifomr_dir_attest_sk")
            .unwrap()
            .unwrap()
            .as_ref(),
        &[3u8; 32]
    );
    assert_eq!(
        cache
            .meta
            .get(META_CLUE_DIR_PEPPER)
            .unwrap()
            .unwrap()
            .as_ref(),
        &[4u8; 32]
    );
    assert!(cache
        .meta
        .get(b"unifomr_clue_dir_pepper_anchor_v1")
        .unwrap()
        .is_none());
    assert!(!cache.tree_exists("lightwalletd_omr_clue_pubkeys_v2"));
    let (ver, proof, clue) = cache
        .get_clue_public_key_entry(&[1u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(ver, 1);
    assert_eq!(proof, vec![0xAB]);
    assert_eq!(clue, vec![0xCD]);
    drop(cache);
    let again = reopen_cache(path);
    assert_eq!(
        again
            .meta
            .get(b"unifomr_dir_attest_sk")
            .unwrap()
            .unwrap()
            .as_ref(),
        &[3u8; 32]
    );
}

#[test]
fn same_height_overwrite_does_not_duplicate_merkle_leaves() {
    let once_dir = tempfile::tempdir().unwrap();
    let twice_dir = tempfile::tempdir().unwrap();
    let once = Cache::new(once_dir.path().to_str().unwrap()).unwrap();
    once.insert_compact_block(&make_test_block(0)).unwrap();
    let twice = Cache::new(twice_dir.path().to_str().unwrap()).unwrap();
    twice.insert_compact_block(&make_test_block(0)).unwrap();
    let mut again = make_test_block(0);
    again.hash = [0xAB; 32];
    twice.insert_compact_block(&again).unwrap();
    assert_eq!(
        once.get_tip_tree_state().unwrap(),
        twice.get_tip_tree_state().unwrap()
    );
}

#[test]
fn corrupt_tip_tree_is_rebuilt_before_append() {
    let broken_dir = tempfile::tempdir().unwrap();
    let fresh_dir = tempfile::tempdir().unwrap();
    let broken_path = broken_dir.path().to_str().unwrap();
    {
        let cache = Cache::new(broken_path).unwrap();
        for h in 0..4 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }
        cache
            .meta
            .insert(META_TIP_MERKLE_TREE, b"not-a-tree")
            .unwrap();
        cache.flush().unwrap();
    }
    let cache = reopen_cache(broken_path);
    cache.insert_compact_block(&make_test_block(4)).unwrap();
    let fresh = Cache::new(fresh_dir.path().to_str().unwrap()).unwrap();
    for h in 0..5 {
        fresh.insert_compact_block(&make_test_block(h)).unwrap();
    }
    assert_eq!(
        cache.get_tip_tree_state().unwrap(),
        fresh.get_tip_tree_state().unwrap()
    );
}

#[test]
fn omr_metadata_enc_survives_reorg_and_expires_on_ttl_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..4 {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }
    let tx_hash = [0xE7u8; 32];
    let memo = b"encrypted-recipient-memo-payload".to_vec();
    cache
        .store_omr_metadata_enc(&tx_hash, memo.clone(), Some(0))
        .unwrap();
    assert!(cache.has_omr_metadata_enc(&tx_hash).unwrap());

    let mut block = make_multi_output_block(4, 2);
    block.txs[0].tx_hash = tx_hash;

    // First confirm merges the memo and retains it for potential reorgs.
    cache.insert_compact_block(&block).unwrap();
    let stored = cache.get_compact_block(4).unwrap().unwrap();
    assert_eq!(stored.txs[0].outputs[0].omr_metadata_enc, memo);
    assert!(stored.txs[0].outputs[1].omr_metadata_enc.is_empty());
    assert!(
        cache.has_omr_metadata_enc(&tx_hash).unwrap(),
        "metadata_enc must be retained until TTL expiry"
    );

    // Reorg rewinds block 4, then darkfid re-serves it without metadata.
    cache.rewind_to_height(3).unwrap();
    assert!(cache.get_compact_block(4).unwrap().is_none());
    cache.insert_compact_block(&block).unwrap();
    let remerged = cache.get_compact_block(4).unwrap().unwrap();
    assert_eq!(
        remerged.txs[0].outputs[0].omr_metadata_enc, memo,
        "memo must re-merge after reorg"
    );

    // Expire past the 24h TTL and verify sweep removes both data and timestamp rows.
    let now = omr_hint_unix_now();
    let expired_ts = now.saturating_sub(OMR_CLUE_HINT_TTL_SECS + 10);
    cache
        .omr_metadata_enc_meta
        .insert(tx_hash.as_slice(), &expired_ts.to_le_bytes())
        .unwrap();
    cache.sweep_expired_omr_clue_hints_at(now).unwrap();
    assert!(!cache.has_omr_metadata_enc(&tx_hash).unwrap());
    assert!(cache
        .omr_metadata_enc
        .get(tx_hash.as_slice())
        .unwrap()
        .is_none());
    assert!(cache
        .omr_metadata_enc_meta
        .get(tx_hash.as_slice())
        .unwrap()
        .is_none());
}

#[test]
fn omr_metadata_enc_row_without_ttl_counts_as_expired() {
    let now = 1_000_000u64;
    assert!(!omr_metadata_enc_row_expired(Some(&now.to_le_bytes()), now));
    let still_live = now - OMR_CLUE_HINT_TTL_SECS;
    assert!(!omr_metadata_enc_row_expired(
        Some(&still_live.to_le_bytes()),
        now
    ));
    let expired = still_live - 1;
    assert!(omr_metadata_enc_row_expired(
        Some(&expired.to_le_bytes()),
        now
    ));
    assert!(omr_metadata_enc_row_expired(Some(&[1, 2, 3]), now));
    assert!(omr_metadata_enc_row_expired(None, now));
}

#[test]
fn omr_metadata_enc_rejects_a_new_tx_when_entry_cap_is_full() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    cache.set_max_omr_metadata_enc_entries(1);

    let first = [0x31u8; 32];
    let second = [0x32u8; 32];
    cache
        .store_omr_metadata_enc(&first, b"memo-1".to_vec(), Some(0))
        .unwrap();
    let err = cache
        .store_omr_metadata_enc(&second, b"memo-2".to_vec(), Some(0))
        .unwrap_err();
    assert!(
        err.to_string().contains("omr metadata registry is full"),
        "{err}"
    );
    assert!(cache.has_omr_metadata_enc(&first).unwrap());
    assert!(!cache.has_omr_metadata_enc(&second).unwrap());

    // Replacing the live hash does not need a free slot.
    cache
        .store_omr_metadata_enc(&first, b"memo-1b".to_vec(), Some(1))
        .unwrap();
    assert!(cache.has_omr_metadata_enc(&first).unwrap());
    assert!(!cache.has_omr_metadata_enc(&second).unwrap());
}

#[test]
fn legacy_omr_metadata_enc_without_meta_does_not_survive_startup_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap();
    let legacy = [0x11u8; 32];
    let live = [0x22u8; 32];
    {
        let db = sled::open(path).unwrap();
        let data = db.open_tree(OMR_METADATA_ENC_TREE).unwrap();
        let meta = db.open_tree(OMR_METADATA_ENC_META_TREE).unwrap();
        let mut legacy_row = 0u32.to_le_bytes().to_vec();
        legacy_row.extend_from_slice(b"legacy-memo");
        data.insert(legacy, legacy_row).unwrap();
        let mut live_row = 0u32.to_le_bytes().to_vec();
        live_row.extend_from_slice(b"live-memo");
        data.insert(live, live_row).unwrap();
        meta.insert(live, &omr_hint_unix_now().to_le_bytes())
            .unwrap();
        db.flush().unwrap();
    }

    let cache = reopen_cache(path);
    assert!(
        cache.omr_metadata_enc.get(legacy).unwrap().is_none(),
        "legacy ciphertext with no TTL must be deleted on startup sweep"
    );
    assert!(cache.omr_metadata_enc_meta.get(legacy).unwrap().is_none());
    assert!(
        cache.has_omr_metadata_enc(&live).unwrap(),
        "a row with a fresh TTL survives the same sweep"
    );
}

#[test]
fn legacy_omr_metadata_enc_without_meta_is_dropped_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    let legacy = [0x44u8; 32];
    let mut row = 0u32.to_le_bytes().to_vec();
    row.extend_from_slice(b"legacy-memo");
    cache.omr_metadata_enc.insert(legacy, row).unwrap();

    assert!(!cache.has_omr_metadata_enc(&legacy).unwrap());
    assert!(cache.omr_metadata_enc.get(legacy).unwrap().is_none());

    // The uncounted delete must not wrap the admission counter.
    cache
        .store_omr_metadata_enc(&legacy, b"fresh".to_vec(), Some(0))
        .unwrap();
    assert!(cache.has_omr_metadata_enc(&legacy).unwrap());
}

#[test]
fn rewind_to_height_sweeps_every_derived_tree_and_handles_u32_max() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    for h in 0..=5u32 {
        cache.insert_compact_block(&make_test_block(h)).unwrap();
    }
    // Simulate a crash mid-rewind: compact_blocks[4] and [5] were deleted,
    // leaving orphan rows in block_hashes, hash_to_height, nullifiers, coins.
    cache.compact_blocks.remove(4u32.to_be_bytes()).unwrap();
    cache.compact_blocks.remove(5u32.to_be_bytes()).unwrap();
    let orphan_hash4 = [4u8; 32];
    let orphan_hash5 = [5u8; 32];
    assert!(cache.get_block_hash(4).unwrap().is_some());
    assert!(cache.nullifiers.get(5u32.to_be_bytes()).unwrap().is_some());
    assert!(cache.coins.get(5u32.to_be_bytes()).unwrap().is_some());

    cache.rewind_to_height(2).unwrap();

    assert_eq!(cache.get_tip().unwrap().unwrap().0, 2);
    for h in 3..=5u32 {
        assert!(cache.get_compact_block(h).unwrap().is_none());
        assert!(cache.get_block_hash(h).unwrap().is_none());
        assert!(cache.nullifiers.get(h.to_be_bytes()).unwrap().is_none());
        assert!(cache.coins.get(h.to_be_bytes()).unwrap().is_none());
    }
    assert!(cache.hash_to_height.get(orphan_hash4).unwrap().is_none());
    assert!(cache.hash_to_height.get(orphan_hash5).unwrap().is_none());

    // u32::MAX must not overflow `height + 1`; with no block at u32::MAX it
    // cleanly repairs to the highest block still on disk (height 2).
    cache.rewind_to_height(u32::MAX).unwrap();
    assert_eq!(cache.get_tip().unwrap().unwrap().0, 2);
}

#[test]
fn insert_overwrite_cleans_stale_hash_nullifiers_and_coins() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();

    let original = make_test_block(0);
    let old_hash = original.hash;
    cache.insert_compact_block(&original).unwrap();
    assert!(cache.hash_to_height.get(old_hash).unwrap().is_some());
    assert!(cache.nullifiers.get(0u32.to_be_bytes()).unwrap().is_some());
    assert!(cache.coins.get(0u32.to_be_bytes()).unwrap().is_some());

    // Overwrite height 0 with an empty block and a new hash.
    let mut replacement = make_empty_block(0);
    replacement.hash = [0xEE; 32];
    cache.insert_compact_block(&replacement).unwrap();

    assert!(cache.hash_to_height.get(old_hash).unwrap().is_none());
    assert_eq!(
        cache
            .hash_to_height
            .get([0xEE; 32])
            .unwrap()
            .unwrap()
            .as_ref(),
        &0u32.to_be_bytes()
    );
    assert!(cache.nullifiers.get(0u32.to_be_bytes()).unwrap().is_none());
    assert!(cache.coins.get(0u32.to_be_bytes()).unwrap().is_none());
    // Tip tree should now equal the empty sentinel tree (no coins left at height 0).
    let (_, tree_data) = cache.get_tip_tree_state().unwrap().unwrap();
    assert_eq!(
        tree_data,
        darkfi_serial::serialize(&Cache::empty_tip_tree())
    );
}

#[test]
fn open_reconciles_tip_merkle_mismatch_and_empty_reset_clears_merkle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    let expected_tree = {
        let cache = Cache::new(&path).unwrap();
        for h in 0..=3u32 {
            cache.insert_compact_block(&make_test_block(h)).unwrap();
        }
        let expected = cache.get_tip_tree_state().unwrap().unwrap();
        // Simulate crash leaving META_TIP_MERKLE_HEIGHT behind META_TIP_HEIGHT.
        cache
            .meta
            .insert(META_TIP_MERKLE_HEIGHT, &1u32.to_be_bytes())
            .unwrap();
        cache.flush().unwrap();
        expected
    };

    let reopened = reopen_cache(&path);
    assert_eq!(
        reopened.get_tip_tree_state().unwrap().unwrap(),
        expected_tree,
        "Cache::new must rebuild tip Merkle tree when tip_height != tip_merkle_height"
    );
    drop(reopened);

    // Now delete all compact blocks to trigger repair_missing_tip empty reset.
    {
        let db = sled::open(&path).unwrap();
        db.open_tree(COMPACT_BLOCKS_TREE).unwrap().clear().unwrap();
        db.flush().unwrap();
    }
    let empty = reopen_cache(&path);
    assert!(empty.get_tip().unwrap().is_none());
    assert!(empty.get_tip_tree_state().unwrap().is_none());
    assert!(empty.latest_snapshot().unwrap().is_none());
}

#[test]
fn reconcile_rebuilds_legacy_sentinel_missing_merkle_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    let (expected_h0, expected_tip) = {
        let cache = Cache::new(&path).unwrap();
        cache.insert_compact_block(&make_empty_block(0)).unwrap();
        cache.insert_compact_block(&make_test_block(1)).unwrap();
        cache.insert_compact_block(&make_test_block(2)).unwrap();

        let expected_h0 = darkfi_serial::serialize(&Cache::empty_tip_tree());
        let expected_tip = cache.get_tip_tree_state().unwrap().unwrap();

        // Simulate a legacy pre-sentinel cache: overwrite h=0 snapshot and tip
        // tree with a sentinel-less tree and remove META_TIP_MERKLE_SCHEMA.
        let sentinel_less =
            darkfi_serial::serialize(&darkfi_sdk::crypto::MerkleTree::new(TIP_TREE_CHECKPOINTS));
        cache
            .merkle_snapshots
            .insert(0u32.to_be_bytes(), sentinel_less.as_slice())
            .unwrap();
        cache
            .meta
            .insert(META_TIP_MERKLE_TREE, sentinel_less.as_slice())
            .unwrap();
        cache.meta.remove(META_TIP_MERKLE_SCHEMA).unwrap();
        cache.flush().unwrap();
        (expected_h0, expected_tip)
    };

    let reopened = reopen_cache(&path);
    assert_eq!(
        reopened.tip_merkle_schema().unwrap(),
        TIP_MERKLE_SCHEMA_VERSION
    );
    let h0_bytes = reopened.merkle_snapshot(0).unwrap().unwrap();
    let h0_tree: darkfi_sdk::crypto::MerkleTree = darkfi_serial::deserialize(&h0_bytes).unwrap();
    assert_eq!(
        h0_tree.root(0),
        Cache::empty_tip_tree().root(0),
        "height 0 snapshot must be rebuilt with the ZERO sentinel leaf"
    );
    assert_eq!(h0_bytes, expected_h0);
    assert_eq!(
        reopened.get_tip_tree_state().unwrap().unwrap(),
        expected_tip,
        "tip Merkle tree must be rebuilt from cached coins with the ZERO sentinel leaf"
    );
    drop(reopened);

    // Second reopen preserves the repaired root without errors.
    let reopened_again = reopen_cache(&path);
    assert_eq!(
        reopened_again.tip_merkle_schema().unwrap(),
        TIP_MERKLE_SCHEMA_VERSION
    );
    assert_eq!(
        reopened_again.get_tip_tree_state().unwrap().unwrap(),
        expected_tip
    );
}
