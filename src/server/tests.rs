#[allow(unused_imports)]
use super::*;

#[cfg(not(feature = "fhe-omr"))]
#[test]
fn trial_decrypt_is_the_default_build() {
    const { assert!(!cfg!(feature = "fhe-omr")) };
}

#[cfg(feature = "fhe-omr")]
#[test]
fn unifomr_stays_behind_an_explicit_feature() {
    const { assert!(cfg!(feature = "fhe-omr")) };
}

#[test]
fn end_height_zero_resolves_to_cached_tip() {
    let dir = tempfile::tempdir().unwrap();
    let cache = crate::cache::Cache::new(dir.path().to_str().unwrap()).unwrap();
    assert!(resolve_block_range(&cache, 0, 0).is_err());

    cache
        .insert_compact_block(&crate::compact_block::CompactBlock {
            height: 40,
            hash: [9u8; 32],
            prev_hash: [0u8; 32],
            timestamp: 1,
            txs: vec![],
            dao_calls: vec![],
            func_events: vec![],
        })
        .unwrap();
    assert_eq!(resolve_block_range(&cache, 0, 0).unwrap(), (0, 40));
    assert_eq!(resolve_block_range(&cache, 10, 0).unwrap(), (10, 40));
    assert_eq!(resolve_block_range(&cache, 0, 10_000).unwrap(), (0, 40));
    assert!(resolve_block_range(&cache, 41, 0).is_err());

    cache
        .insert_compact_block(&crate::compact_block::CompactBlock {
            height: 20_000,
            hash: [8u8; 32],
            prev_hash: [0u8; 32],
            timestamp: 2,
            txs: vec![],
            dao_calls: vec![],
            func_events: vec![],
        })
        .unwrap();
    assert!(resolve_block_range(&cache, 0, 0).is_err());
    assert_eq!(
        resolve_block_range(&cache, 19_000, 0).unwrap(),
        (19_000, 20_000)
    );
}

#[test]
fn digest_stops_before_first_missing_height() {
    let dir = tempfile::tempdir().unwrap();
    let cache = crate::cache::Cache::new(dir.path().to_str().unwrap()).unwrap();
    assert_eq!(digest_evaluable_end(&cache, 0, 5).unwrap(), (None, false));

    for h in [10u32, 11, 12, 14, 15] {
        cache
            .insert_compact_block(&crate::compact_block::CompactBlock {
                height: h,
                hash: [h as u8; 32],
                prev_hash: [h.wrapping_sub(1) as u8; 32],
                timestamp: h as u64,
                txs: vec![],
                dao_calls: vec![],
                func_events: vec![],
            })
            .unwrap();
    }
    // Fully cached window below the tip.
    assert_eq!(
        digest_evaluable_end(&cache, 10, 12).unwrap(),
        (Some(12), true)
    );
    // Interior hole at 13: evaluate only 10..=12, never 14/15.
    assert_eq!(
        digest_evaluable_end(&cache, 10, 15).unwrap(),
        (Some(12), false)
    );
    // Hole at the window start: nothing evaluable.
    assert_eq!(digest_evaluable_end(&cache, 13, 15).unwrap(), (None, false));
    // End beyond tip: truncate at tip, incomplete.
    assert_eq!(
        digest_evaluable_end(&cache, 14, 20).unwrap(),
        (Some(15), false)
    );
    // Start beyond tip.
    assert_eq!(digest_evaluable_end(&cache, 16, 20).unwrap(), (None, false));
    // Hole at 0 below the first cached block.
    assert_eq!(digest_evaluable_end(&cache, 0, 12).unwrap(), (None, false));
}

#[test]
fn height_span_rejects_wraparound() {
    assert!(height_span(0, u32::MAX).unwrap() > MAX_BLOCKS_PER_REQUEST as u64);
    assert!(reject_oversized_window(0, u32::MAX).is_err());
    assert!(reject_oversized_window(10, 9).is_err());
    assert_eq!(reject_oversized_window(1, 1).unwrap(), 1);
    assert_eq!(reject_oversized_window(1, 10_000).unwrap(), 10_000);
    assert!(reject_oversized_window(1, 10_001).is_err());
}

#[test]
fn snapshot_integrity_hash_covers_height_tree_and_nullifiers() {
    let a = snapshot_integrity_hash(10, b"tree", b"nf");
    let b = snapshot_integrity_hash(10, b"tree", b"nf");
    assert_eq!(a, b);
    assert_ne!(snapshot_integrity_hash(11, b"tree", b"nf"), a);
    assert_ne!(snapshot_integrity_hash(10, b"TREE", b"nf"), a);
    assert_ne!(snapshot_integrity_hash(10, b"tree", b"NF"), a);
    assert_ne!(blake3::hash(b"tree").as_bytes(), &a);
}

#[test]
fn trusted_proxy_match_exact_and_cidr() {
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(ip_matches_proxy_entry(loopback, "127.0.0.1"));
    assert!(ip_matches_proxy_entry(loopback, "127.0.0.0/8"));
    assert!(!ip_matches_proxy_entry(loopback, "10.0.0.0/8"));
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert!(ip_matches_proxy_entry(v6, "::1"));
    assert!(ip_matches_proxy_entry(v6, "::1/128"));
    assert!(ip_matches_proxy_entry(
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        "fd00::/8"
    ));
    assert!(!ip_matches_proxy_entry(v6, "fd00::/8"));
    assert_eq!(
        padded_decoy_clue_public_key(&[1; 32], &[2; 32]).len(),
        CLUE_PUBLIC_KEY_WIRE_LEN
    );
    let trusted = vec!["127.0.0.1".to_string()];
    // nginx appends; leftmost hop is client-spoofable and must be ignored.
    assert_eq!(
        client_ip_from_forwarded("1.2.3.4, 203.0.113.9, 127.0.0.1", &trusted),
        "203.0.113.9".parse::<IpAddr>().ok()
    );
    assert_eq!(
        client_ip_from_forwarded("203.0.113.9", &trusted),
        "203.0.113.9".parse::<IpAddr>().ok()
    );
}

fn test_block(height: u32, prev: u8) -> crate::compact_block::CompactBlock {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&height.to_be_bytes());
    crate::compact_block::CompactBlock {
        height,
        hash,
        prev_hash: [prev; 32],
        timestamp: 1_000 + height as u64,
        txs: vec![],
        dao_calls: vec![],
        func_events: vec![],
    }
}

fn test_service(cache: Arc<Cache>) -> (LightWalletService, tokio::sync::watch::Sender<u32>) {
    let (tx, rx) = tokio::sync::watch::channel(0u32);
    let endpoint = url::Url::parse("http://127.0.0.1:9").unwrap();
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(endpoint));
    let svc = LightWalletService::with_limits(
        cache,
        rpc,
        "test".into(),
        0x01,
        10_000,
        10_000,
        DEFAULT_MAX_TX_BYTES,
        rx,
        Vec::new(),
    );
    (svc, tx)
}

#[test]
fn padded_range_accepts_power_of_two_bucket_and_rejects_short() {
    // Exactly 1024, ending at the tip.
    assert!(padded_range_rejection(0, 1023, 1023, MAX_BLOCKS_PER_REQUEST).is_none());
    // Power of two, not aligned to zero, ending before the tip.
    assert!(padded_range_rejection(100, 1123, 5_000, MAX_BLOCKS_PER_REQUEST).is_none());
    assert!(padded_range_rejection(0, 8191, 8191, MAX_BLOCKS_PER_REQUEST).is_none());
    // Short unpadded range.
    assert!(padded_range_rejection(0, 100, 10_000, MAX_BLOCKS_PER_REQUEST).is_some());
    // 512 is a power of two but below the 1024 minimum.
    assert!(padded_range_rejection(0, 511, 10_000, MAX_BLOCKS_PER_REQUEST).is_some());
    // 1025 is not a power of two.
    assert!(padded_range_rejection(0, 1024, 10_000, MAX_BLOCKS_PER_REQUEST).is_some());
    // 16384 is a power of two but above max_range (10_000).
    assert!(padded_range_rejection(0, 16_383, 100_000, MAX_BLOCKS_PER_REQUEST).is_some());
    // Ends past the tip.
    assert!(padded_range_rejection(0, 1023, 100, MAX_BLOCKS_PER_REQUEST).is_some());
    assert!(padded_range_rejection(5, 4, 10, MAX_BLOCKS_PER_REQUEST).is_some());

    // A short cursor near a high tip pads to a bucket the server accepts.
    let (padded_start, padded_end) = pad_block_range(4990, 5000, 5000);
    assert!(padded_start <= 4990 && padded_end == 5000);
    assert!(
        padded_range_rejection(padded_start, padded_end, 5000, MAX_BLOCKS_PER_REQUEST).is_none()
    );
    let span = padded_end - padded_start + 1;
    assert!(span >= MIN_PADDED_RANGE_SPAN && span.is_power_of_two());
    // The unpadded cursor itself is still rejected.
    assert!(padded_range_rejection(4990, 5000, 5000, MAX_BLOCKS_PER_REQUEST).is_some());
    // A chain shorter than one bucket is served whole, from genesis only.
    let (short_start, short_end) = pad_block_range(0, 10, 10);
    assert_eq!((short_start, short_end), (0, 10));
    assert!(padded_range_rejection(short_start, short_end, 10, MAX_BLOCKS_PER_REQUEST).is_none());
    assert!(padded_range_rejection(5, 10, 10, MAX_BLOCKS_PER_REQUEST).is_some());
}

#[test]
fn padded_range_accepts_client_buckets_cut_at_the_tip() {
    // Client pad_block_range(4990, 5000, 5000): bucket 4096..=5119 cut at the tip.
    assert!(padded_range_rejection(4096, 5000, 5000, MAX_BLOCKS_PER_REQUEST).is_none());
    // The client's tip trails ours by a few blocks.
    assert!(padded_range_rejection(4096, 5000, 5003, MAX_BLOCKS_PER_REQUEST).is_none());
    // Two 1024 buckets cut at the tip (client pad of 1500..=2500).
    assert!(padded_range_rejection(1024, 2600, 2600, MAX_BLOCKS_PER_REQUEST).is_none());
    // Two full 1024 buckets.
    assert!(padded_range_rejection(1024, 3071, 50_000, MAX_BLOCKS_PER_REQUEST).is_none());
    // A partial bucket far below the tip publishes the cursor.
    assert!(padded_range_rejection(4096, 4990, 50_000, MAX_BLOCKS_PER_REQUEST).is_some());
    assert!(padded_range_rejection(4096, 5000, 5065, MAX_BLOCKS_PER_REQUEST).is_some());
    assert!(padded_range_rejection(4096, 5000, 5064, MAX_BLOCKS_PER_REQUEST).is_none());
    // A partial bucket must start on its boundary.
    assert!(padded_range_rejection(4097, 5000, 5000, MAX_BLOCKS_PER_REQUEST).is_some());
    assert!(padded_range_rejection(1536, 2600, 2600, MAX_BLOCKS_PER_REQUEST).is_some());
}

#[test]
fn require_padded_block_range_rejects_unpadded_against_tip() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().to_str().unwrap()).unwrap();
    assert!(require_padded_block_range(&cache, 0, 1023).is_err());

    cache.insert_compact_block(&test_block(3000, 0)).unwrap();
    assert_eq!(
        require_padded_block_range(&cache, 0, 1023).unwrap(),
        (0, 1023)
    );
    assert!(require_padded_block_range(&cache, 0, 100).is_err());
    // span = 3000 - 1977 + 1 = 1024, end == tip.
    assert!(require_padded_block_range(&cache, 1977, 3000).is_ok());
    assert!(require_padded_block_range(&cache, 1976, 3000).is_err());
}

#[tokio::test]
async fn checkpoint_snapshot_at_or_below_birthday_and_tree_state_miss() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    cache.insert_compact_block(&test_block(0, 0)).unwrap();
    cache.insert_compact_block(&test_block(1, 1)).unwrap();
    cache.insert_compact_block(&test_block(2, 2)).unwrap();
    let (svc, _) = test_service(Arc::clone(&cache));

    let miss =
        DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 1 }))
            .await
            .unwrap_err();
    assert_eq!(miss.code(), tonic::Code::FailedPrecondition);
    assert!(
        miss.message().contains("greatest snapshot <= 1 is 0"),
        "status text: {}",
        miss.message()
    );

    let tip_state =
        DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 2 }))
            .await
            .unwrap()
            .into_inner();
    assert!(tip_state.is_checkpoint);
    assert_eq!(tip_state.height, 2);

    let snap0 =
        DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 0 }))
            .await
            .unwrap()
            .into_inner();
    assert!(snap0.is_checkpoint);
    assert_eq!(snap0.height, 0);

    use tokio_stream::StreamExt;
    let mut stream = DarkFiLightWallet::get_checkpoint_snapshot(
        &svc,
        Request::new(proto::CheckpointRequest {
            preferred_height: 1,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let mut tree_data = Vec::new();
    let mut height = None;
    let mut state_root = Vec::new();
    let mut snapshot_hash = Vec::new();
    let mut scan_cursor = 0u32;
    while let Some(chunk) = stream.next().await {
        let snap = chunk.unwrap();
        if height.is_none() {
            height = Some(snap.height);
            state_root = snap.state_root.clone();
            snapshot_hash = snap.snapshot_hash.clone();
            scan_cursor = snap.scan_cursor;
        }
        assert!(snap.nullifier_index.is_empty());
        assert_eq!(snap.scan_cursor, snap.height);
        tree_data.extend_from_slice(&snap.tree_data);
    }
    let height = height.unwrap();
    assert!(height <= 1, "birthday 1 must not receive a later snapshot");
    assert_eq!(height, 0);
    assert_eq!(scan_cursor, height);
    assert_eq!(
        snapshot_hash,
        snapshot_integrity_hash(height, &tree_data, &[]).to_vec()
    );
    // Gap: CompactBlock has no block-header money-tree / coin root.
    // state_root stays blake3(tree_data). Do not invent a second root
    // until darkfid exposes that field on the cached compact block.
    assert_eq!(state_root, blake3::hash(&tree_data).as_bytes().to_vec());

    let mut latest = DarkFiLightWallet::get_checkpoint_snapshot(
        &svc,
        Request::new(proto::CheckpointRequest {
            preferred_height: 0,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let first = latest.next().await.unwrap().unwrap();
    assert_eq!(
        first.height, 2,
        "preferred 0 is the latest snapshot, the tip"
    );
    assert_eq!(first.scan_cursor, 2);

    let empty_dir = tempfile::tempdir().unwrap();
    let empty = Arc::new(Cache::new(empty_dir.path().to_str().unwrap()).unwrap());
    let (empty_svc, _) = test_service(empty);
    let missing = DarkFiLightWallet::get_checkpoint_snapshot(
        &empty_svc,
        Request::new(proto::CheckpointRequest {
            preferred_height: 5,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
}

#[cfg(feature = "fhe-omr")]
#[tokio::test]
async fn pool_digest_missing_and_expired_handles_are_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (svc, _) = test_service(cache);

    let missing = DarkFiLightWallet::get_unif_omr_digest_from_pool(
        &svc,
        Request::new(proto::PoolDigestRequest {
            handle: vec![9u8; 32],
            start_height: 0,
            end_height: 10,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let bad_len = DarkFiLightWallet::get_unif_omr_digest_from_pool(
        &svc,
        Request::new(proto::PoolDigestRequest {
            handle: vec![1, 2, 3],
            start_height: 0,
            end_height: 10,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(bad_len.code(), tonic::Code::InvalidArgument);

    let handle = {
        let mut pool = svc.detection_pool.lock().unwrap();
        pool.insert(
            PooledDetectionKey {
                keys: vec![Arc::new(vec![1, 2, 3])],
                #[cfg(feature = "fhe-omr")]
                parsed_keys: Vec::new(),
                network_byte: 1,
                expires_unix: 10,
                byte_length: 3,
            },
            svc.max_detection_key_bytes,
            0,
        )
        .unwrap()
    };
    let expired = DarkFiLightWallet::get_unif_omr_digest_from_pool(
        &svc,
        Request::new(proto::PoolDigestRequest {
            handle: handle.to_vec(),
            start_height: 0,
            end_height: 10,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(expired.code(), tonic::Code::NotFound);
    assert!(
        expired.message().contains("expired") || expired.message().contains("not found"),
        "{}",
        expired.message()
    );
}

#[tokio::test]
async fn subscribe_blocks_skips_unsent_tip_instead_of_dropping() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (svc, tip_tx) = test_service(Arc::clone(&cache));
    let notice = Arc::clone(&svc.tip_notice);

    let mut stream = DarkFiLightWallet::subscribe_blocks(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap()
        .into_inner();

    cache.insert_compact_block(&test_block(1, 0x11)).unwrap();
    tip_tx.send(1).unwrap();
    tokio::time::timeout(Duration::from_secs(2), notice.notified())
        .await
        .expect("first tip notice blocked");

    // Client has not read. The one-slot buffer is full; this must not
    // wait 30s or close the subscription.
    cache.insert_compact_block(&test_block(2, 0x22)).unwrap();
    tip_tx.send(2).unwrap();
    tokio::time::timeout(Duration::from_secs(2), notice.notified())
        .await
        .expect("slow client caused a 30s drop or a blocked send");

    use tokio_stream::StreamExt;
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("subscription closed")
        .expect("subscription ended")
        .unwrap();
    assert_eq!(first.height, 1);
    assert_eq!(first.prev_hash, vec![0x11; 32]);
    assert_eq!(first.hash, test_block(1, 0x11).hash.to_vec());

    cache.insert_compact_block(&test_block(3, 0x33)).unwrap();
    tip_tx.send(3).unwrap();
    let third = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("subscription dropped after a skipped tip")
        .expect("subscription ended")
        .unwrap();
    assert_eq!(third.height, 3);
    assert_eq!(third.prev_hash, vec![0x33; 32]);
    assert_eq!(third.hash, test_block(3, 0x33).hash.to_vec());
}

#[tokio::test]
async fn compact_output_bodies_are_one_per_output_in_a_padded_range() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let mut prev_hash = [0u8; 32];
    for height in 0u32..1023 {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&height.to_be_bytes());
        cache
            .insert_compact_block(&crate::compact_block::CompactBlock {
                height,
                hash,
                prev_hash,
                timestamp: height as u64,
                txs: vec![],
                dao_calls: vec![],
                func_events: vec![],
            })
            .unwrap();
        prev_hash = hash;
    }
    let coin_a = [0x11u8; 32];
    let coin_b = [0x22u8; 32];
    let mut tip_hash = [0u8; 32];
    tip_hash[..4].copy_from_slice(&1023u32.to_be_bytes());
    cache
        .insert_compact_block(&crate::compact_block::CompactBlock {
            height: 1023,
            hash: tip_hash,
            prev_hash,
            timestamp: 1023,
            txs: vec![crate::compact_block::CompactTx {
                tx_hash: [0x44; 32],
                outputs: vec![
                    crate::compact_block::CompactOutput {
                        coin: coin_a,
                        encrypted_note: vec![1, 2],
                        value_commit: vec![3],
                        token_commit: [4; 32],
                        omr_clue: vec![5],
                        omr_metadata_enc: vec![6],
                        func_code: 0,
                    },
                    crate::compact_block::CompactOutput {
                        coin: coin_b,
                        encrypted_note: vec![7],
                        value_commit: vec![],
                        token_commit: [8; 32],
                        omr_clue: vec![],
                        omr_metadata_enc: vec![9, 9],
                        func_code: 0,
                    },
                ],
                nullifiers: vec![[0xAB; 32]],
                fee: 7,
            }],
            dao_calls: vec![],
            func_events: vec![],
        })
        .unwrap();
    let (svc, _) = test_service(Arc::clone(&cache));

    let rejected = DarkFiLightWallet::get_compact_output_bodies(
        &svc,
        Request::new(proto::BlockRange {
            start_height: 0,
            end_height: 10,
            omit_omr_clues: false,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(rejected.code(), tonic::Code::InvalidArgument);

    use tokio_stream::StreamExt;
    let mut stream = DarkFiLightWallet::get_compact_output_bodies(
        &svc,
        Request::new(proto::BlockRange {
            start_height: 0,
            end_height: 1023,
            omit_omr_clues: false,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let mut bodies = Vec::new();
    while let Some(item) = stream.next().await {
        bodies.push(item.expect("connected padded range"));
    }
    assert_eq!(
        bodies.len(),
        2,
        "one message per output, nullifiers not included"
    );
    assert_eq!(bodies[0].height, 1023);
    assert_eq!(bodies[0].hash, tip_hash.to_vec());
    assert_eq!(bodies[0].prev_hash, prev_hash.to_vec());
    assert_eq!(bodies[0].coin, coin_a.to_vec());
    assert_eq!(bodies[0].encrypted_note, vec![1, 2]);
    assert_eq!(bodies[0].omr_clue, vec![5]);
    assert_eq!(bodies[0].omr_metadata_enc, vec![6]);
    assert_eq!(bodies[0].tx_hash, vec![0x44; 32]);
    assert_eq!(bodies[1].coin, coin_b.to_vec());
    assert_eq!(bodies[1].hash, tip_hash.to_vec());
    assert!(bodies[1].omr_clue.is_empty());

    // Trial-decrypt clients set omit_omr_clues = true to strip clue overhead while
    // keeping coin, encrypted_note, omr_metadata_enc, tx_hash, and func_code intact.
    let mut stream_omit = DarkFiLightWallet::get_compact_output_bodies(
        &svc,
        Request::new(proto::BlockRange {
            start_height: 0,
            end_height: 1023,
            omit_omr_clues: true,
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let mut omitted = Vec::new();
    while let Some(item) = stream_omit.next().await {
        omitted.push(item.expect("omitted padded range"));
    }
    assert_eq!(omitted.len(), 2);
    assert!(omitted[0].omr_clue.is_empty());
    assert_eq!(omitted[0].coin, coin_a.to_vec());
    assert_eq!(omitted[0].encrypted_note, vec![1, 2]);
    assert_eq!(omitted[0].omr_metadata_enc, vec![6]);
    assert_eq!(omitted[1].coin, coin_b.to_vec());
}

#[cfg(feature = "fhe-omr")]
#[test]
fn clue_window_cache_keeps_notes_not_digest_bytes() {
    let mut cache = ClueWindowCache::new();
    let detector = crate::unifomr::UnifOmrDetector::new(0x01).unwrap();
    let ct = crate::unifomr::RlweCiphertext {
        a: vec![1u64; crate::unifomr::CLUE_N],
        b: vec![3u64; crate::unifomr::CLUE_ELL],
    };
    let prepared = Arc::new(detector.prepare_window(&[ct]).unwrap());
    let window = Arc::new(FlattenedClueWindow {
        prepared,
        slot_heights_wire: crate::unifomr::pack_slot_heights(&[4]),
        truncated: false,
    });
    let hash = [7u8; 32];
    cache.insert(0, 1023, hash, Arc::clone(&window));
    let hit = cache.get(0, 1023, hash).unwrap();
    assert!(Arc::ptr_eq(&hit, &window));
    assert_eq!(hit.prepared.message_count(), 1);
    assert_eq!(hit.slot_heights_wire, window.slot_heights_wire);
    assert!(cache.get(0, 1023, [8u8; 32]).is_none());
}

#[cfg(feature = "fhe-omr")]
#[test]
fn pir_window_cache_reuses_stripped_payload_arc() {
    let mut cache = PirWindowCache::new();
    let payloads = Arc::new(vec![vec![1, 2], vec![3]]);
    let hash = [9u8; 32];
    cache.insert(10, 11, hash, Arc::clone(&payloads));
    let hit = cache.get(10, 11, hash).unwrap();
    assert!(Arc::ptr_eq(&hit, &payloads));
    assert!(cache.get(10, 11, [0u8; 32]).is_none());
}

#[cfg(feature = "fhe-omr")]
#[test]
fn pir_encode_strips_omr_clue_under_payload_cap() {
    use prost::Message;
    let clue = vec![0x5Au8; crate::pir_server::MAX_PIR_PAYLOAD_BYTES + 1];
    let block = CompactBlock {
        height: 7,
        hash: [1u8; 32],
        prev_hash: [2u8; 32],
        timestamp: 9,
        txs: vec![crate::compact_block::CompactTx {
            tx_hash: [3u8; 32],
            outputs: vec![crate::compact_block::CompactOutput {
                coin: [4u8; 32],
                encrypted_note: vec![0x11; 40],
                value_commit: vec![0x22; 33],
                token_commit: [0x33; 32],
                omr_clue: clue,
                omr_metadata_enc: vec![0x44; 16],
                func_code: 0,
            }],
            nullifiers: vec![[0x55; 32]],
            fee: 1,
        }],
        dao_calls: vec![],
        func_events: vec![],
    };
    let raw = block.to_proto().encode_to_vec();
    assert!(raw.len() > crate::pir_server::MAX_PIR_PAYLOAD_BYTES);
    assert_eq!(
        crate::pir_server::payload_limb(&raw, 0),
        crate::pir_server::MAX_PIR_PAYLOAD_BYTES as u64 + 1,
        "unstripped clue must still overflow; this test must not hide that"
    );

    let stripped = encode_compact_block_for_pir(&block);
    assert!(stripped.len() <= crate::pir_server::MAX_PIR_PAYLOAD_BYTES);
    assert_eq!(
        crate::pir_server::payload_limb(&stripped, 0),
        stripped.len() as u64
    );
    let decoded = proto::CompactBlock::decode(stripped.as_slice()).unwrap();
    let out = &decoded.txs[0].outputs[0];
    assert!(out.omr_clue.is_empty());
    assert_eq!(out.coin, vec![4u8; 32]);
    assert_eq!(out.encrypted_note, vec![0x11; 40]);
    assert_eq!(out.omr_metadata_enc, vec![0x44; 16]);
    assert_eq!(decoded.txs[0].nullifiers, vec![vec![0x55; 32]]);
    assert_eq!(PIR_RATE_LIMIT_PER_MIN, 4096);
    assert_eq!(crate::pir_server::MAX_PIR_LIMBS, 32_768);
}

async fn spawn_mock_darkfid(pending_contains_hash: bool, hash_hex: String) -> String {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hash_hex = hash_hex.clone();
            tokio::spawn(async move {
                let (r, mut w) = stream.into_split();
                let mut reader = BufReader::new(r);
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let id = line
                    .parse::<tinyjson::JsonValue>()
                    .ok()
                    .and_then(|v| v.get::<HashMap<String, tinyjson::JsonValue>>().cloned())
                    .and_then(|m| m.get("id").and_then(|i| i.get::<f64>().copied()))
                    .unwrap_or(1.0) as i64;
                let resp = if line.contains("\"tx.broadcast\"") {
                    format!(r#"{{"jsonrpc":"2.0","result":"{hash_hex}","id":{id}}}"#) + "\n"
                } else if line.contains("\"tx.pending\"") {
                    if pending_contains_hash {
                        format!(r#"{{"jsonrpc":"2.0","result":["{hash_hex}"],"id":{id}}}"#) + "\n"
                    } else {
                        format!(r#"{{"jsonrpc":"2.0","result":[],"id":{id}}}"#) + "\n"
                    }
                } else if line.contains("\"blockchain.get_tx\"") {
                    format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32603,"message":"not found"}},"id":{id}}}"#
                    ) + "\n"
                } else {
                    format!(r#"{{"jsonrpc":"2.0","result":null,"id":{id}}}"#) + "\n"
                };
                let _ = w.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// Broadcast returns a hash, then the listener is closed so confirm cannot connect.
async fn spawn_mock_darkfid_broadcast_ok_then_refuse(hash_hex: String) -> String {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        // Later confirm RPCs must fail to connect. Drop the listener before
        // the broadcast response is written so the client cannot sneak in.
        drop(listener);
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let id = line
            .parse::<tinyjson::JsonValue>()
            .ok()
            .and_then(|v| v.get::<HashMap<String, tinyjson::JsonValue>>().cloned())
            .and_then(|m| m.get("id").and_then(|i| i.get::<f64>().copied()))
            .unwrap_or(1.0) as i64;
        let resp = format!(r#"{{"jsonrpc":"2.0","result":"{hash_hex}","id":{id}}}"#) + "\n";
        let _ = w.write_all(resp.as_bytes()).await;
        let _ = w.shutdown().await;
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn send_transaction_confirms_mempool_and_get_transaction_serves_it() {
    use proto::dark_fi_light_wallet_server::DarkFiLightWallet;
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let expected_hash = [0xABu8; 32];
    let hash_hex = hex::encode(expected_hash);
    let url_str = spawn_mock_darkfid(true, hash_hex).await;
    let (_tx, rx) = tokio::sync::watch::channel(0u32);
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(
        url::Url::parse(&url_str).unwrap(),
    ));
    let svc = LightWalletService::with_limits(
        cache,
        rpc,
        "test".into(),
        0x01,
        10_000,
        10_000,
        DEFAULT_MAX_TX_BYTES,
        rx,
        Vec::new(),
    );
    let raw_tx = vec![1u8, 2, 3, 4];
    let send_resp = svc
        .send_transaction(Request::new(proto::RawTransaction {
            data: raw_tx.clone(),
            omr_clue: vec![],
            omr_clue_output_index: 0,
            omr_metadata_enc: vec![],
            extra_omr_clues: vec![],
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        send_resp.error.is_empty(),
        "expected mempool confirmation, got {}",
        send_resp.error
    );
    assert_eq!(send_resp.tx_hash, expected_hash.to_vec());

    let got = svc
        .get_transaction(Request::new(proto::TxHash {
            hash: expected_hash.to_vec(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.data, raw_tx);
}

#[tokio::test]
async fn send_transaction_fails_when_missing_from_mempool() {
    use proto::dark_fi_light_wallet_server::DarkFiLightWallet;
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let hash_hex = hex::encode([0xCDu8; 32]);
    let url_str = spawn_mock_darkfid(false, hash_hex).await;
    let (_tx, rx) = tokio::sync::watch::channel(0u32);
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(
        url::Url::parse(&url_str).unwrap(),
    ));
    let svc = LightWalletService::with_limits(
        cache,
        rpc,
        "test".into(),
        0x01,
        10_000,
        10_000,
        DEFAULT_MAX_TX_BYTES,
        rx,
        Vec::new(),
    );
    let send_resp = svc
        .send_transaction(Request::new(proto::RawTransaction {
            data: vec![9u8, 8, 7],
            omr_clue: vec![],
            omr_clue_output_index: 0,
            omr_metadata_enc: vec![],
            extra_omr_clues: vec![],
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!send_resp.error.is_empty());
    assert!(send_resp.tx_hash.is_empty());
}

#[tokio::test]
async fn get_tree_state_and_omr_capabilities_enforce_rpc_rate_limit() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (_tx, rx) = tokio::sync::watch::channel(0u32);
    let endpoint = url::Url::parse("http://127.0.0.1:9").unwrap();
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(endpoint));
    // Allow only 2 RPC calls per minute per peer.
    let svc = LightWalletService::with_limits(
        cache,
        rpc,
        "test".into(),
        0x01,
        10,
        2,
        DEFAULT_MAX_TX_BYTES,
        rx,
        Vec::new(),
    );

    let state =
        DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 0 }))
            .await
            .unwrap()
            .into_inner();
    // Empty tip fallback must match Cache::empty_tip_tree() sentinel leaf.
    assert_eq!(
        state.tree_data,
        darkfi_serial::serialize(&Cache::empty_tip_tree())
    );

    let _caps = DarkFiLightWallet::get_omr_capabilities(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap();

    // 3rd call from the same peer must be rate-limited on both endpoints.
    let err_tree =
        DarkFiLightWallet::get_tree_state(&svc, Request::new(proto::BlockHeight { height: 0 }))
            .await
            .unwrap_err();
    assert_eq!(err_tree.code(), tonic::Code::ResourceExhausted);

    let err_caps = DarkFiLightWallet::get_omr_capabilities(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap_err();
    assert_eq!(err_caps.code(), tonic::Code::ResourceExhausted);
}

#[cfg(not(feature = "fhe-omr"))]
#[tokio::test]
async fn pool_digest_returns_unimplemented_without_fhe_feature() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (svc, _) = test_service(cache);
    let err = DarkFiLightWallet::get_unif_omr_digest_from_pool(
        &svc,
        Request::new(proto::PoolDigestRequest {
            handle: vec![1, 2, 3],
            start_height: 0,
            end_height: 10,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn subscribe_blocks_enforces_dedicated_semaphore_cap() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (mut svc, _) = test_service(cache);
    svc.subscribe_permits = Arc::new(tokio::sync::Semaphore::new(2));

    let s1 = DarkFiLightWallet::subscribe_blocks(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap();
    let _s2 = DarkFiLightWallet::subscribe_blocks(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap();
    let err = DarkFiLightWallet::subscribe_blocks(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    // Dropping an active stream frees a slot once its task observes tx.closed().
    drop(s1);
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        DarkFiLightWallet::subscribe_blocks(&svc, Request::new(proto::Empty {}))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn register_omr_clue_wires_and_bounds_metadata_enc() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (svc, _) = test_service(Arc::clone(&cache));
    let tx_hash = [0x55u8; 32];
    let peer = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    svc.remember_send_peer(tx_hash, peer);

    // Oversized metadata is rejected before storage.
    let too_big = DarkFiLightWallet::register_omr_clue(
        &svc,
        Request::new(proto::OmrClueRegistration {
            tx_hash: tx_hash.to_vec(),
            omr_clue: vec![],
            omr_clue_output_index: 0,
            omr_metadata_enc: vec![0xAB; MAX_OMR_METADATA_ENC_BYTES + 1],
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(too_big.code(), tonic::Code::InvalidArgument);

    // Valid metadata-only registration succeeds for bound peer.
    let memo = b"encrypted-memo".to_vec();
    DarkFiLightWallet::register_omr_clue(
        &svc,
        Request::new(proto::OmrClueRegistration {
            tx_hash: tx_hash.to_vec(),
            omr_clue: vec![],
            omr_clue_output_index: 0,
            omr_metadata_enc: memo.clone(),
        }),
    )
    .await
    .unwrap();
    assert!(cache.has_omr_metadata_enc(&tx_hash).unwrap());
}

#[tokio::test]
async fn send_transaction_cleans_up_pre_broadcast_metadata_on_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let tx = darkfi::tx::Transaction {
        calls: vec![],
        proofs: vec![],
        signatures: vec![],
    };
    let tx_hash = *tx.hash().inner();
    let raw_tx = darkfi_serial::serialize(&tx);
    let url_str = spawn_mock_darkfid(false, hex::encode(tx_hash)).await;
    let (_tx, rx) = tokio::sync::watch::channel(0u32);
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(
        url::Url::parse(&url_str).unwrap(),
    ));
    let svc = LightWalletService::with_limits(
        Arc::clone(&cache),
        rpc,
        "test".into(),
        0x01,
        10_000,
        10_000,
        DEFAULT_MAX_TX_BYTES,
        rx,
        Vec::new(),
    );

    let resp = DarkFiLightWallet::send_transaction(
        &svc,
        Request::new(proto::RawTransaction {
            data: raw_tx,
            omr_clue: vec![],
            omr_clue_output_index: 0,
            omr_metadata_enc: b"memo-for-rejected-tx".to_vec(),
            extra_omr_clues: vec![],
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(!resp.error.is_empty());
    assert!(
        !cache.has_omr_metadata_enc(&tx_hash).unwrap(),
        "rejected tx must not retain pre-broadcast metadata_enc"
    );
}

#[test]
fn confirm_connection_error_keeps_pre_broadcast_rows() {
    assert!(!drop_pre_broadcast_rows(
        PreBroadcastFollowup::ConfirmConnectionError
    ));
    assert!(!drop_pre_broadcast_rows(PreBroadcastFollowup::Confirmed));
    assert!(drop_pre_broadcast_rows(PreBroadcastFollowup::NotConfirmed));
    assert!(drop_pre_broadcast_rows(
        PreBroadcastFollowup::BroadcastFailed
    ));
}

#[tokio::test]
async fn send_transaction_keeps_pre_broadcast_metadata_on_confirm_connection_error() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let tx = darkfi::tx::Transaction {
        calls: vec![],
        proofs: vec![],
        signatures: vec![],
    };
    let tx_hash = *tx.hash().inner();
    let raw_tx = darkfi_serial::serialize(&tx);
    let url_str = spawn_mock_darkfid_broadcast_ok_then_refuse(hex::encode(tx_hash)).await;
    let (_tx, rx) = tokio::sync::watch::channel(0u32);
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(
        url::Url::parse(&url_str).unwrap(),
    ));
    let svc = LightWalletService::with_limits(
        Arc::clone(&cache),
        rpc,
        "test".into(),
        0x01,
        10_000,
        10_000,
        DEFAULT_MAX_TX_BYTES,
        rx,
        Vec::new(),
    );

    let err = DarkFiLightWallet::send_transaction(
        &svc,
        Request::new(proto::RawTransaction {
            data: raw_tx,
            omr_clue: vec![],
            omr_clue_output_index: 0,
            omr_metadata_enc: b"memo-for-unconfirmed-transport".to_vec(),
            extra_omr_clues: vec![],
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert!(
        cache.has_omr_metadata_enc(&tx_hash).unwrap(),
        "confirm connection error must keep pre-broadcast metadata until the TTL"
    );
}

#[tokio::test]
async fn register_clue_public_key_enforces_payload_and_entry_caps() {
    use darkfi::util::pcg::Pcg32;
    use darkfi_sdk::crypto::Keypair;

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    cache.set_max_clue_pubkey_entries(1);
    let (svc, _) = test_service(Arc::clone(&cache));

    let kp1 = Keypair::random(&mut Pcg32::new(1));
    let pk1 = kp1.public.to_bytes();

    // Oversized clue_public_key rejected before ownership verification.
    let err_pk = DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk1.to_vec(),
            clue_public_key: vec![0xAA; MAX_CLUE_PUBLIC_KEY_BYTES + 1],
            ownership_proof: vec![0xBB; 64],
            key_version: 1,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err_pk.code(), tonic::Code::InvalidArgument);

    // Oversized ownership_proof rejected before ownership verification.
    let err_proof = DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk1.to_vec(),
            clue_public_key: vec![0xAA; 32],
            ownership_proof: vec![0xBB; MAX_OWNERSHIP_PROOF_BYTES + 1],
            key_version: 1,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err_proof.code(), tonic::Code::InvalidArgument);

    // Entry cap enforced (using valid key bytes when fhe-omr is enabled).
    #[cfg(feature = "fhe-omr")]
    let clue_bytes = {
        let (_, cpk) = crate::unifomr::clue_keypair_from_wallet(&[0x11u8; 32], 0x01).unwrap();
        crate::unifomr::serialize_public_key(&cpk)
    };
    #[cfg(not(feature = "fhe-omr"))]
    let clue_bytes = vec![0xCCu8; 32];

    let proof1 =
        crate::clue_ownership::sign_clue_pk_ownership(&kp1.secret, 0x01, 1, &pk1, &clue_bytes);
    DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk1.to_vec(),
            clue_public_key: clue_bytes.clone(),
            ownership_proof: proof1,
            key_version: 1,
        }),
    )
    .await
    .unwrap();

    let kp2 = Keypair::random(&mut Pcg32::new(2));
    let pk2 = kp2.public.to_bytes();
    let proof2 =
        crate::clue_ownership::sign_clue_pk_ownership(&kp2.secret, 0x01, 1, &pk2, &clue_bytes);
    let full = DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk2.to_vec(),
            clue_public_key: clue_bytes.clone(),
            ownership_proof: proof2,
            key_version: 1,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(full.code(), tonic::Code::ResourceExhausted);

    // Even while the directory is at capacity, an existing key can still
    // refresh at the same key_version (idempotent) or rotate to a higher
    // key_version, while key_version=0 and downgrades are rejected.
    let proof1_refresh =
        crate::clue_ownership::sign_clue_pk_ownership(&kp1.secret, 0x01, 1, &pk1, &clue_bytes);
    DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk1.to_vec(),
            clue_public_key: clue_bytes.clone(),
            ownership_proof: proof1_refresh,
            key_version: 1,
        }),
    )
    .await
    .expect("idempotent refresh of existing entry must succeed when full");

    #[cfg(feature = "fhe-omr")]
    let rotated_clue = {
        let (_, cpk) = crate::unifomr::clue_keypair_from_wallet(&[0x22u8; 32], 0x01).unwrap();
        crate::unifomr::serialize_public_key(&cpk)
    };
    #[cfg(not(feature = "fhe-omr"))]
    let rotated_clue = vec![0xDDu8; 32];

    let proof1_v2 =
        crate::clue_ownership::sign_clue_pk_ownership(&kp1.secret, 0x01, 2, &pk1, &rotated_clue);
    DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk1.to_vec(),
            clue_public_key: rotated_clue.clone(),
            ownership_proof: proof1_v2,
            key_version: 2,
        }),
    )
    .await
    .expect("higher key_version rotation of existing entry must succeed when full");

    let proof1_downgrade =
        crate::clue_ownership::sign_clue_pk_ownership(&kp1.secret, 0x01, 1, &pk1, &clue_bytes);
    let err_down = DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk1.to_vec(),
            clue_public_key: clue_bytes,
            ownership_proof: proof1_downgrade,
            key_version: 1,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err_down.code(), tonic::Code::InvalidArgument);

    let proof1_v0 =
        crate::clue_ownership::sign_clue_pk_ownership(&kp1.secret, 0x01, 0, &pk1, &rotated_clue);
    let err_v0 = DarkFiLightWallet::register_clue_public_key(
        &svc,
        Request::new(proto::CluePublicKeyRegistration {
            payment_pubkey: pk1.to_vec(),
            clue_public_key: rotated_clue,
            ownership_proof: proof1_v0,
            key_version: 0,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err_v0.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn get_clue_public_key_decoy_matches_client_key_version_and_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (svc, _) = test_service(Arc::clone(&cache));

    let attest_pk = svc.directory_attest_pubkey().unwrap();
    let unregistered = [0x42u8; 32];

    let r1 = DarkFiLightWallet::get_clue_public_key(
        &svc,
        Request::new(proto::PaymentPubkey {
            payment_pubkey: unregistered.to_vec(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let r2 = DarkFiLightWallet::get_clue_public_key(
        &svc,
        Request::new(proto::PaymentPubkey {
            payment_pubkey: unregistered.to_vec(),
        }),
    )
    .await
    .unwrap()
    .into_inner();

    assert!(r1.found, "decoy must report found=true");
    assert_eq!(
        r1.key_version, 1,
        "decoy key_version must match client constant 1"
    );
    assert_eq!(r1.clue_public_key.len(), CLUE_PUBLIC_KEY_WIRE_LEN);
    assert_eq!(
        r1.clue_public_key, r2.clue_public_key,
        "decoy key must be deterministic for the same payment_pubkey"
    );
    assert_eq!(
        r1.ownership_proof.len(),
        crate::clue_ownership::OWNERSHIP_PROOF_WIRE_LEN
    );
    crate::clue_ownership::verify_directory_attestation(
        &attest_pk,
        0x01,
        r1.key_version,
        &unregistered,
        &r1.clue_public_key,
        &r1.ownership_proof,
    )
    .expect("decoy directory attestation must verify against LightInfo key");
}

#[test]
fn peer_ip_handles_spoofed_xff_trusted_proxies_ipv6_and_multi_header() {
    use tonic::metadata::MetadataMap;

    let trusted = vec!["127.0.0.1".to_string(), "::1".to_string()];
    let loopback4: IpAddr = "127.0.0.1".parse().unwrap();
    let loopback6: IpAddr = "::1".parse().unwrap();
    let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    let direct_peer: IpAddr = "198.51.100.77".parse().unwrap();

    // 1. Untrusted direct peer: spoofed XFF must be completely ignored.
    let mut meta = MetadataMap::new();
    meta.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
    assert_eq!(resolve_peer_ip(direct_peer, &meta, &trusted), direct_peer);

    // 2. Empty trusted_proxies: XFF ignored even from loopback.
    assert_eq!(resolve_peer_ip(loopback4, &meta, &[]), loopback4);

    // 3. Trusted loopback proxy with spoofed leftmost IP: rightmost untrusted wins.
    let mut spoofed = MetadataMap::new();
    spoofed.insert(
        "x-forwarded-for",
        "1.2.3.4, 203.0.113.9, 127.0.0.1".parse().unwrap(),
    );
    assert_eq!(
        resolve_peer_ip(loopback4, &spoofed, &trusted),
        "203.0.113.9".parse::<IpAddr>().unwrap()
    );

    // 4. Multi-header HTTP/2 XFF (client sends spoofed header, proxy appends second header):
    //    rightmost header must win instead of metadata.get() returning the first spoofed value.
    let mut multi = MetadataMap::new();
    multi.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
    multi.append("x-forwarded-for", "203.0.113.55".parse().unwrap());
    assert_eq!(
        resolve_peer_ip(loopback4, &multi, &trusted),
        "203.0.113.55".parse::<IpAddr>().unwrap()
    );

    // 5. Trailing unparseable garbage must not fall through to a spoofed IP to its left.
    let mut garbage = MetadataMap::new();
    garbage.insert("x-forwarded-for", "1.2.3.4, not-an-ip".parse().unwrap());
    assert_eq!(resolve_peer_ip(loopback4, &garbage, &trusted), loopback4);

    // 6. IPv6 client behind IPv6 loopback proxy (`::1`).
    let mut v6_client = MetadataMap::new();
    v6_client.insert(
        "x-forwarded-for",
        "1.2.3.4, 2001:db8::42, ::1".parse().unwrap(),
    );
    assert_eq!(
        resolve_peer_ip(loopback6, &v6_client, &trusted),
        "2001:db8::42".parse::<IpAddr>().unwrap()
    );

    // 7. IPv4-mapped IPv6 proxy peer (`::ffff:127.0.0.1`) matches `"127.0.0.1"`
    //    and canonicalizes IPv4-mapped client hops.
    let mut mapped_client = MetadataMap::new();
    mapped_client.insert("x-forwarded-for", "::ffff:203.0.113.88".parse().unwrap());
    assert_eq!(
        resolve_peer_ip(mapped_loopback, &mapped_client, &trusted),
        "203.0.113.88".parse::<IpAddr>().unwrap()
    );

    // 8. All-trusted XFF chain falls back to the proxy peer IP.
    let mut all_trusted = MetadataMap::new();
    all_trusted.insert("x-forwarded-for", "127.0.0.1, ::1".parse().unwrap());
    assert_eq!(
        resolve_peer_ip(loopback4, &all_trusted, &trusted),
        loopback4
    );
}

#[test]
fn per_ip_rate_limiting_isolates_clients_behind_trusted_loopback_proxy() {
    use tonic::metadata::MetadataMap;

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (_tx, rx) = tokio::sync::watch::channel(0u32);
    let endpoint = url::Url::parse("http://127.0.0.1:9").unwrap();
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(endpoint));
    let trusted = vec!["127.0.0.1".to_string(), "::1".to_string()];
    let svc = LightWalletService::with_limits(
        cache,
        rpc,
        "test".into(),
        0x01,
        10,
        2,
        DEFAULT_MAX_TX_BYTES,
        rx,
        trusted.clone(),
    );
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();

    // Client A exhausts its 2/min bucket; rotating spoofed leftmost XFF
    // hops must still map to Client A (198.51.100.10) and stay blocked.
    let mut meta_a1 = MetadataMap::new();
    meta_a1.insert(
        "x-forwarded-for",
        "10.0.0.1, 198.51.100.10".parse().unwrap(),
    );
    let ip_a1 = resolve_peer_ip(loopback, &meta_a1, &trusted);

    let mut meta_a2 = MetadataMap::new();
    meta_a2.insert(
        "x-forwarded-for",
        "10.0.0.2, 198.51.100.10".parse().unwrap(),
    );
    let ip_a2 = resolve_peer_ip(loopback, &meta_a2, &trusted);

    let mut meta_a3 = MetadataMap::new();
    meta_a3.insert(
        "x-forwarded-for",
        "10.0.0.3, 198.51.100.10".parse().unwrap(),
    );
    let ip_a3 = resolve_peer_ip(loopback, &meta_a3, &trusted);

    assert_eq!(ip_a1, "198.51.100.10".parse::<IpAddr>().unwrap());
    assert_eq!(ip_a1, ip_a2);
    assert_eq!(ip_a2, ip_a3);
    assert!(svc.rpc_rate_limiter.check(ip_a1));
    assert!(svc.rpc_rate_limiter.check(ip_a2));
    assert!(
        !svc.rpc_rate_limiter.check(ip_a3),
        "client A must not bypass rate limit by spoofing leftmost XFF"
    );

    // Client B behind the same ngrok loopback proxy gets its own fresh bucket.
    let mut meta_b = MetadataMap::new();
    meta_b.insert("x-forwarded-for", "203.0.113.20".parse().unwrap());
    let ip_b = resolve_peer_ip(loopback, &meta_b, &trusted);
    assert_eq!(ip_b, "203.0.113.20".parse::<IpAddr>().unwrap());
    assert!(svc.rpc_rate_limiter.check(ip_b));
    assert!(svc.rpc_rate_limiter.check(ip_b));
    assert!(!svc.rpc_rate_limiter.check(ip_b));
}

#[tokio::test]
async fn service_metrics_counts_requests_rate_limits_and_active_streams() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());
    let (_tx, rx) = tokio::sync::watch::channel(0u32);
    let endpoint = url::Url::parse("http://127.0.0.1:9").unwrap();
    let rpc = Arc::new(crate::rpc_client::DarkfidRpcClient::new_simple(endpoint));
    // Allow 2 RPCs/min so the 3rd triggers rate_limited.
    let svc = LightWalletService::with_limits(
        cache,
        rpc,
        "test".into(),
        0x01,
        10,
        2,
        DEFAULT_MAX_TX_BYTES,
        rx,
        Vec::new(),
    );
    let metrics = svc.metrics();
    assert_eq!(
        metrics.snapshot(),
        MetricsSnapshot {
            rpc_requests: 0,
            rate_limited: 0,
            active_streams: 0,
            omr_digest_requests: 0,
            omr_digest_ms_total: 0,
            pir_requests: 0,
            pir_limbs_total: 0,
            pir_ms_total: 0,
        }
    );

    let stream = DarkFiLightWallet::subscribe_blocks(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap();
    assert_eq!(metrics.snapshot().rpc_requests, 1);
    assert_eq!(metrics.snapshot().active_streams, 1);

    let _ = DarkFiLightWallet::get_omr_capabilities(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap();
    let err = DarkFiLightWallet::get_omr_capabilities(&svc, Request::new(proto::Empty {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    let snap = metrics.snapshot();
    assert_eq!(snap.rpc_requests, 3);
    assert_eq!(snap.rate_limited, 1);
    assert_eq!(snap.active_streams, 1);

    drop(stream);
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(metrics.snapshot().active_streams, 0);
}

#[cfg(feature = "fhe-omr")]
#[tokio::test]
async fn unifomr_v2_pooled_digest_and_streaming_pir_e2e() {
    use prost::Message;
    use tokio_stream::StreamExt;

    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());

    let alice = [0x42u8; 32];
    let bob = [0x99u8; 32];
    let alice_client = crate::unifomr::UnifOmrClient::from_wallet(&alice, 0x01).unwrap();
    let (_, alice_pk) = crate::unifomr::clue_keypair_from_wallet(&alice, 0x01).unwrap();
    let (_, bob_pk) = crate::unifomr::clue_keypair_from_wallet(&bob, 0x01).unwrap();

    let mut rng = rand::rng();
    let mut prev_hash = [0u8; 32];
    let target_height = 512u32;
    let tip_height = 1023u32;
    for height in 0u32..=tip_height {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&height.to_be_bytes());
        let clue = if height == target_height {
            crate::unifomr::serialize_clue(&alice_pk.encrypt_zeros(&mut rng))
        } else {
            crate::unifomr::serialize_clue(&bob_pk.encrypt_zeros(&mut rng))
        };
        let txs = if height == target_height || height % 256 == 0 {
            let coin = if height == target_height {
                let mut c = [0u8; 32];
                c[0] = 0x77;
                c
            } else {
                let mut c = [0u8; 32];
                c[0] = 0x22;
                c
            };
            vec![crate::compact_block::CompactTx {
                tx_hash: [height as u8; 32],
                outputs: vec![crate::compact_block::CompactOutput {
                    coin,
                    encrypted_note: vec![if height == target_height { 0xAB } else { 0x01 }; 320],
                    value_commit: vec![0x33; 33],
                    token_commit: [0x44; 32],
                    omr_clue: clue,
                    omr_metadata_enc: vec![0x55; 64],
                    func_code: 0,
                }],
                nullifiers: Vec::new(),
                fee: 100,
            }]
        } else {
            Vec::new()
        };
        cache
            .insert_compact_block(&crate::compact_block::CompactBlock {
                height,
                hash,
                prev_hash,
                timestamp: 1_780_000_000 + height as u64,
                txs,
                dao_calls: Vec::new(),
                func_events: Vec::new(),
            })
            .unwrap();
        prev_hash = hash;
    }

    let (svc, _) = test_service(Arc::clone(&cache));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let server_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(proto::dark_fi_light_wallet_server::DarkFiLightWalletServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    let mut client = proto::dark_fi_light_wallet_client::DarkFiLightWalletClient::connect(
        format!("http://{addr}"),
    )
    .await
    .unwrap();

    // Verify capabilities report unifomr-v2 and LightInfo reports 2.2.0.
    let info = client.get_light_info(proto::Empty {}).await.unwrap().into_inner();
    assert_eq!(info.proto_version, "2.2.0");
    let caps = client
        .get_omr_capabilities(proto::Empty {})
        .await
        .unwrap()
        .into_inner();
    assert!(caps.enabled);
    assert_eq!(caps.scheme, "unifomr-v2");

    // 1. Upload v3 detection key once via RegisterDetectionKey.
    let det_key = alice_client.build_detection_key(0x01).unwrap();
    let chunks: Vec<proto::DetectionKeyChunk> = det_key
        .chunks(1024 * 1024)
        .enumerate()
        .map(|(i, sl)| {
            let is_last = (i + 1) * (1024 * 1024) >= det_key.len();
            proto::DetectionKeyChunk {
                start_height: 0,
                end_height: tip_height,
                num_keys: if i == 0 { 1 } else { 0 },
                data: sl.to_vec(),
                key_done: is_last,
            }
        })
        .collect();
    let reg = client
        .register_detection_key(tokio_stream::iter(chunks))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reg.handle.len(), 32);

    // 2. Fetch compact OMR digest from pooled handle.
    let digest_resp = client
        .get_unif_omr_digest_from_pool(proto::PoolDigestRequest {
            handle: reg.handle,
            start_height: 0,
            end_height: tip_height,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(digest_resp.complete);
    let slot_heights = crate::unifomr::unpack_slot_heights(&digest_resp.slot_heights).unwrap();
    let matched = alice_client
        .decrypt_matching_heights(&digest_resp.encrypted_digest, &slot_heights)
        .unwrap();
    assert_eq!(matched, vec![target_height]);

    // 3. Round-2 PIR: length limb via FetchPirBatch + body limbs via FetchPirBatchStream.
    let pir_client = crate::pir_server::BatchPirClient::from_wallet(&alice, 0x01).unwrap();
    let window = (tip_height + 1) as usize;
    let queries = pir_client
        .generate_sealpir_queries(&[target_height as usize], window)
        .unwrap();

    let len_resp = client
        .fetch_pir_batch(proto::BatchPirRequest {
            query_ciphertexts: queries.clone(),
            start_height: 0,
            end_height: tip_height,
            limb_index: 0,
            limb_count: 1,
        })
        .await
        .unwrap()
        .into_inner();
    let len_col = pir_client
        .decrypt_sealpir_stripes(&len_resp.payload_ciphertexts, window)
        .unwrap();
    let needed_limbs =
        crate::pir_server::pir_payload_limb_count(len_col[target_height as usize]).unwrap();
    let padded_limbs = crate::pir_server::padded_limb_count(needed_limbs);

    let mut pir_stream = client
        .fetch_pir_batch_stream(proto::BatchPirRequest {
            query_ciphertexts: queries,
            start_height: 0,
            end_height: tip_height,
            limb_index: 1,
            limb_count: (padded_limbs - 1) as u32,
        })
        .await
        .unwrap()
        .into_inner();

    let mut limb_cols = vec![len_col];
    while let Some(chunk) = pir_stream.next().await {
        let chunk = chunk.unwrap();
        limb_cols.push(
            pir_client
                .decrypt_sealpir_stripes(&chunk.payload_ciphertexts, window)
                .unwrap(),
        );
    }
    assert_eq!(limb_cols.len(), padded_limbs);
    let payloads = crate::pir_server::assemble_payloads(&[target_height as usize], &limb_cols);
    let recovered = proto::CompactBlock::decode(payloads[0].as_slice()).unwrap();
    assert_eq!(recovered.height, target_height);
    let mut expected_coin = vec![0u8; 32];
    expected_coin[0] = 0x77;
    assert_eq!(recovered.txs[0].outputs[0].coin, expected_coin);
    assert!(recovered.txs[0].outputs[0].omr_clue.is_empty());

    server_handle.abort();
}
