use super::*;

#[tonic::async_trait]
impl DarkFiLightWallet for LightWalletService {
    type GetBlockRangeStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactBlock, Status>>;

    type GetCompactOutputBodiesStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactOutputBody, Status>>;

    /// Stream one compact output body per Money output in a padded range.
    async fn get_compact_output_bodies(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetCompactOutputBodiesStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;
        let permit = self.acquire_block_range().await?;
        let stream_guard = self.metrics.track_stream();
        Ok(Response::new(spawn_output_bodies(
            Arc::clone(&self.cache),
            start,
            end,
            permit,
            stream_guard,
        )))
    }

    type GetCompactOutputsByFuncStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactOutputBody, Status>>;

    /// Money outputs of one function code, plus auth-token events with an empty note.
    async fn get_compact_outputs_by_func(
        &self,
        request: Request<proto::FuncBlockRange>,
    ) -> Result<Response<Self::GetCompactOutputsByFuncStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;
        let permit = self.acquire_block_range().await?;
        let stream_guard = self.metrics.track_stream();
        Ok(Response::new(spawn_outputs_by_func(
            Arc::clone(&self.cache),
            start,
            end,
            range.func_code,
            permit,
            stream_guard,
        )))
    }

    type GetCompactDaoCallsStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactDaoCall, Status>>;

    /// DAO mint, propose, vote, exec, and auth-transfer records. Proofs are omitted.
    async fn get_compact_dao_calls(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetCompactDaoCallsStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;
        let permit = self.acquire_block_range().await?;
        let stream_guard = self.metrics.track_stream();
        Ok(Response::new(spawn_dao_calls(
            Arc::clone(&self.cache),
            start,
            end,
            permit,
            stream_guard,
        )))
    }

    /// Stream compact blocks in a height range.
    async fn get_block_range(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) = resolve_block_range(&self.cache, range.start_height, range.end_height)?;

        let permit = self.acquire_block_range().await?;
        let stream_guard = self.metrics.track_stream();
        Ok(Response::new(spawn_compact_range(
            Arc::clone(&self.cache),
            start,
            end,
            permit,
            stream_guard,
            CompactBlock::to_proto,
        )))
    }

    /// Get a single compact block by height.
    async fn get_block(
        &self,
        request: Request<proto::BlockHeight>,
    ) -> Result<Response<proto::CompactBlock>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let height = request.into_inner().height;

        match self.cache.get_compact_block(height) {
            Ok(Some(block)) => Ok(Response::new(block.to_proto())),
            Ok(None) => Err(Status::not_found(format!(
                "Block not found at height {height}"
            ))),
            Err(e) => Err(cache_status(e)),
        }
    }

    type GetCompactBlocksAtHeightsStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CompactBlock, Status>>;

    /// Stream compact blocks at specific heights (sparse fetch).
    ///
    /// Rejects empty lists and lists over [`MAX_SPARSE_HEIGHTS`]. Server
    /// sorts/dedups. Returns NOT_FOUND if any requested height is missing
    /// so tip advance stays correct.
    async fn get_compact_blocks_at_heights(
        &self,
        request: Request<proto::HeightList>,
    ) -> Result<Response<Self::GetCompactBlocksAtHeightsStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let mut heights = request.into_inner().heights;
        if heights.is_empty() {
            return Err(Status::invalid_argument(
                "HeightList.heights must not be empty",
            ));
        }
        if heights.len() > MAX_SPARSE_HEIGHTS {
            return Err(Status::invalid_argument(format!(
                "Too many heights: {} requested, max is {MAX_SPARSE_HEIGHTS}",
                heights.len()
            )));
        }

        heights.sort_unstable();
        heights.dedup();

        // Acquire a block-range permit before running blocking sled reads, and
        // hold it until streaming completes.
        let permit = self.acquire_block_range().await?;
        let cache = Arc::clone(&self.cache);
        #[allow(clippy::result_large_err)]
        let blocks = tokio::task::spawn_blocking(move || {
            let mut blocks = Vec::with_capacity(heights.len());
            for &h in &heights {
                match cache.get_compact_block(h) {
                    Ok(Some(block)) => blocks.push(block),
                    Ok(None) => {
                        return Err(Status::not_found(format!("Block not found at height {h}")));
                    }
                    Err(e) => return Err(cache_status(e)),
                }
            }
            for w in blocks.windows(2) {
                check_adjacent_pair(&w[0], &w[1])?;
            }
            Ok::<Vec<CompactBlock>, Status>(blocks)
        })
        .await
        .map_err(|e| Status::internal(format!("block fetch worker join error: {e}")))??;

        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let stream_guard = self.metrics.track_stream();

        tokio::spawn(async move {
            let _permit = permit;
            let _stream_guard = stream_guard;
            for block in blocks {
                if tx.is_closed() {
                    return;
                }
                if !send_stream(&tx, Ok(block.to_proto())).await {
                    break;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Get the current chain tip.
    async fn get_chain_tip(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<Response<proto::ChainTip>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        for attempt in 0..2 {
            match self.cache.get_tip() {
                Ok(Some((height, hash))) => {
                    let block = self.cache.get_compact_block(height).map_err(cache_status)?;
                    if let Some(ref b) = block {
                        if b.hash != hash {
                            if attempt == 0 {
                                continue;
                            }
                            return Err(Status::aborted("concurrent chain tip update"));
                        }
                    } else if attempt == 0 {
                        continue;
                    } else {
                        return Err(Status::aborted("concurrent chain tip update"));
                    }
                    let timestamp = block.as_ref().map(|b| b.timestamp).unwrap_or(0);
                    let prev_hash = block.map(|b| b.prev_hash.to_vec()).unwrap_or_default();

                    let block_target = self.block_target_for_tip(height, hash).await;

                    return Ok(Response::new(proto::ChainTip {
                        height,
                        hash: hash.to_vec(),
                        timestamp,
                        block_target,
                        prev_hash,
                    }));
                }
                Ok(None) => return Err(Status::unavailable("No blocks cached yet")),
                Err(e) => return Err(cache_status(e)),
            }
        }
        Err(Status::aborted("concurrent chain tip update"))
    }

    type SubscribeBlocksStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::ChainTip, Status>>;

    /// Stream [`proto::ChainTip`] when the poller watch fires.
    ///
    /// A slow client is not disconnected. If the one-slot buffer is full the
    /// notice is skipped; the next tip the client reads covers the gap.
    async fn subscribe_blocks(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<Response<Self::SubscribeBlocksStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let peer_slot = Self::try_slot(&self.subscribe_slots, self.peer_rate_ip(&request), 8)
            .map_err(|_| {
                Status::resource_exhausted("too many SubscribeBlocks streams from peer")
            })?;
        let permit = Arc::clone(&self.subscribe_permits)
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("too many active SubscribeBlocks streams; retry later")
            })?;
        let cache = Arc::clone(&self.cache);
        let rpc = Arc::clone(&self.rpc_client);
        let tip_facts = Arc::clone(&self.tip_facts);
        let tip_fact_fetch = Arc::clone(&self.tip_fact_fetch);
        let mut tip_rx = self.tip_notify.clone();
        let notice = Arc::clone(&self.tip_notice);
        let (tx, rx) = tokio::sync::mpsc::channel(SUBSCRIBE_TIP_BUFFER);
        let stream_guard = self.metrics.track_stream();

        tokio::spawn(async move {
            let _peer_slot = peer_slot;
            let _permit = permit;
            let _stream_guard = stream_guard;
            loop {
                tokio::select! {
                    biased;
                    _ = tx.closed() => return,
                    changed = tip_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                // Wakeup only. The payload is the cache tip, so a rewind is visible.
                let _watched = *tip_rx.borrow_and_update();

                let Some((height, hash)) = cache.get_tip().unwrap_or(None) else {
                    notice.notify_one();
                    continue;
                };
                let block = match cache.get_compact_block(height) {
                    Ok(Some(b)) if b.hash == hash => b,
                    Ok(Some(_)) | Ok(None) => {
                        tracing::warn!(
                            target: "lightwalletd::server",
                            "SubscribeBlocks skipped torn or missing tip block"
                        );
                        notice.notify_one();
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(
                            target: "lightwalletd::server",
                            "SubscribeBlocks cache error: {e}"
                        );
                        notice.notify_one();
                        continue;
                    }
                };
                let block_target = block_target_from(
                    &tip_facts,
                    &cache,
                    &tip_fact_fetch,
                    &rpc,
                    height,
                    hash,
                    Duration::from_millis(200),
                )
                .await;
                let chain_tip = proto::ChainTip {
                    height,
                    hash: hash.to_vec(),
                    timestamp: block.timestamp,
                    block_target,
                    prev_hash: block.prev_hash.to_vec(),
                };
                match tx.try_send(Ok(chain_tip)) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        tracing::debug!(
                            target: "lightwalletd::server",
                            "SubscribeBlocks client is behind; skipping this tip notice"
                        );
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
                notice.notify_one();
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Get a full transaction by hash.
    async fn get_transaction(
        &self,
        request: Request<proto::TxHash>,
    ) -> Result<Response<proto::RawTransaction>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let hash = request.into_inner().hash;
        if hash.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "transaction hash must be 32 bytes, got {}",
                hash.len()
            )));
        }
        let hash_hex = hex::encode(&hash);

        match self.rpc_client.get_tx(&hash_hex).await {
            Ok(tx_bytes) => Ok(Response::new(proto::RawTransaction {
                data: tx_bytes,
                omr_clue: vec![],
                omr_clue_output_index: 0,
                omr_metadata_enc: vec![],
                extra_omr_clues: vec![],
            })),
            Err(e) if e.is_connection() => Err(backend_unavailable()),
            Err(_) => {
                if let Ok(pending) = self.rpc_client.get_pending_tx_hashes().await {
                    if pending.iter().any(|h| h == &hash_hex) {
                        if let Ok(arr) = <[u8; 32]>::try_from(hash.as_slice()) {
                            if let Some(tx_bytes) = self.cached_mempool_tx(&arr) {
                                return Ok(Response::new(proto::RawTransaction {
                                    data: tx_bytes,
                                    omr_clue: vec![],
                                    omr_clue_output_index: 0,
                                    omr_metadata_enc: vec![],
                                    extra_omr_clues: vec![],
                                }));
                            }
                        }
                    }
                }
                Err(Status::not_found("transaction not found"))
            }
        }
    }

    /// Submit a signed transaction.
    ///
    /// SECURITY: Error messages are sanitized to prevent leaking darkfid
    /// internal state (RPC errors, stack traces, contract names) to the
    /// wallet client.
    async fn send_transaction(
        &self,
        request: Request<proto::RawTransaction>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let peer = self.peer_rate_ip(&request);
        let mut req = request.into_inner();
        let (tx_data, mut omr_clue, mut metadata_enc) =
            if req.data.starts_with(crate::omr_envelope::OMR_ENVELOPE_TAG) {
                let env = crate::omr_envelope::parse_envelope(&req.data).ok_or_else(|| {
                    Status::invalid_argument("malformed OMR envelope on SendTransaction")
                })?;
                let clue = if req.omr_clue.is_empty() && !env.fhe_clue.is_empty() {
                    env.fhe_clue.to_vec()
                } else {
                    std::mem::take(&mut req.omr_clue)
                };
                let memo = if req.omr_metadata_enc.is_empty() && !env.omr_memo.is_empty() {
                    env.omr_memo.to_vec()
                } else {
                    std::mem::take(&mut req.omr_metadata_enc)
                };
                (env.raw_tx.to_vec(), clue, memo)
            } else {
                (
                    std::mem::take(&mut req.data),
                    std::mem::take(&mut req.omr_clue),
                    std::mem::take(&mut req.omr_metadata_enc),
                )
            };
        if req.extra_omr_clues.len() > MAX_EXTRA_OMR_CLUES {
            return Err(Status::invalid_argument(format!(
                "extra_omr_clues length {} exceeds limit {}",
                req.extra_omr_clues.len(),
                MAX_EXTRA_OMR_CLUES
            )));
        }

        if tx_data.len() > self.max_tx_bytes {
            return Err(Status::invalid_argument(format!(
                "transaction size {} exceeds limit {}",
                tx_data.len(),
                self.max_tx_bytes
            )));
        }

        // Pre-compute tx hash so we can index OMR clues & metadata before the block lands.
        let tx_hash_for_clue = darkfi_serial::deserialize::<darkfi::tx::Transaction>(&tx_data)
            .ok()
            .map(|tx| *tx.hash().inner());

        // Validate primary clue, extra clues (even if primary is empty), and metadata up front.
        let primary_clue_present = !omr_clue.is_empty();
        if primary_clue_present {
            // S12: validate on SendTransaction the same as RegisterOmrClue.
            if let Err(e) = Self::validate_omr_clue(&omr_clue) {
                tracing::warn!(
                    target: "lightwalletd::server",
                    "Rejecting OMR clue on SendTransaction: {e}"
                );
                omr_clue.clear();
            }
        }

        let mut pending_extra_clues: Vec<(u32, Vec<u8>)> = Vec::new();
        for extra in &req.extra_omr_clues {
            if extra.omr_clue.is_empty() {
                continue;
            }
            if let Err(e) = Self::validate_omr_clue(&extra.omr_clue) {
                tracing::warn!(
                    target: "lightwalletd::server",
                    "Rejecting extra OMR clue on SendTransaction: {e}"
                );
                continue;
            }
            pending_extra_clues.push((extra.output_index, extra.omr_clue.clone()));
        }

        let mut pending_metadata_enc = if metadata_enc.len() > MAX_OMR_METADATA_ENC_BYTES {
            tracing::warn!(
                target: "lightwalletd::server",
                "Rejecting omr_metadata_enc: {} bytes (max {MAX_OMR_METADATA_ENC_BYTES})",
                metadata_enc.len()
            );
            Vec::new()
        } else {
            std::mem::take(&mut metadata_enc)
        };

        // S22: surface whether the attached clue was accepted (tx may still succeed).
        let mut clue_accepted = false;
        let mut added_clue_indices: Vec<u32> = Vec::new();
        let mut stored_metadata_pre_broadcast = false;

        if let Some(hash) = tx_hash_for_clue {
            // Stored before broadcast: the tx can be mined (and the block
            // indexed) before broadcast_tx returns.
            if !omr_clue.is_empty() {
                clue_accepted = self.store_send_clue_hint(
                    &hash,
                    std::mem::take(&mut omr_clue),
                    req.omr_clue_output_index,
                );
                if clue_accepted {
                    added_clue_indices.push(req.omr_clue_output_index);
                }
            }
            for (idx, clue) in std::mem::take(&mut pending_extra_clues) {
                if self.store_send_clue_hint(&hash, clue, idx) {
                    added_clue_indices.push(idx);
                    if !primary_clue_present {
                        clue_accepted = true;
                    }
                }
            }
            if !pending_metadata_enc.is_empty() {
                stored_metadata_pre_broadcast = self.store_send_metadata_enc(
                    &hash,
                    std::mem::take(&mut pending_metadata_enc),
                    req.omr_clue_output_index,
                );
            }
        }

        let cleanup_pre_broadcast = |hash: &[u8; 32]| {
            if !added_clue_indices.is_empty() {
                if let Err(e) = self
                    .cache
                    .remove_omr_clue_hint_indices(hash, &added_clue_indices)
                {
                    tracing::warn!(
                        target: "lightwalletd::server",
                        "Failed to drop OMR clue hint for rejected tx: {e}"
                    );
                }
            }
            if stored_metadata_pre_broadcast {
                if let Err(e) = self.cache.remove_omr_metadata_enc(hash) {
                    tracing::warn!(
                        target: "lightwalletd::server",
                        "Failed to drop OMR metadata_enc for rejected tx: {e}"
                    );
                }
            }
        };

        let broadcast_timeout = self.rpc_client.timeout();
        match tokio::time::timeout(broadcast_timeout, self.rpc_client.broadcast_tx(&tx_data)).await
        {
            Ok(Ok(tx_hash)) => {
                let followup = match self.confirm_tx_in_mempool_or_chain(&tx_hash).await {
                    Ok(true) => PreBroadcastFollowup::Confirmed,
                    Ok(false) => PreBroadcastFollowup::NotConfirmed,
                    Err(e) if e.is_connection() => PreBroadcastFollowup::ConfirmConnectionError,
                    Err(_) => PreBroadcastFollowup::NotConfirmed,
                };
                // Connection loss after `Ok(tx_hash)` keeps the clue. The node
                // may already have the transaction; the 24h TTL reaps the rows.
                if drop_pre_broadcast_rows(followup) {
                    if let Some(hash) = tx_hash_for_clue {
                        cleanup_pre_broadcast(&hash);
                    }
                }
                if followup == PreBroadcastFollowup::ConfirmConnectionError {
                    return Err(backend_unavailable());
                }
                if followup != PreBroadcastFollowup::Confirmed {
                    return Ok(Response::new(proto::SendResponse {
                        tx_hash: Vec::new(),
                        error: "Transaction was not confirmed in lightwalletd mempool".to_string(),
                        clue_accepted: false,
                    }));
                }

                let tx_hash_bytes = hex::decode(&tx_hash).unwrap_or_else(|_| {
                    tracing::warn!(
                        target: "lightwalletd::server",
                        "Darkfid returned non-hex tx_hash: redacted (len={})",
                        tx_hash.len()
                    );
                    Vec::new()
                });

                let hash = tx_hash_for_clue.or_else(|| {
                    if tx_hash_bytes.len() == 32 {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&tx_hash_bytes);
                        Some(h)
                    } else {
                        None
                    }
                });

                // Remember mempool raw tx bytes so GetTransaction can also confirm mempool presence.
                if let Some(hash) = hash {
                    self.remember_mempool_tx(hash, tx_data.clone());
                }

                // S12: remember which peer submitted this tx so RegisterOmrClue
                // can be bound to the same peer when clue arrives out-of-band.
                if let Some(hash) = hash {
                    self.remember_send_peer(hash, peer);
                }

                // Store any validated clues / metadata whose tx hash only darkfid could tell us
                // (already taken above if `tx_hash_for_clue` was `Some`, so never stored twice).
                if let Some(hash) = hash {
                    if !omr_clue.is_empty() {
                        clue_accepted =
                            self.store_send_clue_hint(&hash, omr_clue, req.omr_clue_output_index);
                    }
                    for (idx, clue) in pending_extra_clues {
                        if self.store_send_clue_hint(&hash, clue, idx) && !primary_clue_present {
                            clue_accepted = true;
                        }
                    }
                    if !pending_metadata_enc.is_empty() {
                        let _ = self.store_send_metadata_enc(
                            &hash,
                            pending_metadata_enc,
                            req.omr_clue_output_index,
                        );
                    }
                }

                Ok(Response::new(proto::SendResponse {
                    tx_hash: tx_hash_bytes,
                    error: String::new(),
                    clue_accepted,
                }))
            }
            Ok(Err(e)) => {
                tracing::error!(
                    target: "lightwalletd::server",
                    "Transaction broadcast failed: {e}"
                );
                // Rejected txs must not park clue hints or metadata for the full TTL.
                if drop_pre_broadcast_rows(PreBroadcastFollowup::BroadcastFailed) {
                    if let Some(hash) = tx_hash_for_clue {
                        cleanup_pre_broadcast(&hash);
                    }
                }
                Ok(Response::new(proto::SendResponse {
                    tx_hash: Vec::new(),
                    error: "Transaction broadcast failed".to_string(),
                    clue_accepted: false,
                }))
            }
            Err(_elapsed) => {
                let secs = broadcast_timeout.as_secs();
                tracing::error!(
                    target: "lightwalletd::server",
                    "Transaction broadcast timed out after {secs} seconds"
                );
                Err(Status::deadline_exceeded(format!(
                    "Transaction broadcast timeout after {secs}s"
                )))
            }
        }
    }

    type GetNoteCommitmentsStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::NoteCommitmentUpdate, Status>>;

    /// Get note commitments for a block range.
    async fn get_note_commitments(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetNoteCommitmentsStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;

        let permit = self.acquire_block_range().await?;
        let stream_guard = self.metrics.track_stream();
        Ok(Response::new(spawn_compact_range(
            Arc::clone(&self.cache),
            start,
            end,
            permit,
            stream_guard,
            |block| proto::NoteCommitmentUpdate {
                height: block.height,
                coins: block
                    .txs
                    .iter()
                    .flat_map(|tx| tx.outputs.iter().map(|o| o.coin.to_vec()))
                    .collect(),
            },
        )))
    }

    type GetNullifiersStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::NullifierUpdate, Status>>;

    /// Get nullifiers for a block range.
    async fn get_nullifiers(
        &self,
        request: Request<proto::BlockRange>,
    ) -> Result<Response<Self::GetNullifiersStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let range = request.into_inner();
        let (start, end) =
            require_padded_block_range(&self.cache, range.start_height, range.end_height)?;

        let permit = self.acquire_block_range().await?;
        let stream_guard = self.metrics.track_stream();
        Ok(Response::new(spawn_compact_range(
            Arc::clone(&self.cache),
            start,
            end,
            permit,
            stream_guard,
            |block| proto::NullifierUpdate {
                height: block.height,
                nullifiers: block
                    .txs
                    .iter()
                    .flat_map(|tx| tx.nullifiers.iter().map(|n| n.to_vec()))
                    .collect(),
            },
        )))
    }

    /// Merkle tree at the tip or a retained snapshot.
    ///
    /// Other heights are `FAILED_PRECONDITION`. The status text includes the
    /// greatest stored snapshot `<=` the request.
    async fn get_tree_state(
        &self,
        request: Request<proto::BlockHeight>,
    ) -> Result<Response<proto::TreeState>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let height = request.into_inner().height;
        let tip = self
            .cache
            .get_tip()
            .map_err(cache_status)?
            .map(|(h, _)| h)
            .unwrap_or(0);

        if height == tip {
            return match self.cache.get_tip_tree_state().map_err(cache_status)? {
                Some((tree_height, tree_data)) if tree_height == tip => {
                    let block_hash = block_hash_vec(&self.cache, tree_height);
                    Ok(Response::new(persisted_tree_state(
                        tree_height,
                        tree_data,
                        block_hash,
                    )))
                }
                Some((tree_height, _)) => Err(Status::failed_precondition(format!(
                    "Tip Merkle tree height {tree_height} does not match tip {tip}; resync required"
                ))),
                None => {
                    if tip == 0 {
                        // Nothing indexed yet: match Cache::empty_tip_tree() sentinel leaf.
                        let tree = Cache::empty_tip_tree();
                        let tree_data = darkfi_serial::serialize(&tree);
                        let state_root = blake3::hash(&tree_data).as_bytes().to_vec();
                        Ok(Response::new(proto::TreeState {
                            height: 0,
                            tree_data,
                            block_hash: vec![],
                            state_root,
                            is_checkpoint: false,
                        }))
                    } else {
                        Err(Status::not_found(
                            "Tip Merkle tree not available yet; wait for chain poller to index blocks",
                        ))
                    }
                }
            };
        }

        if let Some(tree_data) = self.cache.merkle_snapshot(height).map_err(cache_status)? {
            let block_hash = block_hash_vec(&self.cache, height);
            return Ok(Response::new(persisted_tree_state(
                height, tree_data, block_hash,
            )));
        }

        let lower = self
            .cache
            .greatest_snapshot_at_or_below(height)
            .map_err(cache_status)?
            .map(|(h, _)| h);
        Err(snapshot_miss_status(height, tip, lower))
    }

    type GetCheckpointSnapshotStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::CheckpointSnapshot, Status>>;

    /// Stream a retained snapshot in 1 MiB `tree_data` chunks.
    ///
    /// `preferred_height == 0` is the latest snapshot. Otherwise the greatest
    /// snapshot at or below that height. `NOT_FOUND` when none exist.
    async fn get_checkpoint_snapshot(
        &self,
        request: Request<proto::CheckpointRequest>,
    ) -> Result<Response<Self::GetCheckpointSnapshotStream>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let preferred = request.into_inner().preferred_height;
        let permit = self.acquire_block_range().await?;
        let found = if preferred == 0 {
            self.cache.latest_snapshot().map_err(cache_status)?
        } else {
            self.cache
                .greatest_snapshot_at_or_below(preferred)
                .map_err(cache_status)?
        };
        let Some((tree_height, tree_data)) = found else {
            return Err(Status::not_found(
                "no checkpoint snapshot at or below the requested height",
            ));
        };

        let block_hash = block_hash_vec(&self.cache, tree_height);
        // CompactBlock does not store the header money-tree root. state_root
        // stays blake3(tree_data); see the snapshot unit test.
        let state_root = blake3::hash(&tree_data).as_bytes().to_vec();
        let snapshot_hash = snapshot_integrity_hash(tree_height, &tree_data, &[]).to_vec();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let stream_guard = self.metrics.track_stream();

        tokio::spawn(async move {
            let _permit = permit;
            let _stream_guard = stream_guard;
            const CHUNK_SIZE: usize = 1024 * 1024;
            let total_chunks = if tree_data.is_empty() {
                1
            } else {
                tree_data.len().div_ceil(CHUNK_SIZE)
            };

            for i in 0..total_chunks {
                let start = i * CHUNK_SIZE;
                let end = std::cmp::min(start + CHUNK_SIZE, tree_data.len());
                let chunk_data = if tree_data.is_empty() {
                    vec![]
                } else {
                    tree_data[start..end].to_vec()
                };
                let snapshot = proto::CheckpointSnapshot {
                    height: tree_height,
                    block_hash: block_hash.clone(),
                    state_root: state_root.clone(),
                    tree_data: chunk_data,
                    nullifier_index: vec![],
                    scan_cursor: tree_height,
                    snapshot_hash: snapshot_hash.clone(),
                };
                if !send_stream(&tx, Ok(snapshot)).await {
                    break;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Lookup zkas bincodes for a contract.
    async fn lookup_zkas(
        &self,
        request: Request<proto::ContractId>,
    ) -> Result<Response<proto::ZkasResponse>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let contract_id = request.into_inner().id;
        if contract_id.is_empty() || contract_id.len() > MAX_CONTRACT_ID_CHARS {
            return Err(Status::invalid_argument("invalid contract id"));
        }

        match self.rpc_client.lookup_zkas(&contract_id).await {
            Ok(bincodes) => {
                let proto_bincodes: Vec<proto::ZkasBincode> = bincodes
                    .into_iter()
                    .map(|(ns, bc)| proto::ZkasBincode {
                        namespace: ns,
                        bincode: bc,
                    })
                    .collect();
                Ok(Response::new(proto::ZkasResponse {
                    bincodes: proto_bincodes,
                }))
            }
            Err(e) if e.is_connection() => Err(backend_unavailable()),
            Err(_) => Err(Status::not_found("contract not found")),
        }
    }

    /// Get server metadata.
    async fn get_light_info(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<Response<proto::LightInfo>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        let (height, hash) = self
            .cache
            .get_tip()
            .map_err(cache_status)?
            .unwrap_or((0, [0u8; 32]));

        // darkfid RPC can stall during heavy sync; never block LightInfo forever.
        // Both values are cached until the tip height or hash changes.
        let block_target = self.block_target_for_tip(height, hash).await;
        let difficulty = self.difficulty_for_tip(height, hash).await;

        Ok(Response::new(proto::LightInfo {
            version: self.version.clone(),
            chain_name: self.chain_name.clone(),
            block_height: height,
            block_target,
            difficulty,
            omr_supported: cfg!(feature = "fhe-omr"),
            best_block_hash: hash.to_vec(),
            backend_version: format!(
                "lightwalletd {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_HASH").unwrap_or("unknown")
            ),
            directory_attest_pubkey: self.directory_attest_pubkey()?.to_vec(),
            proto_version: LIGHTWALLET_PROTO_VERSION.to_string(),
            tip_fetched_unix: self.cache.tip_fetched_unix().map_err(cache_status)?,
        }))
    }

    /// Get OMR capabilities.
    ///
    /// The default server build reports UnifOMR disabled. Wallets then use
    /// padded trial decryption. `fhe-omr` is the only build that advertises
    /// the experimental scheme.
    async fn get_omr_capabilities(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<Response<proto::OmrCapabilities>, Status> {
        self.metrics.record_request();
        self.check_rpc_rate_limit(&request)?;
        #[cfg(feature = "fhe-omr")]
        {
            Ok(Response::new(proto::OmrCapabilities {
                enabled: true,
                scheme: "unifomr".to_string(),
                // Honest MVP: paper FP rates are not claimed (see unifomr_mvp_limits.md).
                false_positive_rate: 0.0,
                max_range_per_request: 10_000,
            }))
        }
        #[cfg(not(feature = "fhe-omr"))]
        {
            Ok(Response::new(proto::OmrCapabilities {
                enabled: false,
                scheme: String::new(),
                false_positive_rate: 0.0,
                max_range_per_request: 0,
            }))
        }
    }

    /// Register a sender-supplied UnifOMR clue for a pending transaction.
    ///
    /// Transitional until consensus-native `CompactOutput.omr_clue`. Validates
    /// clue size/structure via `validate_unifomr_clue` before storing (S12). When
    /// the tx was previously submitted via SendTransaction, Register must come
    /// from the same peer within the bind TTL.
    async fn register_omr_clue(
        &self,
        request: Request<proto::OmrClueRegistration>,
    ) -> Result<Response<proto::Empty>, Status> {
        self.metrics.record_request();
        // Prefer clue-on-SendTransaction; standalone Register is transitional and rate-limited.
        self.check_clue_rate_limit(&request)?;
        let peer = self.peer_ip(&request);

        let req = request.into_inner();
        if req.tx_hash.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "tx_hash must be 32 bytes, got {}",
                req.tx_hash.len()
            )));
        }
        if req.omr_clue.is_empty() && req.omr_metadata_enc.is_empty() {
            return Err(Status::invalid_argument(
                "omr_clue and omr_metadata_enc cannot both be empty",
            ));
        }
        if req.omr_metadata_enc.len() > MAX_OMR_METADATA_ENC_BYTES {
            return Err(Status::invalid_argument(format!(
                "omr_metadata_enc too large: {} bytes (max {MAX_OMR_METADATA_ENC_BYTES})",
                req.omr_metadata_enc.len()
            )));
        }

        // Reject poison / oversized clues before they enter the sled hint cache (S12).
        if !req.omr_clue.is_empty() {
            if let Err(e) = Self::validate_omr_clue(&req.omr_clue) {
                return Err(Status::invalid_argument(format!("omr_clue rejected: {e}")));
            }
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&req.tx_hash);

        // S12: RegisterOmrClue must follow SendTransaction from the same peer.
        // Unbound Register (no prior Send binding) is rejected — prefer attaching
        // the clue on SendTransaction. Mobile darkfid-broadcast fallback will
        // warn if Register fails; SendTransaction remains the primary path.
        if !self.send_peer_matches(&hash, peer) {
            return Err(Status::failed_precondition(
                "RegisterOmrClue requires a prior SendTransaction from this peer; \
                 attach omr_clue on SendTransaction instead",
            ));
        }

        if !req.omr_clue.is_empty() {
            if self
                .cache
                .omr_clue_index_taken(&hash, req.omr_clue_output_index)
                .unwrap_or(false)
            {
                // S3: first-writer-wins per output index — do not overwrite.
                tracing::info!(
                    target: "lightwalletd::server",
                    "OMR clue already present for RegisterOmrClue output {}; first-writer-wins",
                    req.omr_clue_output_index
                );
            } else {
                self.cache
                    .store_omr_clue_hint(&hash, req.omr_clue, Some(req.omr_clue_output_index))
                    .map_err(|e| Status::internal(format!("Failed to store OMR clue: {e}")))?;
            }
        }

        if !req.omr_metadata_enc.is_empty() {
            if self.cache.has_omr_metadata_enc(&hash).unwrap_or(false) {
                tracing::info!(
                    target: "lightwalletd::server",
                    "OMR metadata_enc already present for RegisterOmrClue; first-writer-wins"
                );
            } else {
                self.cache
                    .store_omr_metadata_enc(
                        &hash,
                        req.omr_metadata_enc,
                        Some(req.omr_clue_output_index),
                    )
                    .map_err(|e| {
                        Status::internal(format!("Failed to store OMR metadata_enc: {e}"))
                    })?;
            }
        }

        Ok(Response::new(proto::Empty {}))
    }

    async fn get_unif_omr_digest(
        &self,
        request: Request<tonic::Streaming<proto::DetectionKeyChunk>>,
    ) -> Result<Response<proto::OmrDigestResponse>, Status> {
        self.metrics.record_request();
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "UnifOMR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let peer = self.peer_rate_ip(&request);
            let upload = self
                .read_detection_key_upload(request.into_inner(), peer, true)
                .await?;
            let _reservation = upload.reservation;
            let permit = self.acquire_fhe_permit().await?;
            let keys = upload.keys.into_iter().map(Arc::new).collect();
            let response = self
                .evaluate_detection_keys(keys, upload.start, upload.end, permit)
                .await?;
            return Ok(Response::new(response));
        }
    }

    async fn register_detection_key(
        &self,
        request: Request<tonic::Streaming<proto::DetectionKeyChunk>>,
    ) -> Result<Response<proto::DetectionKeyHandle>, Status> {
        self.metrics.record_request();
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "UnifOMR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let peer = self.peer_rate_ip(&request);
            let upload = self
                .read_detection_key_upload(request.into_inner(), peer, false)
                .await?;
            let _reservation = upload.reservation;
            let network_byte = self.network_byte;
            let max_key_bytes = self.max_detection_key_bytes;
            let raw_bytes: usize = upload.keys.iter().map(|k| k.len()).sum();
            self.pool_lock()?
                .can_accept_for_peer(raw_bytes, max_key_bytes, detection_pool::unix_now())
                .map_err(|e| match e {
                    PoolReject::Full => Status::resource_exhausted("detection key pool is full"),
                    PoolReject::TooLarge => {
                        Status::invalid_argument("detection key exceeds the size cap")
                    }
                    PoolReject::Empty => Status::invalid_argument("empty detection key"),
                })?;
            let permit = self.acquire_fhe_permit().await?;
            let keys = upload.keys;
            // Parse off the runtime. Ciphertexts are dropped; the wire bytes go
            // back through encode_messages_padded on digest so there is one
            // partial-decrypt path. Do not log the key.
            let (keys, byte_length) = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let detector = crate::unifomr::UnifOmrDetector::new(network_byte)
                    .map_err(|e| e.to_string())?;
                let mut byte_length = 0usize;
                for key in &keys {
                    let (net, _parsed) =
                        crate::unifomr::parse_detection_key(key, &detector.params)?;
                    if net != network_byte {
                        return Err("detection key network does not match this server".to_string());
                    }
                    byte_length += key.len();
                }
                Ok::<_, String>((keys, byte_length))
            })
            .await
            .map_err(|e| Status::internal(format!("UnifOMR worker join error: {e}")))?
            .map_err(|e| Status::invalid_argument(format!("detection key: {e}")))?;

            let now = detection_pool::unix_now();
            let expires_unix = detection_pool::expiry_from(now);
            let pooled = PooledDetectionKey {
                keys: keys.into_iter().map(Arc::new).collect(),
                network_byte,
                expires_unix,
                byte_length,
            };
            let handle = self
                .pool_lock()?
                .insert_for_peer(peer, pooled, max_key_bytes, now)
                .map_err(|e| match e {
                    PoolReject::Full => Status::resource_exhausted("detection key pool is full"),
                    PoolReject::TooLarge => {
                        Status::invalid_argument("detection key exceeds the size cap")
                    }
                    PoolReject::Empty => Status::invalid_argument("empty detection key"),
                })?;
            Ok(Response::new(proto::DetectionKeyHandle {
                handle: handle.to_vec(),
                expires_unix,
            }))
        }
    }

    async fn get_unif_omr_digest_from_pool(
        &self,
        request: Request<proto::PoolDigestRequest>,
    ) -> Result<Response<proto::OmrDigestResponse>, Status> {
        self.metrics.record_request();
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "UnifOMR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let peer = self.peer_rate_ip(&request);
            let req = request.into_inner();
            if req.handle.len() != 32 {
                return Err(Status::invalid_argument(
                    "detection key handle must be 32 bytes",
                ));
            }
            let mut handle = [0u8; 32];
            handle.copy_from_slice(&req.handle);
            // Same OMR limiter as GetUnifOmrDigest. A miss still costs one credit
            // so handle scanning cannot skip the limiter. Do not log the handle.
            self.check_omr_rate_limit(peer, 1)?;
            let pooled = {
                let mut pool = self.pool_lock()?;
                pool.lookup(&handle, detection_pool::unix_now())
            };
            let Some(pooled) = pooled else {
                return Err(Status::not_found(
                    "detection key handle not found or expired",
                ));
            };
            if pooled.network_byte != self.network_byte {
                return Err(Status::invalid_argument(
                    "detection key network does not match this server",
                ));
            }
            let extra = (pooled.keys.len() as u32).saturating_sub(1);
            if extra > 0 {
                self.check_omr_rate_limit(peer, extra)?;
            }
            let permit = self.acquire_fhe_permit().await?;
            let response = self
                .evaluate_detection_keys(pooled.keys, req.start_height, req.end_height, permit)
                .await?;
            Ok(Response::new(response))
        }
    }

    async fn fetch_pir_batch(
        &self,
        request: Request<proto::BatchPirRequest>,
    ) -> Result<Response<proto::BatchPirResponse>, Status> {
        self.metrics.record_request();
        #[cfg(not(feature = "fhe-omr"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "Batch PIR requires the fhe-omr feature",
            ));
        }
        #[cfg(feature = "fhe-omr")]
        {
            let peer = self.peer_rate_ip(&request);
            self.check_pir_rate_limit(peer)?;
            let _pir_slot = self.begin_pir(peer)?;
            let req = request.into_inner();

            if req.query_ciphertexts.is_empty() {
                return Err(Status::invalid_argument("query_ciphertexts required"));
            }
            let start = req.start_height;
            let end = req.end_height;
            let window = reject_oversized_window(start, end)? as usize;
            let degree = crate::unifomr::packing_degree()
                .map_err(|e| Status::internal(format!("PIR init error: {e}")))?;
            let num_stripes = crate::pir_server::sealpir_stripe_count(window, degree);
            if num_stripes > MAX_PIR_STRIPES {
                return Err(Status::invalid_argument(format!(
                    "PIR window {window} needs {num_stripes} SealPIR stripes (max {MAX_PIR_STRIPES})"
                )));
            }
            // SealPIR-style: one query CT per stripe (always), hiding which stripe
            // contains the match. Single-CT still works for window ≤ degree.
            if req.query_ciphertexts.len() != num_stripes {
                return Err(Status::invalid_argument(format!(
                    "SealPIR expects {num_stripes} query ciphertext(s) for window {window}, got {}",
                    req.query_ciphertexts.len()
                )));
            }
            if req
                .query_ciphertexts
                .iter()
                .any(|ct| ct.len() > MAX_PIR_QUERY_CT_BYTES)
            {
                return Err(Status::invalid_argument(format!(
                    "PIR query ciphertext exceeds {MAX_PIR_QUERY_CT_BYTES} bytes"
                )));
            }
            if (req.limb_index as usize) >= crate::pir_server::MAX_PIR_LIMBS {
                return Err(Status::invalid_argument(format!(
                    "limb_index {} >= max {}",
                    req.limb_index,
                    crate::pir_server::MAX_PIR_LIMBS
                )));
            }
            let tip = self
                .cache
                .get_tip()
                .map_err(cache_status)?
                .map(|(height, _)| height)
                .ok_or_else(|| Status::unavailable("No blocks cached yet"))?;
            if end > tip {
                return Err(Status::invalid_argument(format!(
                    "PIR window end {end} is above tip {tip}"
                )));
            }

            let permit = self.acquire_pir_permit().await?;
            let cache = Arc::clone(&self.cache);
            let pir_windows = Arc::clone(&self.pir_windows);
            let limb_index = req.limb_index as usize;
            let queries = req.query_ciphertexts;

            #[allow(clippy::result_large_err)]
            let payload_ciphertexts = tokio::task::spawn_blocking(move || {
                // Held for the computation even if the handler is cancelled.
                let _permit = permit;
                let end_hash = pir_window_end_hash(&cache, end);
                let cached = pir_windows
                    .lock()
                    .ok()
                    .and_then(|guard| guard.get(start, end, end_hash));
                // Same window and end hash: reuse the clue-stripped prost bytes.
                // A hit must not scan the window in sled, re-bincode, or re-prost.
                let payloads = if let Some(payloads) = cached {
                    payloads
                } else {
                    let built = load_pir_window_payloads(&cache, start, end)?;
                    let end_hash_after = pir_window_end_hash(&cache, end);
                    if end_hash != [0u8; 32] && end_hash != end_hash_after {
                        return Err(Status::aborted("chain tip shifted during PIR read"));
                    }
                    if end_hash_after != [0u8; 32] {
                        if let Ok(mut guard) = pir_windows.lock() {
                            guard.insert(start, end, end_hash_after, Arc::clone(&built));
                        }
                    }
                    built
                };

                let db = crate::pir_server::limb_column(&payloads, limb_index);
                let server = crate::pir_server::BatchPirServer::with_unifomr_params()
                    .map_err(|e| Status::internal(format!("PIR init error: {e}")))?;
                server
                    .evaluate_sealpir_stripes(&queries, &db, window)
                    .map_err(|e| Status::invalid_argument(format!("PIR evaluation error: {e}")))
            })
            .await
            .map_err(|e| Status::internal(format!("PIR worker join error: {e}")))??;

            Ok(Response::new(proto::BatchPirResponse {
                payload_ciphertexts,
            }))
        }
    }

    async fn register_clue_public_key(
        &self,
        request: Request<proto::CluePublicKeyRegistration>,
    ) -> Result<Response<proto::Empty>, Status> {
        self.metrics.record_request();
        self.check_clue_rate_limit(&request)?;
        let req = request.into_inner();
        if req.payment_pubkey.len() != 32 {
            return Err(Status::invalid_argument("payment_pubkey must be 32 bytes"));
        }
        if req.clue_public_key.is_empty() {
            return Err(Status::invalid_argument("clue_public_key required"));
        }
        if req.clue_public_key.len() > MAX_CLUE_PUBLIC_KEY_BYTES {
            return Err(Status::invalid_argument(format!(
                "clue_public_key too large: {} bytes (max {MAX_CLUE_PUBLIC_KEY_BYTES})",
                req.clue_public_key.len()
            )));
        }
        if req.ownership_proof.is_empty() {
            return Err(Status::invalid_argument("ownership_proof required"));
        }
        if req.ownership_proof.len() > MAX_OWNERSHIP_PROOF_BYTES {
            return Err(Status::invalid_argument(format!(
                "ownership_proof too large: {} bytes (max {MAX_OWNERSHIP_PROOF_BYTES})",
                req.ownership_proof.len()
            )));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&req.payment_pubkey);
        // The ownership proof binds this server's network byte (no cross-network replay)
        // and the client's monotonic key_version (no stale-registration replay).
        crate::clue_ownership::verify_clue_pk_ownership(
            self.network_byte,
            req.key_version,
            &pk,
            &req.clue_public_key,
            &req.ownership_proof,
        )
        .map_err(Status::invalid_argument)?;
        #[cfg(feature = "fhe-omr")]
        {
            crate::unifomr::deserialize_public_key(&req.clue_public_key).map_err(|e| {
                Status::invalid_argument(format!("invalid UnifOMR clue public key: {e}"))
            })?;
        }
        self.cache
            .store_clue_public_key(
                &pk,
                &req.clue_public_key,
                req.key_version,
                &req.ownership_proof,
            )
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("registry is full") {
                    Status::resource_exhausted("clue public key registry is full")
                } else {
                    Status::invalid_argument(format!("Failed to store clue pk: {e}"))
                }
            })?;
        Ok(Response::new(proto::Empty {}))
    }

    async fn get_clue_public_key(
        &self,
        request: Request<proto::PaymentPubkey>,
    ) -> Result<Response<proto::CluePublicKey>, Status> {
        self.metrics.record_request();
        self.check_clue_rate_limit(&request)?;
        let start = Instant::now();
        let req = request.into_inner();
        if req.payment_pubkey.len() != 32 {
            return Err(Status::invalid_argument("payment_pubkey must be 32 bytes"));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&req.payment_pubkey);

        let attest_sk = self
            .cache
            .get_or_create_directory_attest_secret()
            .map_err(cache_status)?;

        #[cfg(feature = "fhe-omr")]
        let (clue_public_key, key_version) = {
            let registered = self
                .cache
                .get_clue_public_key_entry(&pk)
                .map_err(cache_status)?;
            match registered {
                Some((ver, _stored_proof, real)) => (real, ver),
                None => {
                    let pepper = self
                        .cache
                        .get_or_create_clue_dir_pepper()
                        .map_err(cache_status)?;
                    let pk_c = pk;
                    let clue = tokio::task::spawn_blocking(move || {
                        crate::unifomr::decoy_clue_public_key(&pk_c, &pepper)
                    })
                    .await
                    .map_err(|e| Status::internal(format!("decoy keygen join error: {e}")))?;
                    (clue, crate::unifomr::decoy_key_version())
                }
            }
        };
        #[cfg(not(feature = "fhe-omr"))]
        let (clue_public_key, key_version) = {
            match self
                .cache
                .get_clue_public_key_entry(&pk)
                .map_err(cache_status)?
            {
                Some((ver, _stored_proof, real)) => (real, ver),
                None => {
                    let pepper = self
                        .cache
                        .get_or_create_clue_dir_pepper()
                        .map_err(cache_status)?;
                    (padded_decoy_clue_public_key(&pk, &pepper), 1)
                }
            }
        };

        let ownership_proof = crate::clue_ownership::pad_ownership_proof(
            &crate::clue_ownership::sign_directory_attestation(
                &attest_sk,
                self.network_byte,
                key_version,
                &pk,
                &clue_public_key,
            ),
        )
        .map_err(Status::internal)?;

        // Fixed deadline (not a floor after leftover work) so load-induced
        // decoy keygen overruns still aim at the same response time.
        const MIN_CLUE_LOOKUP: Duration = Duration::from_millis(250);
        let deadline = start + MIN_CLUE_LOOKUP;
        let now = Instant::now();
        if now < deadline {
            tokio::time::sleep(deadline.saturating_duration_since(now)).await;
        }

        // Always report found=true with a fixed-size valid key (real or decoy)
        // so the registration bit does not leak via the boolean or empty body.
        Ok(Response::new(proto::CluePublicKey {
            found: true,
            clue_public_key,
            ownership_proof,
            key_version,
        }))
    }
}
