//! `/api/analyze` — AI fact extraction → store.
//!
//! Production path (default): extract facts via the Extractor service,
//! then per fact concurrently embed + SEAL-encrypt, quota-check the total
//! ciphertext, and enqueue one `UploadAndTransfer` WalletJob per fact —
//! returns HTTP 202 with `status: "pending"` and the per-fact job ids.
//!
//! Benchmark-mode bypass (BENCHMARK_MODE on; off by default, not for
//! production): per fact, embed → `engine.store_blob(plaintext bytes)`
//! synchronously (the `PlaintextEngine` writes the `plaintext` column — no
//! SEAL, no Walrus, no Sui tx, no job row). The response carries the real
//! stored ids and `status: "done"`, so the benchmark harness can treat
//! `/api/analyze` as synchronous the way the SDK's analyze contract did
//! before.

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::jobs::WalletOperation;
use crate::rate_limit;
use crate::services::extractor::MAX_ANALYZE_FACTS;
use crate::types::*;

use super::{collect_bounded_results, enqueue_wallet_job};

const ANALYZE_CONCURRENCY: usize = 5;

/// Stable per-fact key so an HTTP retry of `/api/analyze` collapses onto the
/// in-flight or completed upload instead of minting a second Walrus blob.
///
/// Importance is intentionally not hashed in. The extractor assigns a
/// vital/standard/trivial bucket per fact; a later call that extracts the
/// same text with a different bucket updates the live `vector_entries` row
/// rather than paying for a duplicate write. `forget` NULLs this key so a
/// re-analyze after delete is a new write, not a silent no-op.
fn analyze_fact_idempotency_key(owner: &str, namespace: &str, fact_text: &str) -> String {
    let digest = Sha256::digest(format!("{owner}\n{namespace}\n{fact_text}").as_bytes());
    format!("analyze:{}", hex::encode(digest))
}

#[derive(Debug, PartialEq, Eq)]
enum AnalyzeJobReuse {
    /// In-flight, or already stored with the same importance: return the existing job.
    Collapse,
    /// Failed before a blob was paid for: reset and re-enqueue on the same id.
    RetryUnpaidFailure,
    /// Live memory exists, but the extractor now scores it differently.
    UpdateImportance,
    /// Job completed and the vector is gone (forget / expiry): free the key and write again.
    RewriteForgotten,
}

fn importance_changed(existing: f32, incoming: f32) -> bool {
    (existing - incoming).abs() > 1e-6
}

/// Reset an unpaid failed analyze job before enqueueing a fresh ciphertext.
///
/// SEAL encryption is not deterministic, so the retry's bytes are a new Walrus
/// blob. The previous `encoded` checkpoint still names the old blob id. Leaving
/// it in place makes the sidecar reject the retry with `Resume blobId mismatch`
/// and burn the attempt budget. A registered-or-later resume, or any recorded
/// blob, is left untouched: those bytes may already have been submitted.
pub(crate) fn unpaid_analyze_retry_reset_sql() -> &'static str {
    "UPDATE remember_jobs SET status = 'pending', error_msg = NULL, \
     upload_wallet_index = NULL, upload_wallet_address = NULL, \
     upload_execution_identity = NULL, upload_resume_step = NULL, \
     upload_register_transaction = NULL, updated_at = NOW() \
     WHERE id = $1 AND status = 'failed' AND blob_id IS NULL AND blob_object_id IS NULL \
     AND COALESCE(error_msg, '') <> $2 \
     AND NOT EXISTS (SELECT 1 FROM memory_tombstones WHERE memory_id = remember_jobs.id::text) \
     AND (upload_resume_step IS NULL OR upload_resume_step->>'step' = 'encoded')"
}

fn classify_analyze_job_reuse(
    status: &str,
    blob_id: Option<&str>,
    live_importance: Option<f32>,
    incoming_importance: f32,
) -> AnalyzeJobReuse {
    if status == "failed" && blob_id.is_none() {
        return AnalyzeJobReuse::RetryUnpaidFailure;
    }
    match live_importance {
        None if blob_id.is_some() && status == "done" => AnalyzeJobReuse::RewriteForgotten,
        Some(existing) if importance_changed(existing, incoming_importance) => {
            AnalyzeJobReuse::UpdateImportance
        }
        _ => AnalyzeJobReuse::Collapse,
    }
}

// /api/analyze does not benefit from larger inputs — it sends the
// full text to gpt-4o-mini for fact extraction in a single LLM call (no
// chunking like remember). Cap it at the previous /api/remember ceiling
// so a hostile client cannot burn ~1 MiB of LLM tokens for the same
// rate-limit weight as a tiny request.
const MAX_ANALYZE_TEXT_BYTES: usize = 64 * 1024;

/// How many existing memories to pull as pre-extraction dedup
/// context for the extractor. This matches the default `recall_limit` the
/// benchmark harness uses, so the dedup context reflects what the user is
/// most likely to ask about next.
///
/// Sized for the cost trade-off: each retrieved memory adds ~50-150ms
/// of latency (one extra `search_similar` + `fetch_batch` round-trip),
/// and roughly 50-100 tokens to the LLM input. K=10 keeps p95 latency
/// within the expected +50-150ms budget.
const PRE_EXTRACTION_CONTEXT_LIMIT: usize = 10;

/// Per-leg timeouts on the pre-extraction context retrieval.
/// Set generously above measured p95 (embed ~150ms, search ~30ms warm /
/// 500ms cold, fetch ~50ms warm) so a healthy server is unaffected, but
/// tight enough to cap a stalled external dependency (OpenAI hiccup,
/// pgvector cold-namespace tail, sidecar 5xx). On expiry the leg's
/// fallback path fires — context goes empty, analyze continues. Total
/// pre-extraction worst case after timeouts: ~1.6s vs the observed
/// 30s benchmark outlier under no-timeout.
const EMBED_TIMEOUT_MS: u64 = 800;
const SEARCH_TIMEOUT_MS: u64 = 300;
const FETCH_TIMEOUT_MS: u64 = 500;

/// Largest input handed to the embedder for the pre-extraction dedup query.
/// Matches the embedder's local byte cap: larger inputs already fail before
/// any HTTP request. Skipping them here reports an expected skip instead of
/// an embed failure, while preserving dedup attempts for inputs up to 16 KiB.
///
/// This is a byte limit, not a token guarantee: dense inputs below it can
/// still exceed the provider's token limit and fall back to plain extraction.
/// It is independent of `remember`'s summarize-before-store cost threshold.
const MAX_PRE_EXTRACT_EMBED_BYTES: usize = 16 * 1024;

/// Whether to skip the pre-extraction dedup embed for an input of this size.
///
/// Skipping costs the extractor its dedup context, which is why the boundary
/// is inclusive: input of exactly `MAX_PRE_EXTRACT_EMBED_BYTES` is still
/// handed to the embedder.
fn should_skip_pre_extract_embed(text_len: usize) -> bool {
    text_len > MAX_PRE_EXTRACT_EMBED_BYTES
}

/// One fact that has finished embed + SEAL encrypt and is ready to enqueue:
/// `(plaintext, importance, embedding, ciphertext)`.
type PreparedFact = (String, f32, Vec<f32>, Vec<u8>);

/// POST /api/analyze
///
/// AI fact extraction flow:
/// 1. Verify auth (middleware) → get owner
/// 2. Call LLM to extract memorable facts from text
/// 3. For each fact concurrently: embed + encrypt → Walrus upload → store
pub async fn analyze(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    Json(body): Json<AnalyzeRequest>,
) -> Result<(StatusCode, Json<AnalyzeAcceptedResponse>), AppError> {
    reject_if_writes_paused(state.config.writes_paused)?;
    if text_is_blank(&body.text) {
        return Err(AppError::BadRequest("Text cannot be empty".into()));
    }
    // Reject oversize plaintext before spending an LLM call.
    if body.text.len() > MAX_ANALYZE_TEXT_BYTES {
        return Err(AppError::BadRequest(format!(
            "Text exceeds maximum length of {} bytes",
            MAX_ANALYZE_TEXT_BYTES
        )));
    }
    validate_namespace(&body.namespace)?;

    let owner = &auth.owner;
    let namespace = &body.namespace;
    tracing::info!(
        text_len = body.text.len(),
        owner = %owner,
        namespace = %namespace,
        "analyze request"
    );

    // ── Pre-extraction dedup context ──────────────────────────
    //
    // Before the extractor LLM call, fetch the top-K nearest existing
    // memories for this input. The extractor sees them as
    // `<related_memories>` and uses the context to skip duplicates and
    // anchor borderline facts. This is the architectural fix for the
    // benchmark LME `single_session_assistant` regression — gives the
    // LLM stronger signal for what is new vs already-known, so
    // borderline assistant content gets confidently extracted rather
    // than dropped under "be concise".
    //
    // Pre-extraction context is an *optimisation* — every recall-side
    // failure mode (embed, search, fetch) falls back to plain extraction
    // rather than failing the user's write. A user's write should not
    // depend on their own read working. Each per-leg failure logs a
    // `warn!` so production incidents are visible without breaking the
    // ingest path.
    //
    // Empty-namespace fast path (task #84): a cheap btree existence
    // check on `idx_vector_entries_owner_ns` skips the embed +
    // `search_similar` round-trip on first-ingest-into-a-namespace.
    // pgvector ≤0.7 HNSW with an `owner+namespace` filter does
    // post-filtering and can have a 100-500ms tail on cold namespaces
    // — the existence check eliminates that landmine, saves the embed
    // call ($, ~60-120ms p50), and degrades gracefully on its own
    // failure (treats "unknown" as "non-empty" → fall through to
    // full path, safer than skipping context erroneously).
    let pre_extract_t0 = std::time::Instant::now();
    let mut pre_extract_status = "ok";
    let mut pre_extract_embed_ms: u128 = 0;
    let mut pre_extract_search_ms: u128 = 0;
    let mut pre_extract_walrus_ms: u128 = 0;
    let mut pre_extract_seal_ms: u128 = 0;
    let mut pre_extract_dropped: usize = 0;

    let namespace_has_memories: bool = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM vector_entries WHERE owner = $1 AND namespace = $2 LIMIT 1",
    )
    .bind(owner)
    .bind(namespace)
    .fetch_optional(state.db.pool())
    .await
    .map(|r| r.is_some())
    .unwrap_or_else(|e| {
        tracing::warn!(
            error = %e,
            owner = %owner,
            namespace = %namespace,
            "analyze pre-extraction namespace-existence check failed; falling through to full path"
        );
        // Safer to *not* skip the recall when the existence check is
        // ambiguous — degrades to "task #83 behaviour", not "no context".
        true
    });

    let related_memories: Vec<crate::engine::HydratedMemory> = if !namespace_has_memories {
        pre_extract_status = "skipped_empty_namespace";
        Vec::new()
    } else if should_skip_pre_extract_embed(body.text.len()) {
        // The embedder already rejects inputs above its byte cap locally.
        // Classify this expected outcome as a skip instead of logging an
        // embed failure; no network round-trip would occur either way.
        //
        // The consequence is that large inputs extract without dedup context.
        // Recovering it would need summarize-before-embed, the way
        // `remember` does it — not affordable here, where pre-extraction is
        // inline on the caller's request under a ~1.6s total budget while
        // `remember` summarizes inside a spawned job.
        pre_extract_status = "skipped_oversized";
        Vec::new()
    } else {
        // Embed the input as a query. On embed failure, log + degrade —
        // do NOT propagate via `?`, even though the embed below uses the
        // same OpenAI endpoint as per-fact embeds (which DO propagate).
        // The distinction: per-fact embeds produce vectors that get
        // stored (data loss on failure); this one only feeds dedup
        // context (best-effort optimisation).
        // each leg of the pre-extraction recall is wrapped in
        // a `tokio::time::timeout`. On expiry the corresponding status
        // (`embed_timeout`, `search_timeout`, `fetch_timeout`) is set
        // and the context falls back to empty — analyze continues with
        // plain extraction rather than blocking the user's write on a
        // stalled external dependency.
        let embed_t = std::time::Instant::now();
        let input_vector_opt = match tokio::time::timeout(
            std::time::Duration::from_millis(EMBED_TIMEOUT_MS),
            state.embedder.embed(&body.text),
        )
        .await
        {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    owner = %owner,
                    namespace = %namespace,
                    "analyze pre-extraction embed failed; falling back to plain extract"
                );
                pre_extract_status = "embed_failed";
                None
            }
            Err(_elapsed) => {
                tracing::warn!(
                    owner = %owner,
                    namespace = %namespace,
                    timeout_ms = EMBED_TIMEOUT_MS,
                    "analyze pre-extraction embed timed out; falling back to plain extract"
                );
                pre_extract_status = "embed_timeout";
                None
            }
        };
        pre_extract_embed_ms = embed_t.elapsed().as_millis();

        match input_vector_opt {
            None => Vec::new(),
            Some(input_vector) => {
                let search_t = std::time::Instant::now();
                let search_result = tokio::time::timeout(
                    std::time::Duration::from_millis(SEARCH_TIMEOUT_MS),
                    state.db.search_similar(
                        &input_vector,
                        owner,
                        namespace,
                        PRE_EXTRACTION_CONTEXT_LIMIT,
                    ),
                )
                .await;
                pre_extract_search_ms = search_t.elapsed().as_millis();

                match search_result {
                    Ok(Ok(hits)) if hits.is_empty() => {
                        // Existence check said non-empty but search found
                        // 0 hits — possible if pgvector statistics are
                        // stale or the index hasn't caught up. Rare but
                        // not an error. Just no context this time.
                        Vec::new()
                    }
                    Ok(Ok(hits)) => {
                        let hit_refs: Vec<(String, f64)> = hits
                            .iter()
                            .map(|h| (h.blob_id.clone(), h.distance))
                            .collect();
                        // `fetch_batch` handles decrypt + cache + reactive
                        // cleanup on 404 / decrypt failure. Dropped hits
                        // just shrink the context; the extractor still
                        // works with whatever survives. On total failure
                        // (e.g. sidecar 5xx) or timeout, log and fall back.
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(FETCH_TIMEOUT_MS),
                            state.engine.fetch_batch(owner, namespace, &hit_refs, &auth),
                        )
                        .await
                        {
                            Ok(Ok((hydrated, dropped, timings))) => {
                                pre_extract_walrus_ms = timings.walrus_ms;
                                pre_extract_seal_ms = timings.seal_ms;
                                pre_extract_dropped = dropped;
                                if dropped > 0 {
                                    // Some context memories failed to
                                    // decrypt — surface so we can see
                                    // mass-decrypt-rot in production.
                                    tracing::warn!(
                                        owner = %owner,
                                        namespace = %namespace,
                                        requested = hit_refs.len(),
                                        got = hydrated.len(),
                                        dropped,
                                        "analyze pre-extraction: some context memories dropped at decrypt"
                                    );
                                    pre_extract_status = "ok_with_dropped";
                                }
                                hydrated
                            }
                            Ok(Err(e)) => {
                                tracing::warn!(
                                    error = %e,
                                    owner = %owner,
                                    namespace = %namespace,
                                    "analyze pre-extraction fetch_batch failed; falling back to plain extract"
                                );
                                pre_extract_status = "fetch_failed";
                                Vec::new()
                            }
                            Err(_elapsed) => {
                                tracing::warn!(
                                    owner = %owner,
                                    namespace = %namespace,
                                    timeout_ms = FETCH_TIMEOUT_MS,
                                    "analyze pre-extraction fetch_batch timed out; falling back to plain extract"
                                );
                                pre_extract_status = "fetch_timeout";
                                Vec::new()
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            owner = %owner,
                            namespace = %namespace,
                            "analyze pre-extraction search_similar failed; falling back to plain extract"
                        );
                        pre_extract_status = "search_failed";
                        Vec::new()
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            owner = %owner,
                            namespace = %namespace,
                            timeout_ms = SEARCH_TIMEOUT_MS,
                            "analyze pre-extraction search_similar timed out; falling back to plain extract"
                        );
                        pre_extract_status = "search_timeout";
                        Vec::new()
                    }
                }
            }
        }
    };
    let related_texts: Vec<&str> = related_memories.iter().map(|m| m.text.as_str()).collect();
    let pre_extract_ms = pre_extract_t0.elapsed().as_millis();
    tracing::info!(
        owner = %owner,
        namespace = %namespace,
        related_count = related_texts.len(),
        requested = PRE_EXTRACTION_CONTEXT_LIMIT,
        dropped = pre_extract_dropped,
        pre_extract_ms = %pre_extract_ms,
        embed_ms = %pre_extract_embed_ms,
        search_ms = %pre_extract_search_ms,
        walrus_ms = %pre_extract_walrus_ms,
        seal_ms = %pre_extract_seal_ms,
        status = pre_extract_status,
        "analyze pre-extraction context retrieved"
    );

    // Step 1: Extract facts using the Extractor service (sync — fast, ~1-2s).
    // pass `related_memories` as dedup context. The LlmExtractor
    // short-circuits to plain `extract` on empty slice — no wasted tokens
    // when the namespace had no nearest hits.
    // also pass `body.occurred_at` as the temporal anchor. When
    // present, the extractor renders a `<context occurred_at="..."/>` tag
    // alongside the prompt so the LLM can resolve relative-time
    // references ("last Friday") to absolute dates *inside the extracted
    // fact text* (Architecture A — no metadata column, date flows into
    // the encrypted blob + embedding only).
    let extracted = state
        .extractor
        .extract_with_context(&body.text, &related_texts, body.occurred_at)
        .await?;
    let raw_fact_count = extracted.raw_count;
    let facts = extracted.facts;
    let reserved_additional_weight = rate_limit::analyze_additional_weight(facts.len());
    tracing::info!(
        "  → Extracted {} facts (accepted={} cap={})",
        raw_fact_count,
        facts.len(),
        MAX_ANALYZE_FACTS,
    );

    if facts.is_empty() {
        return Ok((
            StatusCode::ACCEPTED,
            Json(AnalyzeAcceptedResponse {
                job_ids: vec![],
                facts: vec![],
                fact_count: 0,
                status: "pending".to_string(),
                owner: owner.clone(),
            }),
        ));
    }

    rate_limit::charge_explicit_weight(&state, &auth, reserved_additional_weight, "/api/analyze")
        .await?;

    // ── Benchmark-mode bypass: synchronous ingestion ──────────────────────
    //
    // The production path below is async (encrypt → enqueue WalletJob →
    // worker uploads to Walrus → insert_vector → SDK polls job_id). The
    // benchmark harness expects `POST /api/analyze` to return when the
    // memories are stored and searchable, the way the SDK's synchronous
    // analyze contract worked before. In benchmark mode we honour
    // that: per fact, embed → engine.store_blob(plaintext bytes) (the
    // PlaintextEngine writes the `plaintext` column — no SEAL, no Walrus,
    // no Sui transaction, no job row), in parallel across facts. The
    // response carries the real stored ids and status "done".
    //
    // Production behaviour is untouched — this branch only runs when
    // BENCHMARK_MODE is on (which is off by default and not for production).
    if state.config.benchmark_mode {
        // Quota check on plaintext byte length (benchmark mode has no
        // ciphertext — plaintext is the closest analog).
        let total_plaintext_bytes: i64 = facts.iter().map(|f| f.text.len() as i64).sum();
        // Inline path: one reservation covering the whole batch, released once
        // the rows are committed. Local id because these rows have no
        // `remember_jobs` row to key on (benchmark mode skips the job queue).
        let reservation_id = uuid::Uuid::new_v4().to_string();
        rate_limit::reserve_storage_quota_one(
            &state,
            owner,
            reservation_id.clone(),
            total_plaintext_bytes,
        )
        .await?;

        let store_tasks: Vec<_> = facts
            .iter()
            .map(|fact| {
                let state = Arc::clone(&state);
                let owner = owner.clone();
                let account_id = auth.account_id.clone();
                let namespace = namespace.clone();
                let agent_pk = auth.public_key.clone();
                let fact = fact.clone();
                async move {
                    let vector = state.embedder.embed(&fact.text).await?;
                    // importance is threaded through the engine
                    // (see store_blob signature in engine::MemoryEngine).
                    // The PlaintextEngine persists it on the new
                    // `vector_entries.importance` column; the ranker
                    // consumes it at recall time.
                    let mref = state
                        .engine
                        .store_blob(
                            &owner,
                            &account_id,
                            &namespace,
                            fact.text.as_bytes(),
                            &vector,
                            fact.importance,
                            Some(&agent_pk),
                        )
                        .await?;
                    Ok::<_, AppError>(AnalyzeAcceptedFact {
                        text: fact.text,
                        id: mref.id.clone(),
                        job_id: mref.id,
                    })
                }
            })
            .collect();

        let store_results = collect_bounded_results(store_tasks, ANALYZE_CONCURRENCY).await;

        // Release before the `?` below so a partial failure cannot strand the
        // reservation for the full TTL. Any facts that did land are already
        // counted as rows, and the ones that did not should not keep holding
        // quota.
        rate_limit::release_storage_quota_one(&state, &reservation_id).await;

        let mut stored_facts: Vec<AnalyzeAcceptedFact> = Vec::with_capacity(store_results.len());
        for r in store_results {
            stored_facts.push(r?);
        }

        let fact_count = stored_facts.len();
        let job_ids: Vec<String> = stored_facts.iter().map(|f| f.id.clone()).collect();
        tracing::info!(
            "analyze (benchmark mode) complete: {} facts stored synchronously owner={} ns={}",
            fact_count,
            owner,
            namespace
        );

        return Ok((
            StatusCode::ACCEPTED,
            Json(AnalyzeAcceptedResponse {
                job_ids,
                facts: stored_facts,
                fact_count,
                // "done" (not "pending") — the memories are stored and
                // searchable by the time this response is sent. "done"
                // matches the existing remember_jobs status vocabulary
                // ("done" = stored, blob_id known), rather than coining a
                // new term for the benchmark-only case.
                status: "done".to_string(),
                owner: owner.clone(),
            }),
        ));
    }

    // Step 2: embed + SEAL encrypt all facts concurrently (no wallet needed yet).
    // This is the fast part (~300-500ms), done in the request handler so:
    //   - No plaintext stored in job payload
    //   - Exact ciphertext size known for quota check
    let auth_pubkey_base = auth.public_key.clone();
    let account_id = auth.account_id.clone();
    let prep_tasks: Vec<_> = facts
        .iter()
        .map(|fact| {
            let state = Arc::clone(&state);
            let owner = owner.clone();
            let account_id = account_id.clone();
            let fact = fact.clone();
            async move {
                let embed_fut = state.embedder.embed(&fact.text);
                let encrypt_fut = crate::storage::seal::seal_encrypt(
                    &state.http_client,
                    &state.config.seal_sidecar_url,
                    state.config.sidecar_secret.as_deref(),
                    fact.text.as_bytes(),
                    &owner,
                    &account_id,
                    &state.config.package_id,
                    state.config.seal_expected_committee_identity.as_ref(),
                );
                let (vector_result, encrypted_result) = tokio::join!(embed_fut, encrypt_fut);
                // carry `importance` through the prep tuple so
                // the job payload below can persist it alongside the
                // ciphertext + vector.
                Ok::<_, AppError>((
                    fact.text,
                    fact.importance,
                    vector_result?,
                    encrypted_result?,
                ))
            }
        })
        .collect();

    let prep_results = collect_bounded_results(prep_tasks, ANALYZE_CONCURRENCY).await;

    // Exact ciphertext size per fact is known here, which is what the
    // per-fact reservations below are sized from.
    let mut prepared: Vec<PreparedFact> = Vec::with_capacity(prep_results.len());
    for r in prep_results {
        prepared.push(r?);
    }
    // Job ids are minted here, before admission, rather than inside the loop
    // below: each one keys the reservation for the fact it will store, so
    // jobs.rs can release from the job id it already carries once the vector
    // row lands. The insert happens minutes later (after the Walrus upload),
    // which is exactly the window a bare check left unprotected.
    let pending: Vec<(String, PreparedFact)> = prepared
        .into_iter()
        .map(|fact| (uuid::Uuid::new_v4().to_string(), fact))
        .collect();

    // All-or-nothing across the batch, so an over-quota analyze request is
    // still rejected whole with the same 402 shape.
    let reservations: Vec<crate::storage::db::StorageReservationRequest> = pending
        .iter()
        .map(
            |(job_id, (_, _, _, encrypted))| crate::storage::db::StorageReservationRequest {
                id: job_id.clone(),
                bytes: encrypted.len() as i64,
            },
        )
        .collect();
    rate_limit::reserve_storage_quota(&state, owner, &reservations).await?;

    // Facts are enqueued in order, so at iteration `idx` the set
    // `all_ids[idx..]` is exactly what holds a reservation with no queued job
    // to release it. Those get released explicitly if we bail out mid-loop;
    // without that they would sit against the owner's quota until the TTL.
    let all_ids: Vec<String> = pending.iter().map(|(id, _)| id.clone()).collect();

    // Step 3: For each prepared fact — insert remember_jobs row + enqueue WalletJob.
    // Round-robin across wallet pool so facts upload in parallel.
    let mut job_ids: Vec<String> = Vec::with_capacity(pending.len());
    let mut accepted_facts: Vec<AnalyzeAcceptedFact> = Vec::with_capacity(pending.len());
    for (idx, (job_id, (fact_text, importance, vector, encrypted))) in
        pending.into_iter().enumerate()
    {
        let idem_key = analyze_fact_idempotency_key(owner, namespace, &fact_text);
        let inserted = match sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, idempotency_key, request_fingerprint)
             VALUES ($1, $2, $3, 'pending', $4, $4)
             ON CONFLICT (owner, namespace, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING",
        )
        .bind(&job_id)
        .bind(owner)
        .bind(namespace)
        .bind(&idem_key)
        .execute(state.db.pool())
        .await
        {
            Ok(result) => result,
            Err(e) if super::remember::is_idempotency_key_unique_violation(&e) => {
                rate_limit::release_storage_quota(&state, &all_ids[idx..]).await;
                return Err(AppError::Conflict(
                    super::remember::IDEMPOTENCY_KEY_CONFLICT_MESSAGE.into(),
                ));
            }
            Err(e) => {
                rate_limit::release_storage_quota(&state, &all_ids[idx..]).await;
                return Err(AppError::Internal(format!(
                    "Failed to create analyze job row: {}",
                    e
                )));
            }
        };
        let mut upload_job_id = job_id.clone();
        if inserted.rows_affected() == 0 {
            rate_limit::release_storage_quota(&state, std::slice::from_ref(&job_id)).await;
            let existing = sqlx::query_as::<_, (String, String, Option<String>)>(
                "SELECT id, status, blob_id FROM remember_jobs WHERE owner = $1 AND namespace = $2 AND idempotency_key = $3",
            )
            .bind(owner)
            .bind(namespace)
            .bind(&idem_key)
            .fetch_optional(state.db.pool())
            .await;
            match existing {
                Err(e) => {
                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                    return Err(AppError::Internal(format!(
                        "Failed to look up analyze job: {}",
                        e
                    )));
                }
                Ok(None) => {
                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                    if super::remember::has_remember_job_for_owner_key(
                        state.db.pool(),
                        owner,
                        &idem_key,
                    )
                    .await?
                    {
                        return Err(AppError::Conflict(
                            super::remember::IDEMPOTENCY_KEY_CONFLICT_MESSAGE.into(),
                        ));
                    }
                    return Err(AppError::Internal(
                        "Failed to create analyze job row: insert affected no rows".into(),
                    ));
                }
                Ok(Some((existing_id, status, blob_id))) => {
                    let live_importance = match sqlx::query_scalar::<_, f32>(
                        "SELECT importance FROM vector_entries
                         WHERE id = $1 AND owner = $2 AND namespace = $3",
                    )
                    .bind(&existing_id)
                    .bind(owner)
                    .bind(namespace)
                    .fetch_optional(state.db.pool())
                    .await
                    {
                        Ok(value) => value,
                        Err(e) => {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(AppError::Internal(format!(
                                "Failed to look up analyze memory: {}",
                                e
                            )));
                        }
                    };
                    let reuse = classify_analyze_job_reuse(
                        &status,
                        blob_id.as_deref(),
                        live_importance,
                        importance,
                    );
                    let rewrite = match reuse {
                        AnalyzeJobReuse::Collapse => {
                            accepted_facts.push(AnalyzeAcceptedFact {
                                text: fact_text,
                                id: existing_id.clone(),
                                job_id: existing_id.clone(),
                            });
                            job_ids.push(existing_id);
                            continue;
                        }
                        AnalyzeJobReuse::UpdateImportance => {
                            match state
                                .db
                                .update_vector_importance(
                                    &existing_id,
                                    owner,
                                    namespace,
                                    importance,
                                )
                                .await
                            {
                                Ok(true) => {
                                    accepted_facts.push(AnalyzeAcceptedFact {
                                        text: fact_text,
                                        id: existing_id.clone(),
                                        job_id: existing_id.clone(),
                                    });
                                    job_ids.push(existing_id);
                                    continue;
                                }
                                Ok(false) => true,
                                Err(e) => {
                                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                        .await;
                                    return Err(e);
                                }
                            }
                        }
                        AnalyzeJobReuse::RewriteForgotten => true,
                        AnalyzeJobReuse::RetryUnpaidFailure => false,
                    };
                    if rewrite {
                        if let Err(e) = sqlx::query(
                            "UPDATE remember_jobs
                             SET idempotency_key = NULL, updated_at = NOW()
                             WHERE id = $1 AND owner = $2",
                        )
                        .bind(&existing_id)
                        .bind(owner)
                        .execute(state.db.pool())
                        .await
                        {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(AppError::Internal(format!(
                                "Failed to release analyze idempotency key: {}",
                                e
                            )));
                        }
                        let rewritten = match sqlx::query(
                            "INSERT INTO remember_jobs (id, owner, namespace, status, idempotency_key, request_fingerprint)
                             VALUES ($1, $2, $3, 'pending', $4, $4)
                             ON CONFLICT (owner, namespace, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING",
                        )
                        .bind(&job_id)
                        .bind(owner)
                        .bind(namespace)
                        .bind(&idem_key)
                        .execute(state.db.pool())
                        .await
                        {
                            Ok(result) => result,
                            Err(e) if super::remember::is_idempotency_key_unique_violation(&e) => {
                                rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                    .await;
                                return Err(AppError::Conflict(
                                    super::remember::IDEMPOTENCY_KEY_CONFLICT_MESSAGE.into(),
                                ));
                            }
                            Err(e) => {
                                rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                    .await;
                                return Err(AppError::Internal(format!(
                                    "Failed to recreate analyze job row: {}",
                                    e
                                )));
                            }
                        };
                        if rewritten.rows_affected() == 0 {
                            // Another retry won the key after we released it.
                            let winner = sqlx::query_scalar::<_, String>(
                                "SELECT id FROM remember_jobs WHERE owner = $1 AND namespace = $2 AND idempotency_key = $3",
                            )
                            .bind(owner)
                            .bind(namespace)
                            .bind(&idem_key)
                            .fetch_optional(state.db.pool())
                            .await;
                            match winner {
                                Ok(Some(winner_id)) => {
                                    accepted_facts.push(AnalyzeAcceptedFact {
                                        text: fact_text,
                                        id: winner_id.clone(),
                                        job_id: winner_id.clone(),
                                    });
                                    job_ids.push(winner_id);
                                    continue;
                                }
                                Ok(None) => {
                                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                        .await;
                                    return Err(AppError::Internal(
                                        "Failed to recreate analyze job row: insert affected no rows"
                                            .into(),
                                    ));
                                }
                                Err(e) => {
                                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                        .await;
                                    return Err(AppError::Internal(format!(
                                        "Failed to look up analyze job: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        if let Err(e) = rate_limit::reserve_storage_quota(
                            &state,
                            owner,
                            &[crate::storage::db::StorageReservationRequest {
                                id: job_id.clone(),
                                bytes: encrypted.len() as i64,
                            }],
                        )
                        .await
                        {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(e);
                        }
                    } else {
                        let reset = match sqlx::query(unpaid_analyze_retry_reset_sql())
                            .bind(&existing_id)
                            .bind(crate::storage::db::FORGOTTEN_IN_FLIGHT_JOB_ERROR)
                            .execute(state.db.pool())
                            .await
                        {
                            Ok(result) => result,
                            Err(e) => {
                                rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                    .await;
                                return Err(AppError::Internal(format!(
                                    "Failed to reset analyze job: {}",
                                    e
                                )));
                            }
                        };
                        // A resume past encode, or a row that is no longer an
                        // unpaid failure, must not be overwritten with new
                        // ciphertext.
                        if reset.rows_affected() == 0 {
                            accepted_facts.push(AnalyzeAcceptedFact {
                                text: fact_text,
                                id: existing_id.clone(),
                                job_id: existing_id.clone(),
                            });
                            job_ids.push(existing_id);
                            continue;
                        }
                        if let Err(e) = rate_limit::reserve_storage_quota(
                            &state,
                            owner,
                            &[crate::storage::db::StorageReservationRequest {
                                id: existing_id.clone(),
                                bytes: encrypted.len() as i64,
                            }],
                        )
                        .await
                        {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(e);
                        }
                        upload_job_id = existing_id;
                    }
                }
            }
        }

        // Pick next wallet slot (round-robin) and enqueue UploadAndTransfer
        let Some(wallet_index) = state.key_pool.least_loaded_index() else {
            rate_limit::release_storage_quota(&state, &all_ids[idx..]).await;
            return Err(AppError::Internal("No Sui keys configured".into()));
        };
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        if let Err(e) = enqueue_wallet_job(
            &state,
            wallet_index,
            WalletOperation::UploadAndTransfer {
                encrypted_b64,
                vector,
                importance,
                owner: owner.clone(),
                namespace: namespace.clone(),
                package_id: state.config.package_id.clone(),
                account_id: account_id.clone(),
                agent_public_key: Some(auth_pubkey_base.clone()),
                remember_job_id: Some(upload_job_id.clone()),
                prepare_claim_token: None,
                epochs: state.config.walrus_storage_epochs,
            },
        )
        .await
        {
            let _ = sqlx::query(
                "UPDATE remember_jobs
                 SET status = 'failed',
                     error_msg = $2,
                     updated_at = NOW()
                 WHERE id = $1
                   AND blob_id IS NULL
                   AND COALESCE(error_msg, '') <> $3
                   AND NOT EXISTS (
                       SELECT 1 FROM memory_tombstones WHERE memory_id = remember_jobs.id::text
                   )",
            )
            .bind(&upload_job_id)
            .bind(e.to_string())
            .bind(crate::storage::db::FORGOTTEN_IN_FLIGHT_JOB_ERROR)
            .execute(state.db.pool())
            .await;
            rate_limit::release_storage_quota(&state, std::slice::from_ref(&upload_job_id)).await;
            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
            return Err(AppError::Internal(format!(
                "Failed to enqueue analyze job: {}",
                e
            )));
        }

        // Queued: jobs.rs owns this reservation from here on.

        tracing::info!(
            job_id = %upload_job_id,
            wallet_index,
            fact_len = fact_text.len(),
            "analyze fact enqueued"
        );
        accepted_facts.push(AnalyzeAcceptedFact {
            text: fact_text,
            id: upload_job_id.clone(),
            job_id: upload_job_id.clone(),
        });
        job_ids.push(upload_job_id);
    }

    let fact_count = job_ids.len();
    tracing::info!(
        "analyze accepted: {} facts enqueued owner={} ns={}",
        fact_count,
        owner,
        namespace
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(AnalyzeAcceptedResponse {
            job_ids,
            facts: accepted_facts,
            fact_count,
            status: "pending".to_string(),
            owner: owner.clone(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_fact_idempotency_key, classify_analyze_job_reuse, should_skip_pre_extract_embed,
        unpaid_analyze_retry_reset_sql, AnalyzeJobReuse, ANALYZE_CONCURRENCY,
        MAX_ANALYZE_TEXT_BYTES, MAX_PRE_EXTRACT_EMBED_BYTES,
    };
    use crate::routes::remember::MAX_REMEMBER_TEXT_BYTES;
    use crate::services::extractor::MAX_ANALYZE_FACTS;

    // ── Text size limit ──────────────────────────────────────────

    #[test]
    fn max_analyze_text_bytes_is_64kb() {
        assert_eq!(MAX_ANALYZE_TEXT_BYTES, 64 * 1024);
    }

    #[test]
    fn analyze_text_strictly_smaller_than_remember() {
        // Analyze does fact extraction in a single LLM call without
        // chunking, so its ceiling must stay below remember's.
        const { assert!(MAX_ANALYZE_TEXT_BYTES < MAX_REMEMBER_TEXT_BYTES) }
    }

    // ── Pre-extraction embed size guard (WALM-411) ───────────────

    #[test]
    fn max_pre_extract_embed_bytes_is_16kb() {
        assert_eq!(MAX_PRE_EXTRACT_EMBED_BYTES, 16 * 1024);
    }

    #[test]
    fn pre_extract_guard_is_reachable_below_the_accepted_input_ceiling() {
        // If the guard sat at or above the endpoint's own cap it could never
        // fire, and the skip would be dead code.
        const { assert!(MAX_PRE_EXTRACT_EMBED_BYTES < MAX_ANALYZE_TEXT_BYTES) }
        // Lowering the embedder cap must not leave analyze attempting inputs
        // that are guaranteed to fail its local validation.
        const { assert!(MAX_PRE_EXTRACT_EMBED_BYTES <= crate::services::embedder::MAX_EMBED_INPUT_BYTES) }
    }

    #[test]
    fn embed_is_attempted_at_and_below_the_threshold() {
        assert!(!should_skip_pre_extract_embed(0));
        assert!(!should_skip_pre_extract_embed(1));
        // Preserve dedup attempts in the band the original 8 KiB guard skipped.
        assert!(!should_skip_pre_extract_embed(8 * 1024 + 1));
        assert!(!should_skip_pre_extract_embed(12 * 1024));
        assert!(!should_skip_pre_extract_embed(
            MAX_PRE_EXTRACT_EMBED_BYTES - 1
        ));
        // Boundary: exactly at the limit is still handed to the embedder.
        assert!(!should_skip_pre_extract_embed(MAX_PRE_EXTRACT_EMBED_BYTES));
    }

    #[test]
    fn embed_is_skipped_above_the_threshold() {
        assert!(should_skip_pre_extract_embed(
            MAX_PRE_EXTRACT_EMBED_BYTES + 1
        ));
        assert!(should_skip_pre_extract_embed(MAX_ANALYZE_TEXT_BYTES));
    }

    #[test]
    fn observed_production_rejection_would_now_be_skipped() {
        // Regression anchor: a real 31,782-byte /api/analyze input was
        // rejected by the embedding API on 2026-08-27 with
        // `Invalid 'input': maximum context length is 8192`, after burning
        // 564ms. Since #837, the embedder rejects it locally; analyze should
        // classify it as skipped_oversized instead of embed_failed.
        assert!(should_skip_pre_extract_embed(31_782));
    }

    // ── Analyze concurrency + weight ────────────────────

    #[test]
    fn analyze_concurrency_constant_is_5() {
        assert_eq!(ANALYZE_CONCURRENCY, 5);
    }

    #[test]
    fn analyze_fact_idempotency_key_is_stable_and_namespaced() {
        let a = analyze_fact_idempotency_key("0xowner", "work", "likes rust");
        let b = analyze_fact_idempotency_key("0xowner", "work", "likes rust");
        let c = analyze_fact_idempotency_key("0xowner", "work", "likes go");
        let other_owner = analyze_fact_idempotency_key("0xother", "work", "likes rust");
        let other_ns = analyze_fact_idempotency_key("0xowner", "home", "likes rust");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, other_owner);
        assert_ne!(a, other_ns);
        assert!(a.starts_with("analyze:"));
    }

    #[test]
    fn classify_collapses_inflight_and_matching_live_row() {
        assert_eq!(
            classify_analyze_job_reuse("pending", None, None, 0.5),
            AnalyzeJobReuse::Collapse
        );
        assert_eq!(
            classify_analyze_job_reuse("uploaded", Some("blob"), None, 0.5),
            AnalyzeJobReuse::Collapse
        );
        assert_eq!(
            classify_analyze_job_reuse("done", Some("blob"), Some(0.5), 0.5),
            AnalyzeJobReuse::Collapse
        );
        // Paid-but-not-indexed: do not mint a second blob.
        assert_eq!(
            classify_analyze_job_reuse("failed", Some("blob"), None, 0.5),
            AnalyzeJobReuse::Collapse
        );
    }

    #[test]
    fn classify_retries_unpaid_failure() {
        assert_eq!(
            classify_analyze_job_reuse("failed", None, None, 0.5),
            AnalyzeJobReuse::RetryUnpaidFailure
        );
    }

    #[test]
    fn unpaid_retry_drops_the_encoded_checkpoint_only() {
        let sql = unpaid_analyze_retry_reset_sql();
        assert!(sql.contains("upload_resume_step = NULL"));
        assert!(sql.contains("upload_register_transaction = NULL"));
        assert!(sql.contains("upload_wallet_address = NULL"));
        assert!(sql.contains("blob_id IS NULL"));
        assert!(sql.contains("blob_object_id IS NULL"));
        assert!(sql.contains("upload_resume_step->>'step' = 'encoded'"));
        assert!(!sql.contains("preparation_encrypted_b64"));
    }

    #[test]
    fn classify_updates_importance_on_live_row() {
        assert_eq!(
            classify_analyze_job_reuse("done", Some("blob"), Some(0.2), 0.9),
            AnalyzeJobReuse::UpdateImportance
        );
    }

    #[test]
    fn classify_rewrites_when_done_job_has_no_live_memory() {
        assert_eq!(
            classify_analyze_job_reuse("done", Some("blob"), None, 0.5),
            AnalyzeJobReuse::RewriteForgotten
        );
    }

    #[test]
    fn max_analyze_facts_constant_is_20() {
        assert_eq!(MAX_ANALYZE_FACTS, 20);
    }

    #[test]
    fn analyze_weight_proportional_to_facts() {
        use crate::rate_limit::{analyze_additional_weight, analyze_total_weight};
        // No facts → only base weight
        assert_eq!(analyze_total_weight(0), 5);
        // Max facts (20) → 5 + 20 = 25
        assert_eq!(analyze_total_weight(20), 25);
        // Additional weight is exactly fact_count
        assert_eq!(analyze_additional_weight(0), 0);
        assert_eq!(analyze_additional_weight(20), 20);
    }
}
