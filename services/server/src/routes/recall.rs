//! `/api/recall` + `/api/recall/manual` handlers, plus the recall
//! query-embedding cache (Redis).
//!
//! `recall`: embed the query (cached) → vector search → hydrate the hits
//! through the storage engine (cache → Walrus → batched SEAL decrypt),
//! surfacing the count of dropped entries. `recall/manual`: client supplies
//! the query vector; the server returns `(blob_id, distance)[]` and the
//! client downloads + decrypts itself.

use axum::extract::State;
use axum::{Extension, Json};
use redis::AsyncCommands;
use sha2::Digest;
use std::sync::Arc;

use crate::engine::stage::{self, Budget, HangUpGuard, RecallStage, StageMarker};
use crate::types::*;

// ============================================================
// Recall query-embedding cache (Redis) — wraps the Embedder service
// ============================================================

fn recall_embedding_cache_key(config: &Config, query: &str) -> String {
    use crate::services::embedder::EMBEDDING_MODEL;
    let mut hasher = sha2::Sha256::new();
    hasher.update(config.openai_api_base.as_bytes());
    hasher.update(b"\0");
    hasher.update(EMBEDDING_MODEL.as_bytes());
    hasher.update(b"\0");
    hasher.update(query.as_bytes());
    format!("memwal:embedding:v1:{:x}", hasher.finalize())
}

/// Embed a recall query, with a Redis cache keyed on
/// api_base + model + query. Cache miss / disabled (ttl 0) falls through
/// to `state.embedder.embed`. Cache errors are best-effort (logged, ignored).
async fn generate_recall_embedding_cached(
    state: &AppState,
    query: &str,
) -> Result<Vec<f32>, AppError> {
    let ttl_secs = state.embedding_cache_ttl.as_secs();
    if ttl_secs == 0 {
        return state.embedder.embed(query).await;
    }

    let cache_key = recall_embedding_cache_key(&state.config, query);
    let mut redis = state.redis.clone();
    match redis.get::<_, Option<String>>(&cache_key).await {
        Ok(Some(payload)) => match serde_json::from_str::<Vec<f32>>(&payload) {
            Ok(vector) => return Ok(vector),
            Err(e) => tracing::warn!("embedding cache decode failed: {}", e),
        },
        Ok(None) => {}
        Err(e) => tracing::warn!("embedding cache get failed: {}", e),
    }

    let vector = state.embedder.embed(query).await?;
    match serde_json::to_string(&vector) {
        Ok(payload) => {
            let result: redis::RedisResult<()> = redis.set_ex(&cache_key, payload, ttl_secs).await;
            if let Err(e) = result {
                tracing::warn!("embedding cache set failed: {}", e);
            }
        }
        Err(e) => tracing::warn!("embedding cache encode failed: {}", e),
    }

    Ok(vector)
}

// ============================================================
// Shared ranking for manual recall
// ============================================================

/// Rank `SearchHit`s with the composite ranker and return them reordered,
/// without hydrating (no Walrus fetch / SEAL decrypt).
///
/// manual recall must produce the same ordering as `/api/recall`
/// and `/api/ask` for the same query + weights. Those paths rank
/// `HydratedMemory` values; to guarantee identical ordering we reuse the
/// **same** `Ranker::rank` rather than re-implementing the scoring on
/// `SearchHit` (which would risk drift — the exact class of bug this fixes).
/// We map each `SearchHit` into a `HydratedMemory` carrying only the fields
/// the ranker reads (`distance` / `created_at` / `importance`), with empty
/// `text` (the ranker never reads text; manual recall never decrypts).
///
/// The ranked output is mapped back to the original `SearchHit`s **by
/// original index, not by `blob_id`**. The ranker treats `blob_id` as
/// opaque carry-through (it scores only distance/recency/importance), so
/// we stash each hit's input index in that slot. Indices are unique, so a
/// blob_id-keyed round-trip cannot drop hits and `results.len() == hits.len()`.
///
/// At default weights `rank()` short-circuits, so the input (cosine) order
/// is returned unchanged.
fn rank_search_hits(
    ranker: &dyn crate::services::ranker::Ranker,
    hits: Vec<SearchHit>,
    weights: &ScoringWeights,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<SearchHit> {
    // Carry the original index through the ranker via the (opaque-to-ranker)
    // blob_id field so reorder is unambiguous even if two hits share a blob_id.
    let hydrated: Vec<crate::engine::HydratedMemory> = hits
        .iter()
        .enumerate()
        .map(|(idx, h)| crate::engine::HydratedMemory {
            blob_id: idx.to_string(),
            text: String::new(),
            distance: h.distance,
            created_at: Some(h.created_at),
            importance: Some(h.importance),
        })
        .collect();
    let ranked = ranker.rank(hydrated, weights, now);

    // Reorder the originals by the ranked index sequence. `Option::take`
    // moves each `SearchHit` out exactly once; a malformed/duplicate index
    // (cannot happen — we generated them) would just be skipped, never
    // duplicating a hit.
    let mut slots: Vec<Option<SearchHit>> = hits.into_iter().map(Some).collect();
    ranked
        .iter()
        .filter_map(|r| {
            r.memory
                .blob_id
                .parse::<usize>()
                .ok()
                .and_then(|idx| slots.get_mut(idx).and_then(Option::take))
        })
        .collect()
}

// ============================================================
// Handlers
// ============================================================

/// POST /api/recall
///
/// Full TEE flow:
/// 1. Verify auth (middleware) → get owner from delegate key onchain lookup
/// 2. Embed query → vector
/// 3. Search Vector DB → top-K {blobId}
/// 4. Download all blobs concurrently + SEAL decrypt each
/// 5. Return plaintext results
pub async fn recall(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    Json(body): Json<RecallRequest>,
) -> Result<Json<RecallResponse>, AppError> {
    if body.query.trim().is_empty() {
        return Err(AppError::BadRequest("Query cannot be empty".into()));
    }
    validate_namespace(&body.namespace)?;

    // Validate scoring_weights up front — fail fast on malformed input
    // (NaN, out-of-range, sub-floor half-life) BEFORE we spend an embed +
    // vector search + Walrus + SEAL round-trip just to 400 at the end.
    // An explicit `sort` suppresses them; see `resolve_scoring_weights`.
    let weights = super::resolve_scoring_weights(body.sort, body.scoring_weights.clone())?;
    let sort = body.sort.unwrap_or_default();

    // Owner is derived from delegate key via onchain verification (auth middleware)
    let owner = &auth.owner;
    let namespace = &body.namespace;

    tracing::info!(
        query_len = body.query.len(),
        owner = %owner,
        namespace = %namespace,
        ranker_active = weights.is_ranker_active(),
        scoring_weights_ignored = body.sort.is_some()
            && body
                .scoring_weights
                .as_ref()
                .is_some_and(ScoringWeights::is_ranker_active),
        "recall request"
    );

    // Stop just short of the caller's deadline, so the 504 can say which
    // stage was running. The caller's clock started before auth did.
    let already = crate::observability::current_request_started()
        .map(|arrived| arrived.elapsed())
        .unwrap_or_default();
    let deadline = match stage::budget_for(body.deadline_ms, already) {
        Budget::Unbounded => None,
        Budget::Run(left) => Some(tokio::time::Instant::now() + left),
        Budget::Exhausted => {
            return Err(recall_timed_out(
                owner,
                namespace,
                RecallStage::Auth,
                already,
                &body,
            ));
        }
    };
    let marker = StageMarker::default();
    let guard = HangUpGuard::new(marker.clone(), owner.clone());
    let outcome = stage::run_with_deadline(
        &marker,
        deadline,
        recall_pipeline(&state, &auth, &body, &weights, sort),
    )
    .await;
    guard.disarm();
    let response = match outcome {
        Ok(result) => result?,
        Err(timed_out) => {
            let elapsed = already + timed_out.elapsed;
            return Err(recall_timed_out(
                owner,
                namespace,
                timed_out.stage,
                elapsed,
                &body,
            ));
        }
    };
    Ok(Json(response))
}

fn recall_timed_out(
    owner: &str,
    namespace: &str,
    stage: RecallStage,
    elapsed: std::time::Duration,
    body: &RecallRequest,
) -> AppError {
    let elapsed_ms = elapsed.as_millis() as u64;
    tracing::warn!(
        owner = %owner,
        namespace = %namespace,
        stage = stage.as_str(),
        elapsed_ms,
        deadline_ms = body.deadline_ms,
        "recall timed out before the caller's deadline"
    );
    AppError::RecallTimeout {
        stage: stage.as_str(),
        elapsed_ms,
    }
}

/// Everything `recall` does after validation, as one future the handler can
/// put a deadline on. Each `stage::enter` names the step a timeout reports.
async fn recall_pipeline(
    state: &Arc<AppState>,
    auth: &AuthInfo,
    body: &RecallRequest,
    weights: &ScoringWeights,
    sort: RecallSort,
) -> Result<RecallResponse, AppError> {
    let owner = &auth.owner;
    let namespace = &body.namespace;

    stage::enter(RecallStage::Embed);
    let t0 = std::time::Instant::now();
    let query_vector = generate_recall_embedding_cached(state, &body.query).await?;
    let embed_ms = t0.elapsed().as_millis();

    // Cap limit to prevent unbounded DB scans / memory use.
    // Without this, an attacker could send limit=999999 to scan the entire DB.
    let limit = body.limit.min(100);
    // `sort=recent` pulls a wider candidate set than it returns — the newest
    // row is frequently a mediocre semantic match and would otherwise fall
    // outside the cosine top-`limit` entirely. `Relevance` fetches exactly
    // `limit`, so the default path issues the identical query it always has.
    let candidate_limit = sort.candidate_limit(limit);
    stage::enter(RecallStage::VectorSearch);
    let t1 = std::time::Instant::now();
    let hits = state
        .db
        .search_similar(&query_vector, owner, namespace, candidate_limit)
        .await?;
    let vsearch_ms = t1.elapsed().as_millis();

    // Order and truncate on the SearchHits, BEFORE hydration: ranking needs
    // only distance + created_at, both already on the row, so the over-fetch
    // costs one wider SQL query instead of 5x the Walrus downloads and SEAL
    // decrypts.
    let hits = super::select_hits_for_sort(hits, sort, limit);
    let hit_count = hits.len();

    if hits.is_empty() {
        tracing::info!(
            "recall complete: 0 results (no vector hits) for owner={}",
            owner
        );
        return Ok(RecallResponse {
            results: vec![],
            total: 0,
            dropped_count: 0,
        });
    }

    // Hydrate the hits through the storage engine: blob cache -> Walrus
    // download -> batched SEAL decrypt -> UTF-8, with reactive cleanup on
    // Walrus 404 (decrypt failures are dropped, never deleted). The
    // engine owns the
    // cache/decrypt-batch internals and derives the SEAL credential from
    // `auth`; per-blob timing breakdowns are visible in its tracing spans.
    stage::enter(RecallStage::WalrusDownload);
    let t2 = std::time::Instant::now();
    let hit_refs: Vec<(String, f64)> = hits
        .iter()
        .map(|h| (h.blob_id.clone(), h.distance))
        .collect();
    let (mut hydrated, dropped_count, timings) = state
        .engine
        .fetch_batch(owner, namespace, &hit_refs, auth)
        .await?;
    let fetch_ms = t2.elapsed().as_millis();

    // Zip `created_at` (recency signal) + `importance` from the
    // SearchHits onto the HydratedMemory records so the ranker has both
    // signals it needs. Engines leave both fields as `None`; the recall
    // path populates them from the SearchHit it already has. See
    // `routes::zip_search_hit_fields_onto_hydrated`.
    super::zip_search_hit_fields_onto_hydrated(&mut hydrated, &hits);

    // Log when the ranker is opted in (non-default `scoring_weights`) so a
    // future "client X is seeing weird ordering" debugging session has a
    // breadcrumb. Default weights short-circuit and aren't logged — that's
    // every other request.
    if weights.is_ranker_active() {
        tracing::info!(
            owner = %owner,
            semantic = weights.semantic,
            recency = weights.recency,
            half_life_days = weights.recency_half_life_days,
            // include the importance weight in the breadcrumb so
            // ordering bug reports can be triaged against the full vector
            // of weights the client sent.
            importance = weights.importance,
            "recall: ranker active"
        );
    }

    // Composite re-rank. With default weights (semantic=1.0, recency=0.0)
    // this is a no-op and preserves the pgvector cosine order exactly —
    // pinned by the `default_weights_preserve_input_order` and
    // `recency_zero_is_short_circuit_no_reorder` tests in services::ranker.
    let ranked = state.ranker.rank(hydrated, weights, chrono::Utc::now());

    let results: Vec<RecallResult> = super::recall_results_from_ranked(ranked);
    let total = results.len();

    // Surface the count of silently-dropped entries (download /
    // decrypt / UTF-8 failures) so clients can distinguish "no matches"
    // from "matches we couldn't return". Per-item errors are logged with
    // the blob_id inside the engine.
    if dropped_count > 0 {
        tracing::warn!(
            "recall: {} of {} matches dropped due to download/decrypt errors (owner={})",
            dropped_count,
            hit_count,
            owner
        );
    }
    // Per-stage `walrus=Xms seal=Xms` keeps parity with the pre-refactor
    // log line that combined the two stages into `fetch=Xms`. Benchmark
    // mode reports the entire Postgres-select fetch as `walrus_ms` and
    // leaves `seal_ms` at 0 — same shape, different mode.
    tracing::info!(
        "recall complete: {} results for owner={} embed={}ms vsearch={}ms walrus={}ms seal={}ms fetch={}ms total={}ms",
        total,
        owner,
        embed_ms,
        vsearch_ms,
        timings.walrus_ms,
        timings.seal_ms,
        fetch_ms,
        t0.elapsed().as_millis()
    );

    Ok(RecallResponse {
        results,
        total,
        dropped_count,
    })
}

/// POST /api/recall/manual
///
/// Manual flow — user provides pre-computed query vector.
/// Server searches Vector DB and returns {blob_id, distance}[].
/// User downloads from Walrus + SEAL decrypts on their own.
///
/// manual recall applies the **same** `CompositeRanker` as
/// `/api/recall` and `/api/ask`, so all three return the same ordering for
/// the same query + `scoring_weights`. Before this fix, manual recall
/// returned raw cosine order while the others reordered when weights were
/// set (the cycle-13 ranker only ran on the hydrating paths), so the two
/// disagreed. The ranker scores the `SearchHit` fields directly
/// (`distance` / `created_at` / `importance`) — no Walrus fetch, no SEAL
/// decrypt — preserving manual recall's lightweight "client hydrates"
/// contract. At default weights this is a no-op: the ranker short-circuits
/// and the pgvector cosine order is returned unchanged.
pub async fn recall_manual(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    Json(body): Json<RecallManualRequest>,
) -> Result<Json<RecallManualResponse>, AppError> {
    // Validate the client-supplied query vector (width + finiteness) up front.
    // The store's embedding column is fixed-width and refuses NaN/Inf, so a
    // malformed query vector can only fail inside pgvector and surface as an
    // opaque 500; reject it here with an actionable 400. (No upload/gas on this
    // read path, unlike remember_manual — this is purely a clearer-error improvement.)
    validate_embedding_vector(&body.vector)?;
    validate_namespace(&body.namespace)?;

    // Validate scoring_weights up front (NaN / out-of-range / sub-floor
    // half-life) before the vector search, mirroring `recall`. Previously
    // the manual path silently ignored weights entirely; now they apply, so
    // malformed input must 400 rather than be discarded.
    let weights = body.scoring_weights.clone().unwrap_or_default();
    weights.validate()?;

    let owner = &auth.owner;
    let namespace = &body.namespace;
    tracing::info!(
        "recall_manual: vector_dims={} limit={} owner={} ns={} ranker_active={}",
        body.vector.len(),
        body.limit,
        owner,
        namespace,
        weights.is_ranker_active()
    );

    // Search Vector DB — blob IDs + distances (+ created_at + importance).
    // Cap limit on recall_manual as well.
    let limit = body.limit.min(100);
    let hits = state
        .db
        .search_similar(&body.vector, owner, namespace, limit)
        .await?;

    // Apply the shared CompositeRanker so manual ordering matches
    // `/api/recall` and `/api/ask`. `rank_search_hits` reuses the
    // exact same `rank()` the hydrating paths use — see its doc for why we
    // map through `HydratedMemory`. At default weights it short-circuits and
    // preserves the pgvector cosine order. Index-based reorder => no hit is
    // dropped, so `results.len()` equals the search hit count.
    let results = rank_search_hits(state.ranker.as_ref(), hits, &weights, chrono::Utc::now());
    let total = results.len();

    if weights.is_ranker_active() {
        tracing::info!(
            owner = %owner,
            semantic = weights.semantic,
            recency = weights.recency,
            half_life_days = weights.recency_half_life_days,
            importance = weights.importance,
            "recall_manual: ranker active"
        );
    }

    tracing::info!(
        "recall_manual complete: {} results for owner={} ns={}",
        total,
        owner,
        namespace
    );

    Ok(Json(RecallManualResponse { results, total }))
}

#[cfg(test)]
mod tests {
    // ── Recall limit capped at 100 ───────────────────────────────

    #[test]
    fn recall_limit_capped_at_100() {
        fn cap_limit(limit: usize) -> usize {
            limit.min(100)
        }

        assert_eq!(cap_limit(999999), 100);
        assert_eq!(cap_limit(100), 100);
        assert_eq!(cap_limit(50), 50);
        assert_eq!(cap_limit(1), 1);
        assert_eq!(cap_limit(0), 0);
    }

    // ── RecallResponse dropped_count serialization ───────────────

    /// The failure report added for accepted-then-failed writes reads the same
    /// `remember_jobs.error_msg` the job-status endpoints read, and reaches the
    /// same untrusted caller — so it has to be sanitized the same way. It was
    /// not, which put the relayer's own wallet address and balance shortfall
    /// into every recall response for 24 hours after an infra failure.
    ///
    /// `infra_wal_balance_failure_hides_relayer_wallet_address` in
    /// routes::remember pins this for `GET /api/remember/:job_id`; this pins
    /// the same guarantee for the recall path.
    #[test]
    fn failed_write_report_hides_relayer_wallet_address() {
        let raw = "walrus upload failed: Insufficient balance of \
0x356a26eb9e012a68958082340d4c4116e7f55615ef27affcff209cf0ae544f59::wal::WAL for owner \
0x8d3c1f0a9b2e4d6c7a5f8e1b0d4c9a2f3e6b7d8c1a0f9e2b3c4d5a6f7e8b9c0d. Required: 64367730, \
Available: 10708877";

        let out =
            crate::routes::remember::sanitize_job_error_for_client("failed", Some(raw.to_string()))
                .expect("a failed job keeps an error");

        // The operator's hot wallet and its shortfall are not the tenant's
        // business, and reading them as "top this address up" is the exact
        // confusion INFRA_JOB_ERROR_MESSAGE exists to prevent.
        assert!(
            !out.contains("0x8d3c1f0a"),
            "wallet address leaked: {}",
            out
        );
        assert!(!out.contains("Available"), "balance leaked: {}", out);
        assert!(!out.contains("10708877"), "shortfall leaked: {}", out);
    }

    #[test]
    fn recall_response_includes_dropped_count_when_nonzero() {
        let resp = crate::types::RecallResponse {
            results: vec![],
            total: 0,
            dropped_count: 3,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["dropped_count"], 3);
    }

    #[test]
    fn recall_response_omits_dropped_count_when_zero() {
        let resp = crate::types::RecallResponse {
            results: vec![],
            total: 0,
            dropped_count: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        // skip_serializing_if = "is_zero_usize" → field absent
        assert!(json.get("dropped_count").is_none());
    }

    // ── manual recall applies the same ranker as non-manual ───

    use crate::services::ranker::{CompositeRanker, Ranker};
    use crate::types::{ScoringWeights, SearchHit};
    use chrono::{DateTime, TimeZone, Utc};

    fn t_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 22, 12, 0, 0).unwrap()
    }

    fn sh(blob_id: &str, distance: f64, age_days: i64, importance: f32) -> SearchHit {
        SearchHit {
            blob_id: blob_id.into(),
            distance,
            created_at: t_now() - chrono::Duration::days(age_days),
            importance,
        }
    }

    /// Ranking the equivalent hydrated memories directly (the non-manual
    /// path) and ranking the SearchHits via `rank_search_hits` (the manual
    /// path) MUST produce the same blob_id ordering — that's the whole point
    /// of this shared-ranker check. Use importance-heavy weights so the ranker actually
    /// reorders (a no-op would pass trivially).
    #[test]
    fn manual_ranking_matches_non_manual_ranking() {
        use crate::engine::HydratedMemory;
        use crate::services::extractor::{IMPORTANCE_TRIVIAL, IMPORTANCE_VITAL};

        let weights = ScoringWeights {
            semantic: 0.3,
            recency: 0.0,
            recency_half_life_days: 30.0,
            importance: 0.7,
        };

        // Cosine-order input where a vital fact sits *below* a trivial one;
        // importance-heavy ranking should promote the vital fact.
        let hits = vec![
            sh("trivial_near", 0.20, 0, IMPORTANCE_TRIVIAL),
            sh("vital_far", 0.25, 0, IMPORTANCE_VITAL),
        ];

        // Manual path: rank the SearchHits via the function under test.
        let manual = super::rank_search_hits(&CompositeRanker, hits.clone(), &weights, t_now());
        let manual_order: Vec<&str> = manual.iter().map(|h| h.blob_id.as_str()).collect();

        // Non-manual path: rank the *equivalent* HydratedMemory values
        // through the same ranker (this is what /api/recall does post-hydrate).
        let hydrated: Vec<HydratedMemory> = hits
            .iter()
            .map(|h| HydratedMemory {
                blob_id: h.blob_id.clone(),
                text: format!("decrypted text for {}", h.blob_id),
                distance: h.distance,
                created_at: Some(h.created_at),
                importance: Some(h.importance),
            })
            .collect();
        let non_manual = CompositeRanker.rank(hydrated, &weights, t_now());
        let non_manual_order: Vec<&str> = non_manual
            .iter()
            .map(|r| r.memory.blob_id.as_str())
            .collect();

        assert_eq!(
            manual_order, non_manual_order,
            "manual and non-manual ranking must agree on ordering"
        );
        // And confirm the ranker actually reordered (vital promoted above trivial).
        assert_eq!(manual_order, vec!["vital_far", "trivial_near"]);
    }

    /// At default weights the ranker short-circuits — manual recall must
    /// return the SearchHits in their original (pgvector cosine) order,
    /// byte-identical to the previous behaviour.
    #[test]
    fn manual_ranking_default_weights_preserves_cosine_order() {
        use crate::services::extractor::{IMPORTANCE_TRIVIAL, IMPORTANCE_VITAL};

        // Deliberately put a vital fact last in cosine order — default
        // weights must NOT promote it.
        let hits = vec![
            sh("a", 0.10, 0, IMPORTANCE_TRIVIAL),
            sh("b", 0.30, 100, IMPORTANCE_VITAL),
            sh("c", 0.50, 1, IMPORTANCE_TRIVIAL),
        ];
        let ranked =
            super::rank_search_hits(&CompositeRanker, hits, &ScoringWeights::default(), t_now());
        let order: Vec<&str> = ranked.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    /// The ranked output must preserve the full SearchHit fields
    /// (created_at + importance), not drop them — clients rely on the shape.
    #[test]
    fn manual_ranking_preserves_search_hit_fields() {
        use crate::services::extractor::IMPORTANCE_VITAL;
        let hits = vec![sh("only", 0.10, 7, IMPORTANCE_VITAL)];
        let ranked =
            super::rank_search_hits(&CompositeRanker, hits, &ScoringWeights::default(), t_now());
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].blob_id, "only");
        assert_eq!(ranked[0].distance, 0.10);
        assert_eq!(ranked[0].importance, IMPORTANCE_VITAL);
        assert_eq!(ranked[0].created_at, t_now() - chrono::Duration::days(7));
    }

    /// Remap is by input index, not blob_id, so two hits sharing a blob_id
    /// are both kept. Tested at default (short-circuit) and active weights.
    #[test]
    fn manual_ranking_keeps_duplicate_blob_ids() {
        use crate::services::extractor::{IMPORTANCE_TRIVIAL, IMPORTANCE_VITAL};

        // Two hits sharing a blob_id, plus a distinct one — three in total.
        let hits = vec![
            sh("dup", 0.10, 0, IMPORTANCE_TRIVIAL),
            sh("dup", 0.30, 0, IMPORTANCE_VITAL),
            sh("other", 0.20, 0, IMPORTANCE_TRIVIAL),
        ];

        // Default weights → short-circuit → input order preserved, no drop.
        let ranked = super::rank_search_hits(
            &CompositeRanker,
            hits.clone(),
            &ScoringWeights::default(),
            t_now(),
        );
        assert_eq!(ranked.len(), 3, "duplicate blob_ids must not be dropped");
        // Order + per-hit distances preserved exactly (the wrong-survivor bug
        // would swap the two `dup` distances).
        assert_eq!(
            ranked.iter().map(|h| h.distance).collect::<Vec<_>>(),
            vec![0.10, 0.30, 0.20]
        );

        // Active weights (importance-heavy) → still all three, reordered by
        // score. The vital `dup` (0.30 dist) should outrank the trivial `dup`
        // (0.10 dist) and the trivial `other`.
        let weights = ScoringWeights {
            semantic: 0.3,
            recency: 0.0,
            recency_half_life_days: 30.0,
            importance: 0.7,
        };
        let ranked = super::rank_search_hits(&CompositeRanker, hits, &weights, t_now());
        assert_eq!(ranked.len(), 3, "no hit dropped under active weights");
        // vital dup wins: 0.3*(1-0.30) + 0.7*0.9 = 0.21 + 0.63 = 0.84
        assert_eq!(ranked[0].distance, 0.30);
        assert_eq!(ranked[0].importance, IMPORTANCE_VITAL);
    }

    /// Empty hit list ranks to empty (no panic, no spurious entries).
    #[test]
    fn manual_ranking_empty_hits_returns_empty() {
        let ranked = super::rank_search_hits(
            &CompositeRanker,
            vec![],
            &ScoringWeights::default(),
            t_now(),
        );
        assert!(ranked.is_empty());
    }

    /// Index carry-through under a NON-TRIVIAL reorder of MANY items. The
    /// 2-3 element parity tests can't catch an off-by-one or wrong-survivor
    /// in the `slots[idx].take()` reassembly. Build 8 hits whose importance
    /// forces a known full permutation, and assert the entire reordered
    /// (blob_id, distance) sequence — not just the count — survives the
    /// index round-trip exactly, AND matches the non-manual path.
    #[test]
    fn manual_ranking_many_item_permutation_round_trips_exactly() {
        use crate::engine::HydratedMemory;

        // 8 hits, ascending cosine distance (so input/cosine order is the
        // identity). Importance increases in the OPPOSITE direction, so an
        // importance-only weight reverses the order — a full permutation
        // that touches every slot index.
        let hits: Vec<SearchHit> = (0..8)
            .map(|i| {
                // distance 0.10..0.45 ascending; importance 0.9..0.2 descending
                let distance = 0.10 + (i as f64) * 0.05;
                let importance = 0.9 - (i as f32) * 0.1;
                sh(&format!("hit{i}"), distance, 0, importance)
            })
            .collect();

        let weights = ScoringWeights {
            semantic: 0.0,
            recency: 0.0,
            recency_half_life_days: 30.0,
            importance: 1.0,
        };

        let manual = super::rank_search_hits(&CompositeRanker, hits.clone(), &weights, t_now());

        // Expected: reversed (highest importance = hit0 first ... hit7 last).
        let manual_pairs: Vec<(String, f64)> = manual
            .iter()
            .map(|h| (h.blob_id.clone(), h.distance))
            .collect();
        let expected: Vec<(String, f64)> = (0..8)
            .map(|i| (format!("hit{i}"), 0.10 + (i as f64) * 0.05))
            .collect();
        assert_eq!(
            manual_pairs, expected,
            "index reassembly corrupted the (blob_id, distance) pairing under an 8-item reorder"
        );

        // And it must match the non-manual path on the same inputs.
        let hydrated: Vec<HydratedMemory> = hits
            .iter()
            .map(|h| HydratedMemory {
                blob_id: h.blob_id.clone(),
                text: String::new(),
                distance: h.distance,
                created_at: Some(h.created_at),
                importance: Some(h.importance),
            })
            .collect();
        let non_manual = CompositeRanker.rank(hydrated, &weights, t_now());
        let non_manual_order: Vec<&str> = non_manual
            .iter()
            .map(|r| r.memory.blob_id.as_str())
            .collect();
        let manual_order: Vec<&str> = manual.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(manual_order, non_manual_order);
    }

    /// Combined weights — semantic + recency + importance all non-zero (the
    /// realistic production weight vector). A term-coupling/sign bug only
    /// surfaces when all three signals are live. Manual must match non-manual.
    #[test]
    fn manual_ranking_combined_weights_matches_non_manual() {
        use crate::engine::HydratedMemory;
        use crate::services::extractor::{
            IMPORTANCE_STANDARD, IMPORTANCE_TRIVIAL, IMPORTANCE_VITAL,
        };

        let weights = ScoringWeights {
            semantic: 0.3,
            recency: 0.3,
            recency_half_life_days: 30.0,
            importance: 0.4,
        };
        let hits = vec![
            sh("a", 0.15, 200, IMPORTANCE_TRIVIAL),
            sh("b", 0.25, 5, IMPORTANCE_VITAL),
            sh("c", 0.20, 60, IMPORTANCE_STANDARD),
            sh("d", 0.40, 0, IMPORTANCE_VITAL),
            sh("e", 0.10, 365, IMPORTANCE_TRIVIAL),
        ];

        let manual = super::rank_search_hits(&CompositeRanker, hits.clone(), &weights, t_now());
        let manual_order: Vec<&str> = manual.iter().map(|h| h.blob_id.as_str()).collect();

        let hydrated: Vec<HydratedMemory> = hits
            .iter()
            .map(|h| HydratedMemory {
                blob_id: h.blob_id.clone(),
                text: String::new(),
                distance: h.distance,
                created_at: Some(h.created_at),
                importance: Some(h.importance),
            })
            .collect();
        let non_manual = CompositeRanker.rank(hydrated, &weights, t_now());
        let non_manual_order: Vec<&str> = non_manual
            .iter()
            .map(|r| r.memory.blob_id.as_str())
            .collect();

        assert_eq!(
            manual_order, non_manual_order,
            "manual and non-manual must agree under combined weights"
        );
        assert_eq!(manual.len(), 5, "no hit dropped under combined weights");
    }

    /// Recency-weighted parity: manual ranking must match non-manual for a
    /// recency-heavy weight set too (closes the loop beyond importance).
    #[test]
    fn manual_ranking_recency_matches_non_manual() {
        use crate::engine::HydratedMemory;
        use crate::services::extractor::IMPORTANCE_STANDARD;

        let weights = ScoringWeights {
            semantic: 0.4,
            recency: 0.6,
            recency_half_life_days: 30.0,
            importance: 0.0,
        };
        // "older" has the better cosine match; "newer" is brand new. Recency-
        // heavy weights should promote "newer".
        let hits = vec![
            sh("older", 0.20, 365, IMPORTANCE_STANDARD),
            sh("newer", 0.25, 0, IMPORTANCE_STANDARD),
        ];

        let manual = super::rank_search_hits(&CompositeRanker, hits.clone(), &weights, t_now());
        let manual_order: Vec<&str> = manual.iter().map(|h| h.blob_id.as_str()).collect();

        let hydrated: Vec<HydratedMemory> = hits
            .iter()
            .map(|h| HydratedMemory {
                blob_id: h.blob_id.clone(),
                text: String::new(),
                distance: h.distance,
                created_at: Some(h.created_at),
                importance: Some(h.importance),
            })
            .collect();
        let non_manual = CompositeRanker.rank(hydrated, &weights, t_now());
        let non_manual_order: Vec<&str> = non_manual
            .iter()
            .map(|r| r.memory.blob_id.as_str())
            .collect();

        assert_eq!(manual_order, non_manual_order);
        assert_eq!(manual_order, vec!["newer", "older"]);
    }
}
