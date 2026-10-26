//! HTTP route handlers, split by endpoint family (phase 4.2).
//!
//! Each submodule owns a related group of handlers:
//! - `remember` — `/api/remember`, `/api/remember/manual`, `/api/remember/bulk`
//!   (+ the async prep tasks and the summarize-for-embedding helpers)
//! - `recall` — `/api/recall`, `/api/recall/manual` (+ the recall-embedding cache)
//! - `analyze` — `/api/analyze` (fact extraction → store; sync bypass in benchmark mode)
//! - `admin` — `/api/embed`, `/api/ask`, `/api/forget`, `/api/stats`, `/api/restore`,
//!   `/health`, `/version`, `/config`
//! - `sponsor` — `/sponsor`, `/sponsor/execute` (Enoki proxy)
//! - `accounts` — `/api/accounts/{owner}/exists` (public MemWalAccount
//!   existence check)
//! - `memory_read` — `GET /v1/owners/{owner}/{namespaces,memories,agents}`
//!   (owner-scoped, cursor-paginated reads; accepts either the Ed25519
//!   signed-request scheme or an owner-scoped bearer token — see
//!   `auth::verify_read_api_auth`)
//! - `owner_token` — `POST /v1/owner-tokens` (owner-scoped bearer
//!   token issuance) + `GET /v1/owners/{owner}/_token_probe` (the original
//!   dev-only smoke-test route this mechanism was proven against before
//!   `memory_read`'s real handlers existed; now redundant with them)
//!
//! Shared route-level helpers (`enqueue_wallet_job`, `truncate_str`,
//! `collect_bounded_results`, `cleanup_expired_blob`) live here in `mod.rs`.
//! Capability-level code (embedding, extraction, OpenAI chat wire types,
//! prompt assets) lives in `crate::services` per the Phase 2/3 refactor.

mod accounts;
mod admin;
mod incident;
pub mod admin_activity;
pub mod admin_dashboard;
mod analyze;
mod memory_read;
pub mod oauth;
pub mod owner_token;
mod recall;
mod remember;
pub mod security_delete;
mod sponsor;

// Re-export every handler so `main.rs` keeps using `routes::<name>`
// without having to know which submodule each handler lives in.
pub use accounts::{account_exists, whoami};
pub use incident::{
    delegate_keys, incident_status, list_unblock_requests, request_unblock,
};
pub use admin::{ask, embed, forget, get_config, health, restore, stats, version};
pub use analyze::analyze;
pub use memory_read::{list_owner_agents, list_owner_memories, list_owner_namespaces};
pub use owner_token::{issue_token, token_probe};
pub use recall::{recall, recall_manual};
pub use remember::{
    remember, remember_bulk, remember_bulk_status, remember_manual, remember_status,
};
pub use sponsor::{sponsor_execute_proxy, sponsor_proxy};

use futures::stream::{self, StreamExt};

use crate::jobs::{wallet_job_queue, wallet_job_request, WalletJob, WalletOperation};
use crate::storage::db::VectorDb;
use crate::types::*;

use apalis::prelude::Storage as _;

// ============================================================
// Wallet-job enqueue (used by remember + analyze)
// ============================================================

/// Enqueue a WalletJob. Uploads stay on the prefetch queue. Metadata and
/// finalize go to the followup queue, whose workers are not already holding
/// a batch of uploads.
///
/// `wallet_index` is preserved in the job payload for audit/logging. Upload
/// workers select a fresh round-robin key at execution time so Apalis retries
/// can move to another wallet.
pub async fn enqueue_wallet_job(
    state: &AppState,
    wallet_index: usize,
    operation: WalletOperation,
) -> Result<usize, AppError> {
    let job = WalletJob {
        wallet_index,
        congestion_requeues: 0,
        operation,
    };
    let mut storage = wallet_job_queue(state, &job.operation);
    match storage.push_request(wallet_job_request(job)).await {
        Ok(_) => Ok(wallet_index),
        Err(e) => {
            crate::alerts::maybe_alert_sqlx_postgres_storage_exhausted(
                &state.alerts,
                &state.config.sui_network,
                &e,
            )
            .await;
            Err(AppError::Internal(format!(
                "Failed to enqueue WalletJob: {}",
                e
            )))
        }
    }
}

// ============================================================
// String truncation helper (used in several `tracing::info!` lines)
// ============================================================

/// Truncate a string to at most `max_bytes` bytes without splitting a UTF-8
/// character.  Falls back to the nearest char boundary when `max_bytes` lands
/// inside a multi-byte sequence (e.g. emoji).
#[cfg(test)]
pub(super) fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ============================================================
// Bounded-concurrency task collection
// ============================================================

/// Run `tasks` with at most `concurrency` in flight, returning their
/// results in the original order.
pub(super) async fn collect_bounded_results<F, T, E>(
    tasks: Vec<F>,
    concurrency: usize,
) -> Vec<Result<T, E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let mut indexed_results = stream::iter(tasks)
        .enumerate()
        .map(|(idx, task)| async move { (idx, task.await) })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;
    indexed_results.sort_by_key(|(idx, _)| *idx);
    indexed_results
        .into_iter()
        .map(|(_, result)| result)
        .collect()
}

// ============================================================
// Reactive expired-blob cleanup
// ============================================================

/// Reactively delete an expired blob from the vector DB.
/// Called when Walrus returns 404 (blob expired / not found).
/// Errors are logged but not propagated — cleanup is best-effort.
///
/// `owner` and `namespace` are required so the DELETE is scoped to the
/// caller's isolated rows. The DB layer enforces all three predicates, so an
/// expired blob discovered in one namespace cannot delete another entry even
/// if the owner and blob_id are identical.
pub(super) async fn cleanup_expired_blob(
    db: &VectorDb,
    blob_id: &str,
    owner: &str,
    namespace: &str,
) {
    match db.delete_by_blob_id(blob_id, owner, namespace).await {
        Ok(rows) => {
            tracing::info!(
                "reactive cleanup: deleted {} vector entries for expired blob_id={} owner={} namespace={}",
                rows,
                blob_id,
                owner,
                namespace
            );
        }
        Err(e) => {
            tracing::error!(
                "reactive cleanup failed for blob_id={} owner={} namespace={}: {}",
                blob_id,
                owner,
                namespace,
                e
            );
        }
    }
}

// ============================================================
// Ranker plumbing — zip created_at + importance from SearchHits onto
// HydratedMemory
// ============================================================

/// Zip the `created_at` timestamp **and** the `importance` score
/// from a slice of `SearchHit`s onto a mutable slice of `HydratedMemory`s
/// by `blob_id`. The storage engines deliberately leave both fields as
/// `None` (they don't fetch them as part of the cache → Walrus → SEAL
/// choreography); the recall handler already has both on the `SearchHit`
/// from `db.search_similar` and threads them onto the hydrated records
/// here so the composite ranker can use them for the recency / importance
/// signals.
///
/// Same pattern is used by both `/api/recall` and `/api/ask` — extracting
/// it here keeps the two call sites in sync.
///
/// Renamed from `zip_created_at_onto_hydrated` once importance
/// joined the zip. Single function (rather than two separate ones) because
/// both fields come from the same `SearchHit` and we don't want to walk
/// the hits vector twice for what's a hot path.
pub(super) fn zip_search_hit_fields_onto_hydrated(
    hydrated: &mut [crate::engine::HydratedMemory],
    hits: &[SearchHit],
) {
    let by_blob: std::collections::HashMap<&str, (chrono::DateTime<chrono::Utc>, f32)> = hits
        .iter()
        .map(|h| (h.blob_id.as_str(), (h.created_at, h.importance)))
        .collect();
    for m in hydrated.iter_mut() {
        if let Some((ts, imp)) = by_blob.get(m.blob_id.as_str()).copied() {
            m.created_at = Some(ts);
            m.importance = Some(imp);
        } else {
            m.created_at = None;
            m.importance = None;
        }
    }
}

/// Choose which search hits to hydrate, and in what order.
///
/// Runs on `SearchHit`s — **before** the Walrus download + SEAL decrypt — so
/// `Recent`'s over-fetch costs one wider SQL query rather than five times the
/// decrypt work. Nothing here needs the plaintext: distance and `created_at`
/// both come back from `search_similar` on the same row.
pub(super) fn select_hits_for_sort(
    mut hits: Vec<SearchHit>,
    sort: crate::types::RecallSort,
    limit: usize,
) -> Vec<SearchHit> {
    if sort == crate::types::RecallSort::Recent {
        // Newest first, falling back to the better semantic match when two
        // rows share a timestamp — otherwise same-instant writes would be
        // ordered arbitrarily by sort instability.
        hits.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then(a.distance.total_cmp(&b.distance))
        });
    }
    // `Relevance` needs no sort: `search_similar` already returns cosine
    // order. Truncation is shared — for `Recent` it must happen AFTER the
    // sort, which is the whole point of the over-fetch.
    hits.truncate(limit);
    hits
}

/// The scoring weights `/api/recall` hands to the ranker. An explicit `sort`
/// must not be re-ranked, so it yields the default (no-op) weights; malformed
/// weights are rejected either way.
pub(super) fn resolve_scoring_weights(
    sort: Option<crate::types::RecallSort>,
    requested: Option<crate::types::ScoringWeights>,
) -> Result<crate::types::ScoringWeights, crate::types::AppError> {
    let requested = requested.unwrap_or_default();
    requested.validate()?;
    if sort.is_some() {
        return Ok(crate::types::ScoringWeights::default());
    }
    Ok(requested)
}

/// Project the ranker's output onto the `/api/recall` and `/api/ask` wire
/// shape, preserving ranked order.
///
/// Shared by both handlers so the set of fields that reach a client is
/// decided in one place — they previously carried identical inline `map`
/// closures, and `created_at` (WALM-383) would otherwise have had to be
/// added to each by hand.
pub(super) fn recall_results_from_ranked(
    ranked: Vec<crate::services::ranker::RankedHit>,
) -> Vec<crate::types::RecallResult> {
    ranked
        .into_iter()
        .map(|r| crate::types::RecallResult {
            blob_id: r.memory.blob_id,
            text: r.memory.text,
            distance: r.memory.distance,
            // `score` is `Some` only when the ranker ran (recency > 0); the
            // `#[serde(skip_serializing_if = "Option::is_none")]` on the
            // type omits the field from the wire when default-weighted.
            score: r.score,
            created_at: r.memory.created_at,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{collect_bounded_results, truncate_str};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn bounded_collection_limits_concurrency() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let tasks: Vec<_> = (0..12)
            .map(|_| {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                async move {
                    let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now_active, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok::<usize, ()>(now_active)
                }
            })
            .collect();

        let results = collect_bounded_results(tasks, 5).await;
        assert_eq!(results.len(), 12);
        assert!(peak.load(Ordering::SeqCst) <= 5);
    }

    #[test]
    fn truncate_str_ascii() {
        assert_eq!(truncate_str("hello world", 5), "hello");
    }

    #[test]
    fn truncate_str_no_truncation_needed() {
        assert_eq!(truncate_str("hi", 100), "hi");
    }

    #[test]
    fn truncate_str_empty() {
        assert_eq!(truncate_str("", 10), "");
    }

    #[test]
    fn truncate_str_multibyte_char_boundary() {
        // "café" = 5 bytes (é = 2 bytes). Truncating at 4 bytes → "caf" (not mid-é)
        let s = "café";
        assert_eq!(s.len(), 5); // c=1, a=1, f=1, é=2
        let t = truncate_str(s, 4);
        assert_eq!(t, "caf"); // stops before the 2-byte é
    }

    #[test]
    fn truncate_str_emoji_boundary() {
        // "🦀hello" = 4 + 5 = 9 bytes. Truncating at 2 → "" (can't split 🦀)
        let s = "🦀hello";
        let t = truncate_str(s, 2);
        assert_eq!(t, ""); // can't include partial emoji
    }
}

#[cfg(test)]
mod recall_sort_tests {
    use crate::types::{RecallSort, SearchHit};

    fn ts(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// `distance` ascending is the order pgvector hands back.
    fn search_hit(blob_id: &str, distance: f64, created_at: &str) -> SearchHit {
        SearchHit {
            blob_id: blob_id.to_string(),
            distance,
            created_at: ts(created_at),
            importance: 0.5,
        }
    }

    // ── candidate_limit ──────────────────────────────────────

    #[test]
    fn relevance_fetches_exactly_what_the_caller_asked_for() {
        assert_eq!(RecallSort::Relevance.candidate_limit(10), 10);
        assert_eq!(RecallSort::Relevance.candidate_limit(100), 100);
    }

    #[test]
    fn recent_over_fetches_five_times_the_limit() {
        assert_eq!(RecallSort::Recent.candidate_limit(3), 15);
        assert_eq!(RecallSort::Recent.candidate_limit(10), 50);
    }

    #[test]
    fn recent_over_fetch_is_capped_so_recall_is_not_a_table_scan() {
        assert_eq!(RecallSort::Recent.candidate_limit(20), 50);
    }

    #[test]
    fn recent_never_fetches_fewer_rows_than_the_caller_asked_for() {
        // A naive `min(limit * 5, 50)` returns 50 here — fewer than the 100
        // requested — and the caller silently gets a short page.
        assert_eq!(RecallSort::Recent.candidate_limit(100), 100);
        assert_eq!(RecallSort::Recent.candidate_limit(60), 60);
    }

    // ── selection ────────────────────────────────────────────

    #[test]
    fn relevance_keeps_the_cosine_order_and_truncates() {
        let hits = vec![
            search_hit("close-old", 0.10, "2026-07-01T00:00:00Z"),
            search_hit("mid", 0.30, "2026-07-03T00:00:00Z"),
            search_hit("far-new", 0.50, "2026-07-06T00:00:00Z"),
        ];

        let kept = super::select_hits_for_sort(hits, RecallSort::Relevance, 2);

        let ids: Vec<&str> = kept.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(ids, vec!["close-old", "mid"]);
    }

    /// The exact failure from WALM-383: the newest checkpoint is the WORST
    /// semantic match, so cosine ordering pushes it out of a `limit=2` window.
    /// `Recent` must return it first.
    #[test]
    fn recent_surfaces_the_newest_row_even_when_it_ranks_last_semantically() {
        let hits = vec![
            search_hit("close-old", 0.10, "2026-07-01T00:00:00Z"),
            search_hit("mid", 0.30, "2026-07-03T00:00:00Z"),
            search_hit("far-new", 0.50, "2026-07-06T00:00:00Z"),
        ];

        let kept = super::select_hits_for_sort(hits, RecallSort::Recent, 2);

        let ids: Vec<&str> = kept.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(ids, vec!["far-new", "mid"]);
    }

    #[test]
    fn recent_truncates_after_sorting_not_before() {
        // Truncating first would keep the two closest matches and drop the
        // newest — the bug this whole mode exists to prevent.
        let hits = vec![
            search_hit("a", 0.10, "2026-07-01T00:00:00Z"),
            search_hit("b", 0.20, "2026-07-02T00:00:00Z"),
            search_hit("newest", 0.90, "2026-07-09T00:00:00Z"),
        ];

        let kept = super::select_hits_for_sort(hits, RecallSort::Recent, 1);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].blob_id, "newest");
    }

    #[test]
    fn recent_breaks_a_created_at_tie_on_semantic_distance() {
        // Two checkpoints written the same instant: fall back to the better
        // match rather than leaving the order to sort instability.
        let hits = vec![
            search_hit("worse-match", 0.60, "2026-07-06T00:00:00Z"),
            search_hit("better-match", 0.20, "2026-07-06T00:00:00Z"),
        ];

        let kept = super::select_hits_for_sort(hits, RecallSort::Recent, 2);

        let ids: Vec<&str> = kept.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(ids, vec!["better-match", "worse-match"]);
    }

    #[test]
    fn selection_is_a_no_op_when_fewer_hits_than_the_limit() {
        let hits = vec![search_hit("only", 0.4, "2026-07-06T00:00:00Z")];

        let kept = super::select_hits_for_sort(hits, RecallSort::Recent, 10);

        assert_eq!(kept.len(), 1);
    }
}

/// Each test replays the recall handler's ordering (`select_hits_for_sort`,
/// then the ranker with the resolved weights) over hand-scored rows.
#[cfg(test)]
mod recall_sort_precedence_tests {
    use crate::engine::HydratedMemory;
    use crate::services::ranker::{CompositeRanker, Ranker};
    use crate::types::{AppError, RecallSort, ScoringWeights, SearchHit};

    fn ts(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        ts("2026-07-06T00:00:00Z")
    }

    /// `distance` ascending is the order pgvector hands back.
    fn search_hit(blob_id: &str, distance: f64, created_at: &str) -> SearchHit {
        SearchHit {
            blob_id: blob_id.to_string(),
            distance,
            created_at: ts(created_at),
            importance: 0.5,
        }
    }

    fn weights(recency: f64) -> ScoringWeights {
        ScoringWeights {
            semantic: 1.0,
            recency,
            recency_half_life_days: 30.0,
            importance: 0.0,
        }
    }

    fn recall_order(
        hits: Vec<SearchHit>,
        sort: Option<RecallSort>,
        requested: ScoringWeights,
    ) -> Vec<String> {
        let weights = super::resolve_scoring_weights(sort, Some(requested)).unwrap();
        let limit = hits.len();
        let hydrated: Vec<HydratedMemory> =
            super::select_hits_for_sort(hits, sort.unwrap_or_default(), limit)
                .into_iter()
                .map(|h| HydratedMemory {
                    blob_id: h.blob_id,
                    text: String::new(),
                    distance: h.distance,
                    created_at: Some(h.created_at),
                    importance: Some(h.importance),
                })
                .collect();
        CompositeRanker
            .rank(hydrated, &weights, now())
            .into_iter()
            .map(|r| r.memory.blob_id)
            .collect()
    }

    /// Composite scores at semantic 1.0 / recency 0.3 / half-life 30d:
    ///   old-but-close  = 0.90 + 0.3 * 2^(-30/30) = 1.05
    ///   newest-but-far = 0.10 + 0.3 * 2^(0/30)   = 0.40
    fn ticket_repro_hits() -> Vec<SearchHit> {
        vec![
            search_hit("old-but-close", 0.10, "2026-06-06T00:00:00Z"),
            search_hit("newest-but-far", 0.90, "2026-07-06T00:00:00Z"),
        ]
    }

    /// Composite scores at semantic 1.0 / recency 0.8 / half-life 30d:
    ///   close-old = 0.90 + 0.8 * 2^(-60/30) = 1.10
    ///   far-new   = 0.80 + 0.8 * 2^(0/30)   = 1.60
    /// so the ranker, when it runs, reverses the cosine order.
    fn weights_reverse_cosine_hits() -> Vec<SearchHit> {
        vec![
            search_hit("close-old", 0.10, "2026-05-07T00:00:00Z"),
            search_hit("far-new", 0.20, "2026-07-06T00:00:00Z"),
        ]
    }

    #[test]
    fn explicit_recent_is_not_reordered_by_scoring_weights() {
        assert_eq!(
            recall_order(ticket_repro_hits(), Some(RecallSort::Recent), weights(0.3)),
            ["newest-but-far", "old-but-close"]
        );
    }

    #[test]
    fn explicit_relevance_is_not_reordered_by_scoring_weights() {
        assert_eq!(
            recall_order(
                weights_reverse_cosine_hits(),
                Some(RecallSort::Relevance),
                weights(0.8)
            ),
            ["close-old", "far-new"]
        );
    }

    #[test]
    fn omitted_sort_lets_scoring_weights_rerank() {
        assert_eq!(
            recall_order(weights_reverse_cosine_hits(), None, weights(0.8)),
            ["far-new", "close-old"]
        );
    }

    /// Malformed weights are a 400 even when an explicit `sort` would ignore
    /// them — `sort` does not quietly excuse a bad request.
    #[test]
    fn malformed_weights_are_rejected_even_when_sort_is_explicit() {
        let mut malformed = weights(0.3);
        malformed.semantic = f64::NAN;
        assert!(matches!(
            super::resolve_scoring_weights(Some(RecallSort::Recent), Some(malformed)),
            Err(AppError::BadRequest(_))
        ));
    }
}

#[cfg(test)]
mod recall_result_mapping_tests {
    use crate::engine::HydratedMemory;
    use crate::services::ranker::RankedHit;

    fn ts(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn hit(blob_id: &str, created_at: Option<chrono::DateTime<chrono::Utc>>) -> RankedHit {
        RankedHit {
            memory: HydratedMemory {
                blob_id: blob_id.to_string(),
                text: format!("text for {blob_id}"),
                distance: 0.25,
                created_at,
                importance: Some(0.5),
            },
            score: None,
        }
    }

    /// Ask #1 of WALM-383: a caller implementing "newest wins" must be able to
    /// order results by write-time without parsing it back out of the memory
    /// text.
    #[test]
    fn mapping_carries_the_hydrated_created_at_onto_the_result() {
        let written_at = ts("2026-07-06T12:00:00Z");

        let results = super::recall_results_from_ranked(vec![hit("blob-1", Some(written_at))]);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].created_at, Some(written_at));
    }

    /// `zip_search_hit_fields_onto_hydrated` leaves `created_at` as `None` for
    /// a hydrated record with no matching SearchHit. That must stay absent
    /// rather than become a fabricated timestamp — for a newest-wins caller a
    /// wrong date is worse than a missing one.
    #[test]
    fn mapping_preserves_a_missing_created_at_as_none() {
        let results = super::recall_results_from_ranked(vec![hit("blob-1", None)]);

        assert_eq!(results[0].created_at, None);
    }

    /// Order is the ranker's output order; the mapping must not re-sort.
    #[test]
    fn mapping_preserves_ranked_order() {
        let results = super::recall_results_from_ranked(vec![
            hit("blob-1", Some(ts("2026-07-01T00:00:00Z"))),
            hit("blob-2", Some(ts("2026-07-06T00:00:00Z"))),
        ]);

        let ids: Vec<&str> = results.iter().map(|r| r.blob_id.as_str()).collect();
        assert_eq!(ids, vec!["blob-1", "blob-2"]);
    }
}
