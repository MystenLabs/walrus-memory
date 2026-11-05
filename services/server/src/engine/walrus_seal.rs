//! Production `MemoryEngine`: Walrus upload + SEAL decrypt + Postgres index.
//!
//! Holds the *one* copy of the storage choreography that is currently
//! inlined across `routes.rs` (`recall`, `ask`, `remember_manual`) and
//! `jobs.rs` (the `RememberJob` / `BulkRememberJob` workers):
//!
//! - **store_blob**: pick a Sui key (round-robin pool) → `walrus::upload_blob`
//!   the prepared ciphertext → `db.insert_vector`.
//! - **fetch_one**: Redis blob-cache lookup → on miss,
//!   `walrus::download_blob` with cache write-back → `seal::seal_decrypt` →
//!   UTF-8. Reactive cleanup of the index row (scoped to `owner` and
//!   `namespace`) on
//!   Walrus 404 only — the blob is provably gone. Decrypt failures never
//!   delete: they are logged and dropped. Returns `Ok(None)` for "gone",
//!   not an error.
//! - **fetch_batch**: per-id cache lookup, then `seal::seal_decrypt_batch`
//!   the cache-cold blobs in chunks of 25; same cleanup-on-404 semantics;
//!   returns `(hydrated, dropped_count)` so callers can tell "no matches"
//!   from "matches we couldn't return".
//!
//! The SEAL credential is derived from `&AuthInfo` here (prefer the
//! exported SessionKey, fall back to the legacy delegate key, then to
//! the server fallback key) — the same resolution `routes.rs` does
//! today via `seal::SealCredential::from_auth_or_fallback`.

use async_trait::async_trait;
use redis::AsyncCommands;
use std::sync::Arc;
use std::time::Duration;

use crate::storage::db::VectorDb;
use crate::storage::seal::{self, DecryptOutcome, SealCredential};
use crate::storage::walrus;
use crate::types::{AppError, AuthInfo, Config, KeyPool};

use super::{FetchTimings, HydratedMemory, MemoryEngine, MemoryRef};

/// Redis key prefix for the Walrus blob ciphertext cache.
const BLOB_CACHE_KEY_PREFIX: &str = "memwal:blob:v1:";
/// SEAL decrypt-batch chunk size (matches the inlined `recall` value).
const SEAL_DECRYPT_BATCH_SIZE: usize = 25;
/// Backoff before retrying a transient Walrus aggregator download failure.
const WALRUS_DOWNLOAD_RETRY_BACKOFF: Duration = Duration::from_millis(200);
/// Backoff before retrying a transient SEAL decrypt-batch failure.
const SEAL_DECRYPT_RETRY_BACKOFF: Duration = Duration::from_millis(250);
/// Minimum remaining recall deadline budget required after backoff to start a retry.
const RETRY_MIN_DEADLINE_HEADROOM: Duration = Duration::from_millis(1_000);

/// Production engine — uploads prepared ciphertext to Walrus, indexes
/// the row in Postgres, serves reads through the Redis blob cache.
///
/// Deps are held via `Arc<>` / cheap `Clone` so the engine shares
/// ownership with `AppState` rather than duplicating connections.
pub struct WalrusSealEngine {
    db: Arc<VectorDb>,
    http_client: reqwest::Client,
    key_pool: Arc<KeyPool>,
    config: Arc<Config>,
    redis: redis::aio::ConnectionManager,
    /// Blob ciphertext cache TTL. Zero disables write-back.
    blob_cache_ttl: Duration,
    /// Max ciphertext size kept in the Redis cache. Reads ignore
    /// entries larger than this (they get evicted via TTL eventually);
    /// writes skip blobs larger than this. Zero disables the cache
    /// entirely (read and write).
    blob_cache_max_bytes: usize,
}

impl WalrusSealEngine {
    pub fn new(
        db: Arc<VectorDb>,
        http_client: reqwest::Client,
        key_pool: Arc<KeyPool>,
        config: Arc<Config>,
        redis: redis::aio::ConnectionManager,
        blob_cache_ttl: Duration,
        blob_cache_max_bytes: usize,
    ) -> Self {
        Self {
            db,
            http_client,
            key_pool,
            config,
            redis,
            blob_cache_ttl,
            blob_cache_max_bytes,
        }
    }

    /// Resolve the SEAL credential the way `routes.rs` does: exported
    /// SessionKey > legacy delegate key > server fallback private key.
    fn credential(&self, auth: &AuthInfo) -> Result<SealCredential, AppError> {
        SealCredential::from_auth_or_fallback(auth, self.config.sui_private_key.as_deref())
            .ok_or_else(|| {
                AppError::Internal(
                    "SEAL credential required (x-seal-session, x-delegate-key, or SERVER_SUI_PRIVATE_KEY)"
                        .into(),
                )
            })
    }

    /// Reactively delete an expired blob's index row. Best-effort —
    /// errors logged, not propagated. Scoped to `owner` + `namespace` so a
    /// blob discovered via one recall can't delete another isolated row.
    async fn cleanup_expired_blob(&self, blob_id: &str, owner: &str, namespace: &str) {
        match self.db.delete_by_blob_id(blob_id, owner, namespace).await {
            Ok(rows) => {
                if rows > 0 {
                    tracing::info!(
                        "reactive cleanup: deleted {} vector entries for expired blob_id={} owner={} namespace={}",
                        rows, blob_id, owner, namespace
                    );
                }
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

    /// Try the Redis blob cache. Returns `Some(ciphertext)` on hit;
    /// `None` on miss, oversized entry (cap), or any cache error
    /// (cache is best-effort). Disabled entirely when
    /// `blob_cache_max_bytes` is zero.
    async fn cache_get(&self, blob_id: &str) -> Option<Vec<u8>> {
        if self.blob_cache_max_bytes == 0 {
            return None;
        }
        let mut redis = self.redis.clone();
        let cache_key = format!("{}{}", BLOB_CACHE_KEY_PREFIX, blob_id);
        match redis.get::<_, Option<Vec<u8>>>(&cache_key).await {
            Ok(Some(ciphertext)) => {
                match read_decision(ciphertext.len(), self.blob_cache_max_bytes) {
                    CacheReadDecision::Serve => Some(ciphertext),
                    CacheReadDecision::IgnoreOversize => {
                        // ignore entries larger than the configured cap.
                        // The entry will be evicted by TTL eventually; we don't
                        // delete it here to keep `cache_get` read-only.
                        tracing::info!(
                            "blob cache ignored for {}: {} bytes exceeds max {}",
                            blob_id,
                            ciphertext.len(),
                            self.blob_cache_max_bytes
                        );
                        None
                    }
                }
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("blob cache get failed for {}: {}", blob_id, e);
                None
            }
        }
    }

    /// Write a freshly-downloaded ciphertext into the Redis cache.
    /// No-op when `blob_cache_ttl` is zero, `blob_cache_max_bytes` is
    /// zero, or the ciphertext exceeds the size cap. Best-effort.
    async fn cache_put(&self, blob_id: &str, ciphertext: &[u8]) {
        let ttl_secs = self.blob_cache_ttl.as_secs();
        match write_decision(ciphertext.len(), self.blob_cache_max_bytes, ttl_secs) {
            CacheWriteDecision::Skip => return,
            CacheWriteDecision::SkipOversize => {
                // skip blobs above the size cap to bound Redis memory.
                tracing::info!(
                    "blob cache skip for {}: {} bytes exceeds max {}",
                    blob_id,
                    ciphertext.len(),
                    self.blob_cache_max_bytes
                );
                return;
            }
            CacheWriteDecision::Write => {}
        }
        let mut redis = self.redis.clone();
        let cache_key = format!("{}{}", BLOB_CACHE_KEY_PREFIX, blob_id);
        let result: redis::RedisResult<()> = redis
            .set_ex(&cache_key, ciphertext.to_vec(), ttl_secs)
            .await;
        if let Err(e) = result {
            tracing::warn!("blob cache set failed for {}: {}", blob_id, e);
        }
    }

    /// Fetch a blob's ciphertext: cache → Walrus (+ cache write-back).
    /// Returns `Some((ciphertext, was_cached))` — `was_cached` is `true` on
    /// a Redis hit, `false` on a cold fetch from Walrus. Returns `None` if
    /// the blob is gone (Walrus 404 → reactive cleanup) or any other
    /// download error.
    async fn fetch_ciphertext(
        &self,
        blob_id: &str,
        owner: &str,
        namespace: &str,
    ) -> Option<(Vec<u8>, bool)> {
        if let Some(ciphertext) = self.cache_get(blob_id).await {
            return Some((ciphertext, true));
        }
        let race_after = Duration::from_millis(self.config.walrus_aggregator_race_after_ms);
        let skip_consistency = self.config.walrus_skip_consistency_check;
        let result = download_ciphertext_with_retry(blob_id, || {
            walrus::download_blob_from_aggregators(
                &self.http_client,
                &self.config.walrus_aggregator_urls,
                blob_id,
                skip_consistency,
                race_after,
            )
        })
        .await;
        match result {
            Ok(ciphertext) => {
                self.cache_put(blob_id, &ciphertext).await;
                Some((ciphertext, false))
            }
            Err(AppError::BlobNotFound(msg)) => {
                tracing::warn!("Blob expired, cleaning up: {}", msg);
                self.cleanup_expired_blob(blob_id, owner, namespace).await;
                None
            }
            Err(e) => {
                tracing::warn!("Failed to download blob {}: {}", blob_id, e);
                None
            }
        }
    }
}

#[async_trait]
impl MemoryEngine for WalrusSealEngine {
    #[tracing::instrument(
        name = "engine.walrus_seal.store_blob",
        skip_all,
        fields(owner = %owner, namespace = %namespace, bytes = bytes.len())
    )]
    async fn store_blob(
        &self,
        owner: &str,
        account_id: &str,
        namespace: &str,
        bytes: &[u8],
        vector: &[f32],
        importance: f32,
        agent_public_key: Option<&str>,
    ) -> Result<MemoryRef, AppError> {
        // Pick the least-loaded Sui key slot so concurrent stores don't
        // serialise on one signer. Round-robin alone could land on a wallet
        // that is mid-upload while another sits idle; the per-wallet limit is
        // 1, so that costs the full upload of whatever is ahead.
        let key_index = self.key_pool.least_loaded_index().ok_or_else(|| {
            AppError::Internal(
                "No Sui keys configured (set SERVER_SUI_PRIVATE_KEYS or SERVER_SUI_PRIVATE_KEY)"
                    .into(),
            )
        })?;

        // Hold the slot for the duration of the upload, so a store running
        // concurrently sees this wallet as busy and picks another.
        let _wallet_slot = self.key_pool.begin_attempt(key_index);

        // Upload the prepared ciphertext to Walrus via the relay sidecar
        // (pool key pays gas). `defer_transfer = false` — the blob is
        // transferred to `owner` immediately, same as the inlined
        // `remember_manual` path.
        let upload = walrus::upload_blob(
            &self.http_client,
            &self.config.sidecar_url,
            self.config.sidecar_secret.as_deref(),
            bytes,
            self.config.walrus_storage_epochs as u64,
            owner,
            key_index,
            namespace,
            &self.config.package_id,
            agent_public_key,
            None,
            walrus::SealPersistence::V1New {
                account_id,
                registry_id: &self.config.registry_id,
                policy_package_id: &self.config.seal_policy_package_id,
            },
        )
        .await?;
        let blob_id = upload.blob_id;
        tracing::info!("engine.store_blob: walrus upload ok blob_id={}", blob_id);

        // warm the Redis blob cache with the just-uploaded ciphertext
        // so the first recall of this blob hits the cache instead of round-
        // tripping Walrus. Best-effort — skipped when the cache is disabled
        // or the blob exceeds `blob_cache_max_bytes`.
        self.cache_put(&blob_id, bytes).await;

        // Index the row. Quota accounting uses the ciphertext byte length.
        let id = uuid::Uuid::new_v4().to_string();
        let blob_size = bytes.len() as i64;
        self.db
            .insert_vector(
                &id,
                owner,
                namespace,
                &blob_id,
                vector,
                blob_size,
                importance,
                agent_public_key,
                Some(&self.config.package_id),
                upload.end_epoch,
            )
            .await?;

        Ok(MemoryRef { id, blob_id })
    }

    /// F3 (structure-review): eagerly resolve a SEAL credential so
    /// `/api/ask` can fail fast on credential misconfiguration before
    /// running recall. Returns the same error `fetch_one` / `fetch_batch`
    /// would surface when they try to decrypt — keeps behaviour
    /// equivalent to dev's pre-refactor `/api/ask`, where the credential
    /// check happened up front regardless of how many hits recall
    /// produced.
    fn require_read_credentials(&self, auth: &AuthInfo) -> Result<(), AppError> {
        self.credential(auth).map(|_| ())
    }

    #[tracing::instrument(
        name = "engine.walrus_seal.fetch_one",
        skip_all,
        fields(blob_id = %blob_id)
    )]
    async fn fetch_one(
        &self,
        owner: &str,
        namespace: &str,
        blob_id: &str,
        distance: f64,
        auth: &AuthInfo,
    ) -> Result<Option<HydratedMemory>, AppError> {
        let credential = self.credential(auth)?;

        // Step 1: cache → Walrus. (fetch_one doesn't aggregate cache stats —
        // a single blob's hit/miss isn't worth a log line; the span carries it.)
        let ciphertext = match self.fetch_ciphertext(blob_id, owner, namespace).await {
            Some((c, _was_cached)) => c,
            None => return Ok(None),
        };

        // Step 2: SEAL decrypt via sidecar.
        let plaintext_bytes = match seal::seal_decrypt(
            &self.http_client,
            &self.config.seal_sidecar_url,
            self.config.sidecar_secret.as_deref(),
            &ciphertext,
            &credential,
            &self.config.package_id,
            &self.config.seal_policy_package_id,
            &self.config.registry_id,
            &auth.account_id,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                // `seal_decrypt` (single) doesn't classify permanence the
                // way `seal_decrypt_batch` does; mirror the inlined `ask`
                // behaviour — log, drop, no cleanup on a single failure.
                tracing::warn!("SEAL decrypt failed for {}: {}", blob_id, e);
                return Ok(None);
            }
        };

        // Step 3: UTF-8.
        let text = match String::from_utf8(plaintext_bytes) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    "Invalid UTF-8 in decrypted data for blob {}: {}",
                    blob_id,
                    e
                );
                return Ok(None);
            }
        };

        Ok(Some(HydratedMemory {
            blob_id: blob_id.to_string(),
            text,
            distance,
            // Engine doesn't fetch created_at / importance; the recall
            // handler zips them on from the SearchHit.
            // See HydratedMemory docs.
            created_at: None,
            importance: None,
        }))
    }

    #[tracing::instrument(
        name = "engine.walrus_seal.fetch_batch",
        skip_all,
        fields(hits = hits.len())
    )]
    async fn fetch_batch(
        &self,
        owner: &str,
        namespace: &str,
        hits: &[(String, f64)],
        auth: &AuthInfo,
    ) -> Result<(Vec<HydratedMemory>, usize, FetchTimings), AppError> {
        if hits.is_empty() {
            return Ok((vec![], 0, FetchTimings::default()));
        }
        let credential = self.credential(auth)?;

        // Step 1: fetch all ciphertexts concurrently (cache → Walrus,
        // with cache write-back on cold hits). Blobs that 404 / error
        // drop out here (and get reactive cleanup inside `fetch_ciphertext`).
        struct Fetched {
            blob_id: String,
            distance: f64,
            ciphertext: Vec<u8>,
            was_cached: bool,
        }
        let walrus_start = std::time::Instant::now();
        let fetch_tasks = hits.iter().map(|(blob_id, distance)| {
            let blob_id = blob_id.clone();
            let distance = *distance;
            async move {
                self.fetch_ciphertext(&blob_id, owner, namespace).await.map(
                    |(ciphertext, was_cached)| Fetched {
                        blob_id,
                        distance,
                        ciphertext,
                        was_cached,
                    },
                )
            }
        });
        let fetched: Vec<Fetched> = futures::future::join_all(fetch_tasks)
            .await
            .into_iter()
            .flatten()
            .collect();
        let walrus_ms = walrus_start.elapsed().as_millis();
        let cache_hits = fetched.iter().filter(|f| f.was_cached).count();
        let cache_misses = fetched.len() - cache_hits;
        let download_drops = hits.len() - fetched.len();
        tracing::info!(
            "engine.fetch_batch: {} hits -> {} fetched ({} cached, {} cold), {} dropped (download)",
            hits.len(),
            fetched.len(),
            cache_hits,
            cache_misses,
            download_drops
        );

        // Step 2: batch-decrypt the ciphertexts in chunks.
        super::stage::enter(super::stage::RecallStage::SealDecrypt);
        let seal_start = std::time::Instant::now();
        let batch_input: Vec<(String, Vec<u8>)> = fetched
            .iter()
            .map(|f| (f.blob_id.clone(), f.ciphertext.clone()))
            .collect();
        let mut chunk_results = Vec::new();
        for chunk in batch_input.chunks(SEAL_DECRYPT_BATCH_SIZE) {
            let res = decrypt_chunk_with_retry(chunk, |items| {
                let credential = credential.clone();
                async move {
                    seal::seal_decrypt_batch(
                        &self.http_client,
                        &self.config.seal_sidecar_url,
                        self.config.sidecar_secret.as_deref(),
                        &items,
                        &credential,
                        &self.config.package_id,
                        &self.config.seal_policy_package_id,
                        &self.config.registry_id,
                        &auth.account_id,
                    )
                    .await
                }
            })
            .await;
            if let Err(ref e) = res {
                tracing::warn!(
                    "engine.fetch_batch: seal_decrypt_batch failed for {} blobs: {}",
                    chunk.len(),
                    e
                );
            }
            chunk_results.push((chunk.len(), res));
        }
        let decrypted = fold_decrypt_chunk_results(chunk_results)?;
        let seal_ms = seal_start.elapsed().as_millis();

        // Step 3: assemble results. Decrypt failures (permanent or
        // transient) are logged and dropped — never deleted. See
        // `assemble_decrypted` for why.
        let pairs: Vec<(String, f64)> = fetched
            .iter()
            .map(|f| (f.blob_id.clone(), f.distance))
            .collect();
        let (results, decrypt_drops) = assemble_decrypted(&pairs, decrypted);

        tracing::info!(
            "engine.fetch_batch: decrypted {} of {} fetched ({} dropped: {} download, {} decrypt) walrus={}ms seal={}ms",
            results.len(),
            fetched.len(),
            download_drops + decrypt_drops,
            download_drops,
            decrypt_drops,
            walrus_ms,
            seal_ms,
        );

        Ok((
            results,
            download_drops + decrypt_drops,
            FetchTimings { walrus_ms, seal_ms },
        ))
    }
}

// ============================================================
// Bounded transient retries + pure decrypt-outcome assembly
// ============================================================

fn is_retryable_walrus_download_error(err: &AppError) -> bool {
    match err {
        AppError::BlobNotFound(_) => false,
        AppError::UpstreamUnavailable(_) => true,
        AppError::Internal(msg) => {
            !msg.starts_with("Invalid Walrus blob id")
                && !msg.starts_with("Walrus download failed: no aggregator URLs configured")
                && !msg.starts_with("Invalid Walrus aggregator URL")
        }
        _ => false,
    }
}

async fn download_ciphertext_with_retry<F, Fut>(
    blob_id: &str,
    mut download: F,
) -> Result<Vec<u8>, AppError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, AppError>>,
{
    match download().await {
        Ok(bytes) => Ok(bytes),
        Err(err) if is_retryable_walrus_download_error(&err) => {
            if !super::stage::backoff_if_budget_allows(
                WALRUS_DOWNLOAD_RETRY_BACKOFF,
                RETRY_MIN_DEADLINE_HEADROOM,
            )
            .await
            {
                return Err(err);
            }
            tracing::warn!(
                blob_id = %blob_id,
                error = %err,
                "Transient Walrus download failure, retrying once within recall deadline"
            );
            download().await
        }
        Err(err) => Err(err),
    }
}

async fn decrypt_chunk_with_retry<F, Fut>(
    chunk: &[(String, Vec<u8>)],
    mut decrypt: F,
) -> Result<Vec<DecryptOutcome>, AppError>
where
    F: FnMut(Vec<(String, Vec<u8>)>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<DecryptOutcome>, AppError>>,
{
    let initial = decrypt(chunk.to_vec()).await;
    match initial {
        Err(err @ AppError::UpstreamUnavailable(_)) => {
            if !super::stage::backoff_if_budget_allows(
                SEAL_DECRYPT_RETRY_BACKOFF,
                RETRY_MIN_DEADLINE_HEADROOM,
            )
            .await
            {
                return Err(err);
            }
            tracing::warn!(
                items = chunk.len(),
                error = %err,
                "Transient SEAL decrypt-batch 503 failure, retrying chunk once within recall deadline"
            );
            decrypt(chunk.to_vec()).await
        }
        Err(err) => Err(err),
        Ok(mut outcomes) => {
            let transient_indices: Vec<usize> = outcomes
                .iter()
                .enumerate()
                .filter_map(|(idx, outcome)| match outcome {
                    DecryptOutcome::Failed {
                        permanent: false, ..
                    } => Some(idx),
                    _ => None,
                })
                .collect();
            if transient_indices.is_empty() {
                return Ok(outcomes);
            }
            if !super::stage::backoff_if_budget_allows(
                SEAL_DECRYPT_RETRY_BACKOFF,
                RETRY_MIN_DEADLINE_HEADROOM,
            )
            .await
            {
                return Ok(outcomes);
            }
            let retry_items: Vec<(String, Vec<u8>)> = transient_indices
                .iter()
                .filter_map(|&idx| chunk.get(idx).cloned())
                .collect();
            if retry_items.len() != transient_indices.len() {
                return Ok(outcomes);
            }
            tracing::warn!(
                transient_items = retry_items.len(),
                chunk_items = chunk.len(),
                "Transient per-item SEAL decrypt failure, retrying subset once within recall deadline"
            );
            if let Ok(retried) = decrypt(retry_items).await {
                for (slot_idx, retry_outcome) in transient_indices.into_iter().zip(retried) {
                    if let Some(slot) = outcomes.get_mut(slot_idx) {
                        *slot = retry_outcome;
                    }
                }
            }
            Ok(outcomes)
        }
    }
}

/// Fold per-chunk `seal_decrypt_batch` results across all chunks.
///
/// When one chunk fails with `Err(e)`, we fill `DecryptOutcome::Missing` for
/// every blob in that chunk and continue attempting remaining chunks so that
/// chunk 0 failing does not abort chunk 1+ when later chunks can still
/// succeed. If every non-empty chunk failed, returns `Err` with the last
/// error so an all-failed recall still surfaces an error instead of an empty
/// `200 OK`.
fn fold_decrypt_chunk_results(
    chunks: Vec<(usize, Result<Vec<DecryptOutcome>, AppError>)>,
) -> Result<Vec<DecryptOutcome>, AppError> {
    let total_len: usize = chunks.iter().map(|(len, _)| *len).sum();
    let mut decrypted = Vec::with_capacity(total_len);
    let mut any_chunk_succeeded = false;
    let mut last_err: Option<AppError> = None;

    for (chunk_len, res) in chunks {
        match res {
            Ok(outcomes) => {
                any_chunk_succeeded = true;
                decrypted.extend(outcomes);
            }
            Err(e) => {
                last_err = Some(e);
                decrypted.extend((0..chunk_len).map(|_| DecryptOutcome::Missing));
            }
        }
    }

    if !any_chunk_succeeded {
        if let Some(err) = last_err {
            return Err(err);
        }
    }

    Ok(decrypted)
}

/// Fold batch-decrypt outcomes into hydrated memories. Returns
/// `(results, decrypt_drops)`.
///
/// Pure — no DB handle, so index-row deletion is structurally impossible
/// from a decrypt failure. That is deliberate: the sidecar's "permanent"
/// classification keys off error strings ("Not enough shares",
/// "InvalidCiphertext", "InvalidPersonalMessageSignature") that also
/// arise from SEAL committee / authorization mismatches, so treating a
/// permanent decrypt failure as "blob gone" would silently prune valid
/// index rows (e.g. migrated memories) on a config error. Reactive
/// deletion is reserved for the Walrus 404 path in `fetch_ciphertext`,
/// where the blob is provably gone. The permanent/transient distinction
/// is kept for logging.
fn assemble_decrypted(
    fetched: &[(String, f64)],
    outcomes: Vec<DecryptOutcome>,
) -> (Vec<HydratedMemory>, usize) {
    let mut results = Vec::new();
    let mut decrypt_drops = 0usize;
    for ((blob_id, distance), outcome) in fetched.iter().zip(outcomes) {
        match outcome {
            DecryptOutcome::Ok(plaintext) => match String::from_utf8(plaintext) {
                Ok(text) => results.push(HydratedMemory {
                    blob_id: blob_id.clone(),
                    text,
                    distance: *distance,
                    // Engine doesn't fetch created_at / importance;
                    // recall handler zips them on. See HydratedMemory.
                    created_at: None,
                    importance: None,
                }),
                Err(e) => {
                    tracing::warn!(
                        "Invalid UTF-8 in decrypted data for blob {}: {}",
                        blob_id,
                        e
                    );
                    decrypt_drops += 1;
                }
            },
            DecryptOutcome::Failed { error, permanent } => {
                if permanent {
                    tracing::warn!(
                        "SEAL decrypt permanently failed for blob {} (dropped, index row kept): {}",
                        blob_id,
                        error
                    );
                } else {
                    tracing::warn!(
                        "SEAL decrypt transient failure for blob {}: {}",
                        blob_id,
                        error
                    );
                }
                decrypt_drops += 1;
            }
            DecryptOutcome::Missing => decrypt_drops += 1,
        }
    }
    (results, decrypt_drops)
}

// ============================================================
// Pure cache-policy helpers (size cap, TTL)
// ============================================================

/// What `cache_get` should do with a Redis hit, given the configured
/// size cap. Extracted so the policy is unit-testable without a Redis
/// fixture — the IO-bound branches (Redis error, miss) stay in
/// `cache_get` itself.
#[derive(Debug, PartialEq, Eq)]
enum CacheReadDecision {
    /// Entry is within the cap — serve it.
    Serve,
    /// Entry exceeds the cap — ignore (policy: don't delete,
    /// let TTL evict).
    IgnoreOversize,
}

fn read_decision(ciphertext_len: usize, max_bytes: usize) -> CacheReadDecision {
    if ciphertext_len <= max_bytes {
        CacheReadDecision::Serve
    } else {
        CacheReadDecision::IgnoreOversize
    }
}

/// What `cache_put` should do with a freshly-downloaded ciphertext,
/// given the configured TTL + size cap.
#[derive(Debug, PartialEq, Eq)]
enum CacheWriteDecision {
    /// Either TTL or max-bytes is zero — cache is disabled, no write.
    Skip,
    /// Ciphertext exceeds the size cap — skip the write.
    SkipOversize,
    /// Within policy — go ahead and write with the configured TTL.
    Write,
}

fn write_decision(ciphertext_len: usize, max_bytes: usize, ttl_secs: u64) -> CacheWriteDecision {
    if ttl_secs == 0 || max_bytes == 0 {
        CacheWriteDecision::Skip
    } else if ciphertext_len > max_bytes {
        CacheWriteDecision::SkipOversize
    } else {
        CacheWriteDecision::Write
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::{
        assemble_decrypted, decrypt_chunk_with_retry, download_ciphertext_with_retry,
        fold_decrypt_chunk_results, read_decision, write_decision, AppError, CacheReadDecision,
        CacheWriteDecision, DecryptOutcome,
    };

    // ── transient download & decrypt retries ───────────────────────

    #[tokio::test(start_paused = true)]
    async fn walrus_download_retries_transient_error_once_within_deadline() {
        let marker = super::super::stage::StageMarker::default();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let attempts = AtomicUsize::new(0);

        let res = super::super::stage::run_with_deadline(&marker, Some(deadline), async {
            download_ciphertext_with_retry("blob-1", || {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        Err(AppError::Internal(
                            "Walrus download failed across 1 aggregator(s): HTTP 503".into(),
                        ))
                    } else {
                        Ok(b"ciphertext-ok".to_vec())
                    }
                }
            })
            .await
        })
        .await
        .expect("within deadline");

        assert_eq!(res.expect("retry succeeds"), b"ciphertext-ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn walrus_download_does_not_retry_blob_not_found_or_exhausted_deadline() {
        let attempts_404 = AtomicUsize::new(0);
        let res_404 = download_ciphertext_with_retry("blob-404", || {
            attempts_404.fetch_add(1, Ordering::SeqCst);
            async { Err(AppError::BlobNotFound("blob-404".into())) }
        })
        .await;
        assert!(matches!(res_404, Err(AppError::BlobNotFound(_))));
        assert_eq!(attempts_404.load(Ordering::SeqCst), 1);

        let marker = super::super::stage::StageMarker::default();
        let tight_deadline = tokio::time::Instant::now() + Duration::from_millis(800);
        let attempts_tight = AtomicUsize::new(0);
        let res_tight =
            super::super::stage::run_with_deadline(&marker, Some(tight_deadline), async {
                download_ciphertext_with_retry("blob-tight", || {
                    attempts_tight.fetch_add(1, Ordering::SeqCst);
                    async {
                        Err(AppError::UpstreamUnavailable(
                            "aggregator timeout".to_string(),
                        ))
                    }
                })
                .await
            })
            .await
            .expect("returns immediately without exceeding tight deadline");
        assert!(res_tight.is_err());
        assert_eq!(attempts_tight.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn decrypt_chunk_retries_only_transient_failed_subset() {
        let chunk = vec![
            ("blob-ok".to_string(), vec![1]),
            ("blob-perm".to_string(), vec![2]),
            ("blob-transient".to_string(), vec![3]),
        ];
        let calls = AtomicUsize::new(0);

        let outcomes = decrypt_chunk_with_retry(&chunk, |items| {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    assert_eq!(items.len(), 3);
                    Ok(vec![
                        DecryptOutcome::Ok(b"alpha".to_vec()),
                        DecryptOutcome::Failed {
                            error: "NoAccessError".to_string(),
                            permanent: true,
                        },
                        DecryptOutcome::Failed {
                            error: "fetch_keys failed: TimeoutError".to_string(),
                            permanent: false,
                        },
                    ])
                } else {
                    assert_eq!(items.len(), 1);
                    assert_eq!(items[0].0, "blob-transient");
                    Ok(vec![DecryptOutcome::Ok(b"gamma".to_vec())])
                }
            }
        })
        .await
        .expect("chunk decrypt ok");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(matches!(&outcomes[0], DecryptOutcome::Ok(b) if b == b"alpha"));
        assert!(matches!(
            &outcomes[1],
            DecryptOutcome::Failed {
                permanent: true,
                ..
            }
        ));
        assert!(matches!(&outcomes[2], DecryptOutcome::Ok(b) if b == b"gamma"));
    }

    #[tokio::test(start_paused = true)]
    async fn decrypt_chunk_retries_upstream_503_once() {
        let chunk = vec![("blob-a".to_string(), vec![1])];
        let calls = AtomicUsize::new(0);

        let outcomes = decrypt_chunk_with_retry(&chunk, |_items| {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Err(AppError::UpstreamUnavailable(
                        "seal decrypt-batch failed: 503".to_string(),
                    ))
                } else {
                    Ok(vec![DecryptOutcome::Ok(b"recovered".to_vec())])
                }
            }
        })
        .await
        .expect("chunk recovered on retry");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(matches!(&outcomes[0], DecryptOutcome::Ok(b) if b == b"recovered"));
    }

    // ── decrypt-chunk folding & assembly ───────────────────────────

    #[test]
    fn fold_chunks_single_chunk_failure_returns_err() {
        let chunks = vec![(
            3,
            Err(AppError::UpstreamUnavailable(
                "seal decrypt-batch failed: timeout".to_string(),
            )),
        )];

        let res = fold_decrypt_chunk_results(chunks);
        assert!(res.is_err(), "single chunk failure must return Err");
    }

    #[test]
    fn fold_chunks_chunk0_fails_chunk1_succeeds_returns_partial_ok() {
        let fetched = vec![
            ("blob-0".to_string(), 0.1),
            ("blob-1".to_string(), 0.2),
            ("blob-2".to_string(), 0.3),
            ("blob-3".to_string(), 0.4),
        ];
        let chunks = vec![
            (
                2,
                Err(AppError::UpstreamUnavailable(
                    "seal decrypt-batch failed: chunk 0 timeout".to_string(),
                )),
            ),
            (
                2,
                Ok(vec![
                    DecryptOutcome::Ok(b"gamma".to_vec()),
                    DecryptOutcome::Ok(b"delta".to_vec()),
                ]),
            ),
        ];

        let outcomes = fold_decrypt_chunk_results(chunks)
            .expect("chunk 1 succeeded so fold_decrypt_chunk_results should return Ok");
        assert_eq!(outcomes.len(), 4);
        assert!(matches!(outcomes[0], DecryptOutcome::Missing));
        assert!(matches!(outcomes[1], DecryptOutcome::Missing));

        let (results, drops) = assemble_decrypted(&fetched, outcomes);
        assert_eq!(drops, 2, "chunk 0 items should be counted in decrypt_drops");
        assert_eq!(results.len(), 2, "chunk 1 items should be hydrated");
        assert_eq!(results[0].blob_id, "blob-2");
        assert_eq!(results[0].text, "gamma");
        assert_eq!(results[1].blob_id, "blob-3");
        assert_eq!(results[1].text, "delta");
    }

    #[test]
    fn fold_chunks_chunk0_succeeds_chunk1_fails_returns_partial_ok() {
        let fetched = vec![
            ("blob-0".to_string(), 0.1),
            ("blob-1".to_string(), 0.2),
            ("blob-2".to_string(), 0.3),
            ("blob-3".to_string(), 0.4),
        ];
        let chunks = vec![
            (
                2,
                Ok(vec![
                    DecryptOutcome::Ok(b"alpha".to_vec()),
                    DecryptOutcome::Ok(b"beta".to_vec()),
                ]),
            ),
            (
                2,
                Err(AppError::UpstreamUnavailable(
                    "seal decrypt-batch failed: chunk 1 timeout".to_string(),
                )),
            ),
        ];

        let outcomes = fold_decrypt_chunk_results(chunks)
            .expect("chunk 0 succeeded so fold_decrypt_chunk_results should return Ok");
        assert_eq!(outcomes.len(), 4);
        assert!(matches!(outcomes[2], DecryptOutcome::Missing));
        assert!(matches!(outcomes[3], DecryptOutcome::Missing));

        let (results, drops) = assemble_decrypted(&fetched, outcomes);
        assert_eq!(drops, 2, "chunk 1 items should be counted in decrypt_drops");
        assert_eq!(results.len(), 2, "chunk 0 items should be hydrated");
        assert_eq!(results[0].blob_id, "blob-0");
        assert_eq!(results[0].text, "alpha");
        assert_eq!(results[1].blob_id, "blob-1");
        assert_eq!(results[1].text, "beta");
    }

    #[test]
    fn fold_chunks_all_chunks_fail_returns_err() {
        let chunks = vec![
            (
                2,
                Err(AppError::UpstreamUnavailable(
                    "seal decrypt-batch failed: chunk 0 timeout".to_string(),
                )),
            ),
            (
                2,
                Err(AppError::UpstreamUnavailable(
                    "seal decrypt-batch failed: chunk 1 timeout".to_string(),
                )),
            ),
        ];

        let res = fold_decrypt_chunk_results(chunks);
        assert!(res.is_err(), "when all chunks fail, must return Err");
    }

    #[test]
    fn assemble_hydrates_ok_outcomes() {
        let fetched = vec![("blob-a".to_string(), 0.1), ("blob-b".to_string(), 0.2)];
        let outcomes = vec![
            DecryptOutcome::Ok(b"alpha".to_vec()),
            DecryptOutcome::Ok(b"beta".to_vec()),
        ];

        let (results, drops) = assemble_decrypted(&fetched, outcomes);

        assert_eq!(drops, 0);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].blob_id, "blob-a");
        assert_eq!(results[0].text, "alpha");
        assert_eq!(results[1].blob_id, "blob-b");
        assert_eq!(results[1].text, "beta");
    }

    #[test]
    fn assemble_permanent_decrypt_failure_drops_without_delete() {
        // Regression guard for the migrated-memory data-loss bug: a
        // "permanent" decrypt failure (e.g. "Not enough shares" from a
        // SEAL committee/authorization mismatch) must be dropped from
        // results exactly like a transient one — NOT treated as "blob
        // gone" and deleted. `assemble_decrypted` takes no DB handle,
        // so a delete cannot even be expressed here; this test locks in
        // that the permanent path routes through it.
        let fetched = vec![("blob-a".to_string(), 0.1), ("blob-b".to_string(), 0.2)];
        let outcomes = vec![
            DecryptOutcome::Ok(b"alpha".to_vec()),
            DecryptOutcome::Failed {
                error: "Not enough shares".to_string(),
                permanent: true,
            },
        ];

        let (results, drops) = assemble_decrypted(&fetched, outcomes);

        assert_eq!(results.len(), 1, "permanent failure must be dropped");
        assert_eq!(results[0].blob_id, "blob-a");
        assert_eq!(drops, 1);
    }

    #[test]
    fn assemble_transient_and_permanent_failures_drop_identically() {
        let fetched = vec![("blob-a".to_string(), 0.1), ("blob-b".to_string(), 0.2)];
        let outcomes = vec![
            DecryptOutcome::Failed {
                error: "timeout".to_string(),
                permanent: false,
            },
            DecryptOutcome::Failed {
                error: "InvalidCiphertext".to_string(),
                permanent: true,
            },
        ];

        let (results, drops) = assemble_decrypted(&fetched, outcomes);

        assert!(results.is_empty());
        assert_eq!(drops, 2);
    }

    #[test]
    fn assemble_missing_and_invalid_utf8_count_as_drops() {
        let fetched = vec![("blob-a".to_string(), 0.1), ("blob-b".to_string(), 0.2)];
        let outcomes = vec![
            DecryptOutcome::Missing,
            DecryptOutcome::Ok(vec![0xff, 0xfe]), // invalid UTF-8
        ];

        let (results, drops) = assemble_decrypted(&fetched, outcomes);

        assert!(results.is_empty());
        assert_eq!(drops, 2);
    }

    // ── read-side cap ──────────────────────────────────────────────

    #[test]
    fn read_decision_serves_entries_at_or_below_cap() {
        assert_eq!(
            read_decision(100, 512),
            CacheReadDecision::Serve,
            "100 bytes under 512 cap should be served"
        );
        assert_eq!(
            read_decision(512, 512),
            CacheReadDecision::Serve,
            "exactly at cap should be served (boundary)"
        );
        assert_eq!(
            read_decision(0, 512),
            CacheReadDecision::Serve,
            "empty entry under cap should be served"
        );
    }

    #[test]
    fn read_decision_ignores_oversize_entries() {
        assert_eq!(
            read_decision(513, 512),
            CacheReadDecision::IgnoreOversize,
            "one byte over cap should be ignored"
        );
        assert_eq!(
            read_decision(usize::MAX, 512),
            CacheReadDecision::IgnoreOversize,
            "wildly oversized entry should be ignored without crashing"
        );
    }

    // ── write-side cap + TTL ──────────────────────────────

    #[test]
    fn write_decision_skips_when_ttl_zero() {
        // TTL=0 disables write-back entirely.
        assert_eq!(
            write_decision(100, 512, 0),
            CacheWriteDecision::Skip,
            "TTL=0 should disable cache writes"
        );
    }

    #[test]
    fn write_decision_skips_when_max_bytes_zero() {
        // max=0 disables cache writes.
        assert_eq!(
            write_decision(100, 0, 600),
            CacheWriteDecision::Skip,
            "max_bytes=0 should disable cache writes"
        );
    }

    #[test]
    fn write_decision_skips_when_both_disabled() {
        assert_eq!(
            write_decision(100, 0, 0),
            CacheWriteDecision::Skip,
            "both TTL and max disabled should skip"
        );
    }

    #[test]
    fn write_decision_writes_within_cap() {
        assert_eq!(
            write_decision(100, 512, 600),
            CacheWriteDecision::Write,
            "in-cap ciphertext should be written"
        );
        assert_eq!(
            write_decision(512, 512, 600),
            CacheWriteDecision::Write,
            "exactly at cap should be written (boundary)"
        );
    }

    #[test]
    fn write_decision_skips_oversize() {
        assert_eq!(
            write_decision(513, 512, 600),
            CacheWriteDecision::SkipOversize,
            "one byte over cap should be skipped"
        );
        assert_eq!(
            write_decision(1024 * 1024, 512, 600),
            CacheWriteDecision::SkipOversize,
            "1 MiB ciphertext under 512 B cap should be skipped"
        );
    }

    #[test]
    fn write_decision_disabled_beats_oversize() {
        // If the cache is disabled, the oversize check never fires —
        // Skip is the right answer even when the entry would also be
        // oversize. Documents the precedence in `cache_put`.
        assert_eq!(
            write_decision(1024 * 1024, 0, 600),
            CacheWriteDecision::Skip,
            "max=0 should skip via Skip, not SkipOversize"
        );
    }
}
