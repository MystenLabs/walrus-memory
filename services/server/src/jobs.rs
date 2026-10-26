/// Wallet signing job queue.
///
/// Every operation that requires a Sui wallet signature is modelled as a
/// `WalletJob` jobs are signed by the configured server wallet pool.
/// This guarantees that:
///   - upload → metadata+transfer use the same key for a given job
///   - signing operations can run concurrently across the configured wallets
///   - jobs survive server restarts (persisted in Postgres via Apalis)
///
/// Retry policy: up to MAX_ATTEMPTS attempts with exponential back-off.
/// Failed jobs are visible in the `apalis_jobs` table.
use std::io;
use std::sync::Arc;

use apalis::prelude::*;
use apalis_sql::postgres::PostgresStorage;
use base64::Engine as _;
use redis::AsyncCommands;

use serde::{Deserialize, Serialize};

use crate::alerts::{
    WalrusGasPoolExhaustedAlert, WalrusObjectLockedAlert, WalrusPackageUpgradeDetectedAlert,
    WalrusUploadExhaustedAlert, WalrusWalletBalanceLowAlert, SIDECAR_WALRUS_DEP_VERSION,
};
use crate::storage::walrus::{
    DurableUploadAdvance, PreparedRegisterTransaction, SetMetadataBatchEntry, UploadBlobError,
    UploadExecutionIdentity, UploadJournal,
};
use crate::types::{configured_walrus_storage_epochs, AppState, BLOB_CACHE_KEY_PREFIX};

// ============================================================
// WalletJob — unified job type for all wallet-signing operations
// ============================================================

/// All operations that require a Sui private key to sign a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WalletOperation {
    /// Upload SEAL-encrypted blob to Walrus, index vector, set on-chain
    /// metadata, then transfer the Blob object to the user's wallet.
    ///
    /// This collapses the old RememberJob + MetaTransferJob into one unit
    /// that always executes with the same wallet key.
    UploadAndTransfer {
        /// SEAL-encrypted ciphertext (base64). Pre-computed in route handler.
        encrypted_b64: String,
        /// Pre-computed embedding vector (1536-dim).
        vector: Vec<f32>,
        /// per-fact importance set at extraction time. Persisted
        /// on `vector_entries.importance` after Walrus upload completes.
        /// `#[serde(default = "default_importance")]` so legacy job rows
        /// land at the neutral "standard" bucket
        /// rather than failing deserialisation.
        #[serde(default = "default_importance")]
        importance: f32,
        /// Walrus Memory owner address.
        owner: String,
        /// Namespace for isolation.
        namespace: String,
        /// Walrus Memory package ID.
        package_id: String,
        /// MemWalAccount whose current SEAL counter fences persistence.
        account_id: String,
        /// Delegate public key (used as agent_id on-chain).
        agent_public_key: Option<String>,
        /// `remember_jobs` row ID to update with status/blob_id.
        remember_job_id: Option<String>,
        /// Fences stale preparation workers after their lease is reclaimed.
        #[serde(default)]
        prepare_claim_token: Option<String>,
        /// Storage epochs for Walrus upload.
        #[serde(default = "default_epochs")]
        epochs: u32,
    },
    /// Legacy metadata+transfer operation for rows created before `/walrus/upload`
    /// started doing metadata+transfer atomically.
    SetMetadataAndTransfer {
        /// Sui object ID of the certified Walrus Blob.
        blob_object_id: String,
        /// Sui address of the Walrus Memory user.
        owner: String,
        /// Walrus Memory namespace.
        namespace: String,
        /// Walrus Memory package ID.
        package_id: Option<String>,
        /// Agent / delegate public key.
        agent_id: Option<String>,
        /// `remember_jobs` row ID to complete after transfer. Present for
        /// partial upload recovery jobs; absent for legacy transfer-only rows.
        #[serde(default)]
        remember_job_id: Option<String>,
        /// Walrus blob ID to index after transfer succeeds.
        #[serde(default)]
        blob_id: Option<String>,
        /// Pre-computed embedding vector to index after transfer succeeds.
        #[serde(default)]
        vector: Option<Vec<f32>>,
        /// Encrypted blob size to record with the vector row.
        #[serde(default)]
        blob_size_bytes: Option<i64>,
        /// per-fact importance score, indexed alongside the vector
        /// when this recovery job finalises the upload. Defaulted to
        /// `IMPORTANCE_STANDARD` so legacy rows degrade to the
        /// neutral bucket rather than failing deserialisation.
        #[serde(default = "default_importance")]
        importance: f32,
        /// Present together for v1-new recovery. All absent is explicit
        /// legacy-V1 mode for jobs created before the current upload route.
        #[serde(default)]
        encrypted_b64: Option<String>,
        #[serde(default)]
        account_id: Option<String>,
        #[serde(default)]
        policy_package_id: Option<String>,
        /// Walrus epoch the storage lease ends at, carried from
        /// the `UploadBlobError::MetadataTransferFailed` that triggered this
        /// recovery job. `#[serde(default)]` so in-flight jobs enqueued
        /// before this field existed deserialize as `None` (the prior
        /// behavior) rather than failing.
        #[serde(default)]
        end_epoch: Option<i32>,
    },
    /// Finish a partially recovered upload after metadata+transfer has already
    /// succeeded. This keeps DB/vector retries from repeating an on-chain
    /// transfer for an object that may now be owned by the user.
    FinalizeUploadedBlob {
        owner: String,
        namespace: String,
        #[serde(default)]
        remember_job_id: Option<String>,
        blob_id: String,
        vector: Vec<f32>,
        blob_size_bytes: i64,
        /// same as on `UploadAndTransfer` — persisted on the
        /// `vector_entries.importance` column. Defaulted to
        /// `IMPORTANCE_STANDARD` for backwards compatibility with in-flight
        /// recovery jobs enqueued before this field existed.
        #[serde(default = "default_importance")]
        importance: f32,
        /// Carried from the originating SetMetadataAndTransfer job so the
        /// eventual insert_vector call can persist them.
        /// `#[serde(default)]` so in-flight jobs enqueued before this field
        /// existed deserialize as None rather than failing.
        #[serde(default)]
        agent_id: Option<String>,
        #[serde(default)]
        package_id: Option<String>,
        /// Carried from the originating SetMetadataAndTransfer job so the
        /// eventual insert_vector call can persist it, the same
        /// way agent_id/package_id already are. `#[serde(default)]` so
        /// in-flight jobs enqueued before this field existed deserialize as
        /// `None` rather than failing.
        #[serde(default)]
        end_epoch: Option<i32>,
    },
}

fn default_epochs() -> u32 {
    let network = std::env::var("SUI_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
    configured_walrus_storage_epochs(&network)
}

/// serde default for `WalletOperation::UploadAndTransfer.importance`
/// so legacy job rows enqueued before this field existed degrade to the
/// neutral "standard" bucket on dequeue.
fn default_importance() -> f32 {
    crate::services::extractor::IMPORTANCE_STANDARD
}

pub(crate) async fn warm_blob_cache_after_upload(
    state: &AppState,
    blob_id: &str,
    ciphertext: &[u8],
) {
    let ttl_secs = state.blob_cache_ttl.as_secs();
    if ttl_secs == 0 || state.blob_cache_max_bytes == 0 {
        return;
    }

    if ciphertext.len() > state.blob_cache_max_bytes {
        tracing::info!(
            "blob cache warm skipped for {}: {} bytes exceeds max {}",
            blob_id,
            ciphertext.len(),
            state.blob_cache_max_bytes
        );
        return;
    }

    let cache_key = format!("{}{}", BLOB_CACHE_KEY_PREFIX, blob_id);
    let mut redis = state.redis.clone();
    let result: redis::RedisResult<()> =
        redis.set_ex(cache_key, ciphertext.to_vec(), ttl_secs).await;
    if let Err(e) = result {
        tracing::warn!("blob cache warm failed for {}: {}", blob_id, e);
    }
}

async fn update_remember_job_after_wallet_error(
    pool: &sqlx::PgPool,
    remember_job_id: Option<&str>,
    error: &WalletJobError,
    msg: &str,
    attempt_info: Option<WalletJobAttemptInfo>,
) {
    let Some(jid) = remember_job_id else {
        return;
    };

    // Aborting errors (Permanent or ObjectLockedUntilEpoch) get no further
    // retries, so the row is terminal — mark it failed rather than leaving it
    // stuck on `running` forever. Retryable errors stay `running` for the next
    // attempt — UNLESS this was already the final attempt. Exhausted retries
    // used to stay `running` with an error_msg until the 10-minute stale
    // sweeper force-failed them, so clients polling GET /api/remember/:job_id
    // reported "still uploading" for minutes after every wallet attempt had
    // already died (dev 2026-09-17 upload-slot investigation). Pass
    // `attempt_info` only from the attempt that actually failed the upload;
    // lock-contention Defer callers pass None so a loser cannot mark failed
    // while a winner is still working.
    let exhausted = attempt_info.is_some_and(|info| info.retries_exhausted(error));
    let terminal = error.aborts_retries() || exhausted;
    let status = if terminal { "failed" } else { "running" };

    // Terminal means no later attempt will ever insert the row, so the bytes
    // this job reserved at admission must go back to the owner now rather than
    // waiting out the TTL. Retryable errors keep the reservation: the next
    // attempt still intends to write those bytes, and releasing early would let
    // a concurrent burst overcommit while the retry is in flight.
    //
    // Safe to run even when a concurrent attempt already won and released:
    // release is a delete by id, so a second call is a no-op.
    if terminal {
        crate::storage::db::release_storage_reservations_with_pool(pool, &[jid.to_string()]).await;
    }

    // Guard against downgrading a row a concurrent attempt already finished.
    // Every pre-existing caller only runs while holding the per-job upload
    // lock (JobUploadLock), so it was never the current status writer's own
    // race to lose — but LockOutcome::Defer calls this specifically when it
    // does NOT hold the lock, i.e. exactly while another attempt of the same
    // job may be concurrently writing 'uploaded'/'done' via
    // persist_uploaded_state or insert_vector_and_mark_remember_done. Without
    // this guard, a loser's write landing after the winner's can clobber a
    // genuinely-succeeding row back to 'running' with a stale
    // lock-contention error_msg — status/error_msg only, blob_id/
    // blob_object_id are untouched, so no data loss, but a client polling
    // GET /api/remember/:job_id (routes/remember.rs) would see a
    // misleadingly stuck row until the unrelated staleness sweep.
    let _ = sqlx::query(
        "UPDATE remember_jobs SET status = $1, error_msg = $2, updated_at = NOW() WHERE id = $3 AND status NOT IN ('uploaded', 'done')",
    )
    .bind(status)
    .bind(msg)
    .bind(jid)
    .execute(pool)
    .await;
}

/// Record a metadata failure only while `status = 'uploaded'`, so the other
/// helper still cannot clobber a winner.
async fn record_uploaded_metadata_error(
    pool: &sqlx::PgPool,
    remember_job_id: Option<&str>,
    error: &WalletJobError,
    msg: &str,
    attempt_info: WalletJobAttemptInfo,
) {
    let Some(jid) = remember_job_id else {
        return;
    };
    let terminal = error.aborts_retries() || attempt_info.retries_exhausted(error);
    if terminal {
        // Release only if this statement is the one that failed the row.
        // A concurrent winner may already have moved it to `done`, and a
        // `running` row is the other helper's job.
        let updated = sqlx::query(
            "UPDATE remember_jobs SET status = 'failed', error_msg = $1, updated_at = NOW() WHERE id = $2 AND status = 'uploaded'",
        )
        .bind(msg)
        .bind(jid)
        .execute(pool)
        .await
        .map(|result| result.rows_affected())
        .unwrap_or(0);
        if updated > 0 {
            crate::storage::db::release_storage_reservations_with_pool(pool, &[jid.to_string()])
                .await;
        }
        return;
    }
    let _ = sqlx::query(
        "UPDATE remember_jobs SET error_msg = $1, updated_at = NOW() WHERE id = $2 AND status = 'uploaded'",
    )
    .bind(msg)
    .bind(jid)
    .execute(pool)
    .await;
}

/// Persist a failed metadata attempt, then pause before Apalis polls again.
///
/// Apalis has no retry delay of its own. Without the pause, five attempts of
/// the same dry-run land inside a couple of seconds.
async fn finish_metadata_attempt_error(
    state: &AppState,
    remember_job_id: Option<&str>,
    owner: &str,
    namespace: &str,
    wallet_index: usize,
    err: WalletJobError,
    attempt_info: WalletJobAttemptInfo,
) -> WalletJobError {
    let err = escalate_if_gas_pool_exhausted(err, attempt_info.current, attempt_info.max, 1);
    let msg = err.to_string();
    maybe_alert_walrus_gas_pool_exhausted(
        state,
        &err,
        remember_job_id,
        Some(owner),
        Some(namespace),
        wallet_index,
        &msg,
    )
    .await;
    update_remember_job_after_wallet_error(
        state.db.pool(),
        remember_job_id,
        &err,
        &msg,
        Some(attempt_info),
    )
    .await;
    record_uploaded_metadata_error(state.db.pool(), remember_job_id, &err, &msg, attempt_info)
        .await;
    tracing::error!(
        "[wallet-job:set-metadata] job_id={} {} classification={} retryable={}",
        remember_job_id.unwrap_or("-"),
        msg,
        err.kind(),
        !err.aborts_retries()
    );
    if let Some(delay) = upload_retry_backoff(&err, attempt_info) {
        tracing::info!(
            "[wallet-job:set-metadata] job_id={} backing off {:?} before attempt {}/{}",
            remember_job_id.unwrap_or("-"),
            delay,
            attempt_info.current + 1,
            attempt_info.max,
        );
        tokio::time::sleep(delay).await;
    }
    err
}

/// Refresh `updated_at` on an `uploaded` row. Does not clear `error_msg`.
///
/// The permit wait is 8 minutes and the sidecar call is up to 5. Each fits
/// in the 10-minute sweep; back to back they do not. The upload heartbeat
/// only matches `status = 'running'`.
async fn touch_uploaded_remember_job(pool: &sqlx::PgPool, remember_job_id: Option<&str>) {
    let Some(jid) = remember_job_id else {
        return;
    };
    let _ = sqlx::query(
        "UPDATE remember_jobs SET updated_at = NOW() WHERE id = $1 AND status = 'uploaded'",
    )
    .bind(jid)
    .execute(pool)
    .await;
}

/// Next metadata attempt, still pinned to the wallet that owns the blob.
#[allow(clippy::too_many_arguments)]
fn metadata_congestion_retry_job(
    wallet_index: usize,
    congestion_requeues: u32,
    blob_object_id: &str,
    owner: &str,
    namespace: &str,
    package_id: Option<&str>,
    agent_id: Option<&str>,
    remember_job_id: Option<&str>,
    blob_id: Option<&str>,
    vector: Option<&[f32]>,
    blob_size_bytes: Option<i64>,
    importance: f32,
    encrypted_b64: Option<&str>,
    account_id: Option<&str>,
    policy_package_id: Option<&str>,
    end_epoch: Option<i32>,
) -> WalletJob {
    WalletJob {
        wallet_index,
        congestion_requeues: congestion_requeues + 1,
        operation: WalletOperation::SetMetadataAndTransfer {
            blob_object_id: blob_object_id.to_string(),
            owner: owner.to_string(),
            namespace: namespace.to_string(),
            package_id: package_id.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
            remember_job_id: remember_job_id.map(str::to_string),
            blob_id: blob_id.map(str::to_string),
            vector: vector.map(|values| values.to_vec()),
            blob_size_bytes,
            importance,
            encrypted_b64: encrypted_b64.map(str::to_string),
            account_id: account_id.map(str::to_string),
            policy_package_id: policy_package_id.map(str::to_string),
            end_epoch,
        },
    }
}

/// Park metadata on the congestion budget. `None` means this attempt should
/// finish through Apalis. Does not call `update_remember_job_after_wallet_error`:
/// its terminal branch releases the reservation before the status check.
#[allow(clippy::too_many_arguments)]
async fn schedule_metadata_congestion_retry(
    state: &AppState,
    wallet_index: usize,
    congestion_requeues: u32,
    err: &WalletJobError,
    blob_object_id: &str,
    owner: &str,
    namespace: &str,
    package_id: Option<&str>,
    agent_id: Option<&str>,
    remember_job_id: Option<&str>,
    blob_id: Option<&str>,
    vector: Option<&[f32]>,
    blob_size_bytes: Option<i64>,
    importance: f32,
    encrypted_b64: Option<&str>,
    account_id: Option<&str>,
    policy_package_id: Option<&str>,
    end_epoch: Option<i32>,
) -> Option<Result<(), Error>> {
    if !matches!(err, WalletJobError::UploadSlotCongestion(_))
        || congestion_requeues >= MAX_CONGESTION_REQUEUES
    {
        return None;
    }

    let waiting = congestion_wait_message(err.message());
    // Attempt 1/5 on purpose: a congestion requeue must not look exhausted
    // and fail the uploaded row.
    record_uploaded_metadata_error(
        state.db.pool(),
        remember_job_id,
        err,
        &waiting,
        WalletJobAttemptInfo {
            current: 1,
            max: MAX_ATTEMPTS as usize,
        },
    )
    .await;
    if let Some(job_id) = remember_job_id {
        keep_upload_storage_reservation(state, job_id, owner, encrypted_b64.unwrap_or("")).await;
    }

    let delay_secs = congestion_backoff_secs(congestion_requeues);
    let run_at = chrono::Utc::now().timestamp() + delay_secs as i64;
    let retry = metadata_congestion_retry_job(
        wallet_index,
        congestion_requeues,
        blob_object_id,
        owner,
        namespace,
        package_id,
        agent_id,
        remember_job_id,
        blob_id,
        vector,
        blob_size_bytes,
        importance,
        encrypted_b64,
        account_id,
        policy_package_id,
        end_epoch,
    );
    let mut storage = wallet_job_queue(state, &retry.operation);
    match storage
        .schedule_request(wallet_job_request(retry), run_at)
        .await
    {
        Ok(_) => {
            tracing::warn!(
                "[wallet-job:set-metadata] job_id={} upload slots saturated; requeued delay={}s requeue={}/{} wallet={}",
                remember_job_id.unwrap_or("-"),
                delay_secs,
                congestion_requeues + 1,
                MAX_CONGESTION_REQUEUES,
                wallet_index,
            );
            Some(Ok(()))
        }
        Err(requeue_err) => {
            tracing::error!(
                "[wallet-job:set-metadata] job_id={} congestion requeue failed, falling back to Apalis retry: {}",
                remember_job_id.unwrap_or("-"),
                requeue_err,
            );
            Some(Err(WalletJobError::Transient(format!(
                "{}; congestion requeue failed: {}",
                err.message(),
                requeue_err
            ))
            .into_apalis_error()))
        }
    }
}

async fn mark_remember_job_failed(
    pool: &sqlx::PgPool,
    remember_job_id: Option<&str>,
    msg: &str,
) -> Result<(), sqlx::Error> {
    let Some(jid) = remember_job_id else {
        return Ok(());
    };

    let result = sqlx::query(
        "UPDATE remember_jobs SET status = 'failed', error_msg = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(msg)
    .bind(jid)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    Ok(())
}

fn remember_job_persist_failure_message(msg: &str, persist_err: &sqlx::Error) -> String {
    format!(
        "{}; failed to persist remember_jobs failed status: {}",
        msg, persist_err
    )
}

async fn classify_wallet_remember_handoff_failure(
    pool: &sqlx::PgPool,
    remember_job_id: Option<&str>,
    msg: String,
) -> WalletJobError {
    // Recovery handoff failures happen after an external side effect already
    // succeeded: a Walrus upload and sometimes an on-chain transfer. Once the
    // polling row is durably terminal, abort retries so clients see `failed`
    // instead of polling `uploaded` / `running` forever. If that terminal
    // state cannot be persisted, keep the wallet handler retryable so the row
    // is not orphaned.
    match mark_remember_job_failed(pool, remember_job_id, &msg).await {
        Ok(()) => WalletJobError::Permanent(msg),
        Err(persist_err) => {
            WalletJobError::Transient(remember_job_persist_failure_message(&msg, &persist_err))
        }
    }
}

/// A wallet job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletJob {
    /// Index into `config.sui_private_keys` used by the sidecar for signing.
    /// For `UploadAndTransfer`, this is the enqueue-time starting assignment;
    /// retries derive the next wallet from this index plus the Apalis attempt
    /// number so a job can walk distinct pool wallets without relying on the
    /// global round-robin cursor.
    pub wallet_index: usize,
    /// How many times this job has been re-enqueued because the sidecar's
    /// upload slots were saturated (`UploadSlotCongestion`). Congestion
    /// requeues are scheduled with a real minutes-scale backoff and do NOT
    /// burn the Apalis wallet-attempt budget — see
    /// `maybe_requeue_for_upload_congestion`. `serde(default)` keeps payloads
    /// already queued before this field existed deserializable.
    #[serde(default)]
    pub congestion_requeues: u32,
    pub operation: WalletOperation,
}

/// Convenience type alias
pub type WalletJobStorage = PostgresStorage<WalletJob>;

/// Upload jobs. Workers prefetch a batch from this queue and do not look up
/// again until that batch is done.
pub const WALLET_UPLOAD_QUEUE: &str = "wallet_jobs";

/// Metadata and finalize. A separate queue so a certified blob is picked up
/// while upload workers are still inside a prefetched batch.
pub const WALLET_FOLLOWUP_QUEUE: &str = "wallet_followup_jobs";

pub(crate) fn wallet_job_uses_followup_queue(operation: &WalletOperation) -> bool {
    matches!(
        operation,
        WalletOperation::SetMetadataAndTransfer { .. }
            | WalletOperation::FinalizeUploadedBlob { .. }
    )
}

pub(crate) fn wallet_job_queue(state: &AppState, operation: &WalletOperation) -> WalletJobStorage {
    if wallet_job_uses_followup_queue(operation) {
        state.wallet_followup_storage.clone()
    } else {
        state.wallet_storage.clone()
    }
}

// ============================================================
// Legacy MetaTransferJob — kept for backward-compat with existing DB rows.
// ============================================================

/// Payload stored as JSON in the `apalis_jobs` Postgres table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaTransferJob {
    /// Sui object ID of the certified Walrus Blob (0x...).
    pub blob_object_id: String,
    /// Sui address of the Walrus Memory user who should own the blob.
    pub owner: String,
    /// Walrus Memory namespace (e.g. "default").
    pub namespace: String,
    /// Walrus Memory package ID (optional — stored as on-chain attribute).
    pub package_id: Option<String>,
    /// Agent ID (optional — stored as on-chain attribute).
    pub agent_id: Option<String>,
    /// Index of the pool key that registered/certified this blob.
    /// The set-metadata + transfer transaction MUST be signed by the same key
    /// (the blob is currently owned by that key's address).
    pub key_index: usize,
}

// ============================================================
// Job handler
// ============================================================

/// Apalis calls this function for each `MetaTransferJob`.
///
/// Old payloads do not carry the account/ciphertext needed by the V1-new SEAL
/// persistence fence. They must be reconciled explicitly instead of being
/// mistaken for trusted V1 writes.
pub async fn execute_meta_transfer(
    _job: MetaTransferJob,
    _ctx: Data<Arc<AppState>>,
) -> Result<(), Error> {
    Err(WalletJobError::Permanent(
        "legacy MetaTransferJob lacks the V1-new SEAL persistence fence; reconcile it before enabling the V1-new contract".into(),
    )
    .into_apalis_error())
}

// ============================================================
// Retry constants
// ============================================================

/// Maximum number of attempts (1 initial + N-1 retries).
#[allow(dead_code)]
pub const MAX_ATTEMPTS: u32 = 5;
const WAL_BALANCE_LOW_THRESHOLD_MIST: u64 = 2_000_000_000;

/// Maximum number of congestion requeues per upload job. Each requeue is
/// scheduled with `congestion_backoff_secs` delay, so 6 requeues spread over
/// ~25 minutes — enough to outlive a sidecar upload-queue backlog (observed
/// drain time for a 120-deep queue at ~16 uploads/min is ~8 minutes). Once
/// the budget is spent, congestion errors fall back to normal Apalis attempts
/// so a never-ending saturation still terminates in a (correct) "exhausted
/// retries" alert.
const MAX_CONGESTION_REQUEUES: u32 = 6;

/// Stored on `remember_jobs.error_msg` while a congestion requeue is waiting.
/// The 10-minute stale sweep must not fail that row: the continuation is
/// already scheduled, and a false `failed` makes the client resubmit.
/// `fail_stale_remember_jobs` only sweeps this prefix after 45 minutes, which
/// is a lost-job backstop rather than a wait budget.
pub const CONGESTION_WAIT_ERROR_PREFIX: &str = "upload congestion, waiting to retry: ";

fn congestion_wait_message(msg: &str) -> String {
    format!("{CONGESTION_WAIT_ERROR_PREFIX}{msg}")
}

/// A dropped upload connection is the same journal, not a fresh upload.
/// Rotating the wallet starts a second blob while the first step is still
/// running on the sidecar. Slot-timeout congestion can still move, because
/// that request never started.
fn congestion_resume_wallet(current: usize, pool: usize, transport: bool) -> usize {
    if transport || pool == 0 {
        current
    } else {
        (current + 1) % pool
    }
}

/// How many times one worker re-posts the same journal after the connection
/// drops. The sidecar single-flights that key, so the retry waits for the
/// step already running instead of taking another slot. Past this, the job
/// parks on the congestion requeue and frees the worker.
const SAME_JOURNAL_ATTACHES: u32 = 3;

fn wallet_upload_gates(pool_len: usize) -> &'static Vec<tokio::sync::Semaphore> {
    use std::sync::OnceLock;
    static GATES: OnceLock<Vec<tokio::sync::Semaphore>> = OnceLock::new();
    GATES.get_or_init(|| {
        (0..pool_len.max(1))
            .map(|_| tokio::sync::Semaphore::new(1))
            .collect()
    })
}

/// One permit per wallet. A job for a busy key waits on that key only, so an
/// idle wallet is not stuck behind it. The wait is 8 minutes, inside the
/// 10-minute stale sweep, so the caller refreshes `updated_at` first.
///
/// Take this permit before `JobUploadLock::try_acquire`. The wait must not
/// hold a lock-pool connection.
async fn admit_wallet_upload(
    wallet_index: usize,
    pool_len: usize,
) -> Result<tokio::sync::SemaphorePermit<'static>, WalletJobError> {
    let gates = wallet_upload_gates(pool_len);
    let index = wallet_index % gates.len();
    match tokio::time::timeout(
        std::time::Duration::from_secs(8 * 60),
        gates[index].acquire(),
    )
    .await
    {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(WalletJobError::UploadSlotCongestion(format!(
            "timed out waiting for wallet {wallet_index} upload slot"
        ))),
        Err(_) => Err(WalletJobError::UploadSlotCongestion(format!(
            "timed out waiting for wallet {wallet_index} upload slot"
        ))),
    }
}

/// The storage reservation is admitted at enqueue and expires after 15
/// minutes. A congestion wait can outlive that. Refresh it so a burst cannot
/// take the bytes this job is still going to write. If the row was already
/// swept, admit it again; a rejection is logged and the upload still retries.
async fn keep_upload_storage_reservation(
    state: &AppState,
    job_id: &str,
    owner: &str,
    encrypted_b64: &str,
) {
    let ttl_secs = crate::rate_limit::STORAGE_RESERVATION_TTL.as_secs() as i64;
    let extended = sqlx::query(
        "UPDATE storage_reservations
         SET expires_at = GREATEST(expires_at, NOW() + ($2 * INTERVAL '1 second'))
         WHERE id = $1",
    )
    .bind(job_id)
    .bind(ttl_secs)
    .execute(state.db.pool())
    .await;
    match extended {
        Ok(result) if result.rows_affected() > 0 => return,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                "[wallet-job:upload] job_id={} could not extend storage reservation: {}",
                job_id,
                e
            );
            return;
        }
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encrypted_b64)
        .map(|raw| raw.len() as i64)
        .unwrap_or(encrypted_b64.len() as i64)
        .max(1);
    if let Err(e) =
        crate::rate_limit::reserve_storage_quota_one(state, owner, job_id.to_string(), bytes).await
    {
        tracing::warn!(
            "[wallet-job:upload] job_id={} storage reservation was gone and could not be renewed: {}",
            job_id,
            e
        );
    }
}

/// Backoff before re-running a congestion-requeued upload: 30s, 60s, 120s,
/// 240s, 480s, then capped at 600s. Deliberately minutes-scale — the 2-16s
/// `backoff_duration` style is useless against a backlog that takes minutes
/// to drain (the 2026-06-10 incident burned all 5 wallet attempts inside one
/// congestion window).
fn congestion_backoff_secs(requeues: u32) -> u64 {
    (30u64 << requeues.min(31)).min(600)
}

/// How long `wallet_lock_pool.begin()` may wait for a connection. A miss is
/// this process running out of its own lock pool, not a Walrus 429, so it
/// must not occupy a worker for the sqlx default of 30s.
pub(crate) const WALLET_LOCK_POOL_ACQUIRE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);

/// Scheduled delay after a lock-pool miss. The connection is free as soon as
/// an admitted upload finishes; the minutes-scale congestion ladder is not.
const LOCK_POOL_RETRY_DELAY_SECS: u64 = 1;

/// Why `JobUploadLock::try_acquire` refused to proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockDeferReason {
    /// Another attempt of this same job holds the advisory lock.
    SameJob,
    /// `wallet_lock_pool` had no free connection.
    Pool,
}

fn resume_needs_upload_slot(disposition: &UploadResume) -> bool {
    matches!(disposition, UploadResume::Upload)
}

/// Same-job contention waits out the real upload. A pool miss retries in a
/// second on the same wallet: rotating would only spread the checkout storm.
fn upload_lock_retry_delay(reason: LockDeferReason, congestion_requeues: u32) -> u64 {
    match reason {
        LockDeferReason::SameJob => congestion_backoff_secs(congestion_requeues),
        LockDeferReason::Pool => LOCK_POOL_RETRY_DELAY_SECS,
    }
}

fn upload_lock_retry_wallet(
    reason: LockDeferReason,
    wallet_index: usize,
    pool_len: usize,
) -> usize {
    match reason {
        LockDeferReason::Pool => wallet_index,
        LockDeferReason::SameJob => (wallet_index + 1) % pool_len.max(1),
    }
}

/// Exponential back-off: attempt 1→2s, 2→4s, 3→8s, 4→16s, 5→32s.
pub fn backoff_duration(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(2u64.pow(attempt))
}

/// How long a failed upload attempt should pause before Apalis re-queues it,
/// or `None` when no pause is warranted.
///
/// Apalis attaches no retry/backoff layer (see `WalletJobError`'s doc
/// comment), so a retriable error is re-polled almost immediately and the
/// whole attempt budget burns inside one upstream rate-limit window. Observed
/// in production: a single job took attempts 2, 3, 4 and 5 against Walrus
/// `503 Too Many Requests` within one second, rotating through four wallets
/// that never had a chance to land, and died as "exhausted retries" about a
/// second after its first failure. The upstream limit is time-based, so
/// rotating wallets cannot help — only waiting can.
///
/// Returns `None` for an aborting error (retrying it is pointless) and for the
/// final attempt (nothing is coming, so the sleep would only delay the
/// failure the caller is already reporting).
fn upload_retry_backoff(
    classified: &WalletJobError,
    attempt_info: WalletJobAttemptInfo,
) -> Option<std::time::Duration> {
    if classified.aborts_retries() || attempt_info.current >= attempt_info.max {
        return None;
    }
    Some(backoff_duration(attempt_info.current as u32))
}

/// Apalis runs a larger value first inside one queue. Finalize outranks
/// metadata on the followup queue. Uploads are a separate queue, so this
/// number does not stop an upload a worker has already picked up.
fn wallet_job_priority(operation: &WalletOperation) -> i32 {
    match operation {
        WalletOperation::FinalizeUploadedBlob { .. } => 2,
        WalletOperation::SetMetadataAndTransfer { .. } => 1,
        WalletOperation::UploadAndTransfer { .. } => 0,
    }
}

pub(crate) fn wallet_job_request(
    job: WalletJob,
) -> Request<WalletJob, apalis_sql::context::SqlContext> {
    let mut context = apalis_sql::context::SqlContext::new();
    context.set_max_attempts(MAX_ATTEMPTS as i32);
    context.set_priority(wallet_job_priority(&job.operation));
    Request::new_with_ctx(job, context)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WalletJobAttemptInfo {
    current: usize,
    max: usize,
}

impl WalletJobAttemptInfo {
    fn retries_exhausted(&self, error: &WalletJobError) -> bool {
        !error.aborts_retries() && self.current >= self.max
    }

    fn exhausted_by(&self, error: &WalletJobError) -> bool {
        if matches!(error, WalletJobError::WalrusBalanceLow(_)) {
            return false;
        }
        self.retries_exhausted(error)
    }
}

impl FromRequest<Request<WalletJob, apalis_sql::context::SqlContext>> for WalletJobAttemptInfo {
    fn from_request(
        req: &Request<WalletJob, apalis_sql::context::SqlContext>,
    ) -> Result<Self, Error> {
        wallet_attempt_info_from_request(req)
    }
}

impl FromRequest<Request<RememberJob, apalis_sql::context::SqlContext>> for WalletJobAttemptInfo {
    fn from_request(
        req: &Request<RememberJob, apalis_sql::context::SqlContext>,
    ) -> Result<Self, Error> {
        wallet_attempt_info_from_request(req)
    }
}

fn wallet_attempt_info_from_request<T>(
    req: &Request<T, apalis_sql::context::SqlContext>,
) -> Result<WalletJobAttemptInfo, Error> {
    let mut max =
        usize::try_from(req.parts.context.max_attempts()).unwrap_or(MAX_ATTEMPTS as usize);
    if max == 0 {
        max = MAX_ATTEMPTS as usize;
    }
    Ok(WalletJobAttemptInfo {
        current: req.parts.attempt.current(),
        max,
    })
}

/// Returns the wallet this job should use for a specific Apalis attempt. The
/// starting wallet is chosen when the job is enqueued; retries advance from that
/// start index deterministically so concurrent jobs cannot consume this job's
/// next pool candidate through the global round-robin cursor.
fn wallet_index_for_upload_attempt(
    starting_wallet_index: usize,
    attempt: usize,
    pool_size: usize,
) -> Option<usize> {
    if pool_size == 0 {
        return None;
    }
    let start = starting_wallet_index % pool_size;
    let offset = attempt.saturating_sub(1) % pool_size;
    Some(start.wrapping_add(offset) % pool_size)
}

/// Whether this journal already names the signer that owns the blob.
///
/// `encoded` is a local checkpoint, and a prepared register has not been
/// submitted. `registered` and later refer to a blob object that signer owns.
fn upload_journal_signer_committed(journal: &UploadJournal) -> bool {
    matches!(
        journal
            .resume_step
            .as_ref()
            .and_then(|step| step.get("step"))
            .and_then(serde_json::Value::as_str),
        Some("registered" | "uploaded" | "certified")
    )
}

/// Keep the journaled signer once this upload has a wallet-specific checkpoint.
///
/// A stored wallet address or a prepared register belongs to one key slot.
/// Retrying those bytes on another slot is `WALLET_MAPPING_MISMATCH`, and the
/// prepared transaction may already have been submitted. An encoded checkpoint
/// that names no signer may still move, except during a congestion resume,
/// where the in-flight attempt stays on the journaled slot.
fn pin_journal_wallet(journal: &UploadJournal, congestion_requeues: u32) -> bool {
    upload_journal_signer_committed(journal)
        || journal.wallet_address.is_some()
        || journal.register_transaction.is_some()
        || (congestion_requeues > 0 && journal.resume_step.is_some())
}

/// Move an uncommitted journal onto `free_wallet`.
///
/// Returns whether the caller must persist the journal. A prepared register
/// signed by the old wallet is dropped so the sidecar rebuilds it. The
/// journaled address is cleared so the new key is not rejected as a mapping
/// mismatch. A committed journal is left untouched.
fn steer_uncommitted_upload_wallet(journal: &mut UploadJournal, free_wallet: usize) -> bool {
    if upload_journal_signer_committed(journal) || journal.wallet_index == free_wallet {
        return false;
    }
    journal.wallet_index = free_wallet;
    journal.wallet_address = None;
    journal.register_transaction = None;
    true
}

// ============================================================
// execute_wallet_job — dispatcher for WalletJob
// ============================================================

/// Apalis worker handler for WalletJob.
///
/// Upload jobs and followup jobs are separate queues, but both call this
/// handler. Upload jobs derive the execution wallet from the enqueued starting
/// wallet and current attempt; metadata jobs keep their pinned wallet because
/// the blob object is owned by the wallet that registered it.
pub(crate) async fn execute_wallet_job(
    job: WalletJob,
    ctx: Data<Arc<AppState>>,
    attempt_info: WalletJobAttemptInfo,
) -> Result<(), Error> {
    let state: &AppState = &ctx;
    let enqueued_wallet_index = job.wallet_index;
    let congestion_requeues = job.congestion_requeues;

    let result = match job.operation {
        WalletOperation::UploadAndTransfer {
            encrypted_b64,
            vector,
            importance,
            owner,
            namespace,
            package_id,
            account_id,
            agent_public_key,
            remember_job_id,
            prepare_claim_token,
            epochs,
        } => {
            let mut wallet_index = if congestion_requeues > 0 {
                // The requeue already chose the signer. Do not walk the attempt
                // cursor; that is what pairs a cached prepare with another key.
                enqueued_wallet_index % state.key_pool.len().max(1)
            } else {
                match wallet_index_for_upload_attempt(
                    enqueued_wallet_index,
                    attempt_info.current,
                    state.key_pool.len(),
                ) {
                    Some(index) => index,
                    None => {
                        return Err(WalletJobError::Permanent(
                            "No Sui keys configured (set SERVER_SUI_PRIVATE_KEYS or SERVER_SUI_PRIVATE_KEY)"
                                .into(),
                        )
                        .into_apalis_error());
                    }
                }
            };
            // The attempt index is only the fallback. Once a durable journal
            // names a signer, the sidecar queues on that key, so the busy-count
            // has to name the same wallet or least-loaded keeps feeding the one
            // that is actually full. An encoded checkpoint with no signer can
            // still move onto a free wallet. A stored address or prepared
            // register cannot: those bytes may already be in flight.
            let mut claimed_slot = None;
            if let Some(job_id) = remember_job_id.as_deref() {
                let mut journal = load_upload_journal(state.db.pool(), job_id, wallet_index)
                    .await
                    .map_err(WalletJobError::into_apalis_error)?;
                if pin_journal_wallet(&journal, congestion_requeues) {
                    wallet_index = journal.wallet_index;
                } else if congestion_requeues > 0 {
                    // Nothing has been submitted, but a stored index would
                    // otherwise keep signing while admission follows the
                    // rotated payload. Write the payload wallet through.
                    if journal.wallet_index != wallet_index {
                        journal.wallet_index = wallet_index;
                        journal.wallet_address = None;
                        journal.register_transaction = None;
                        persist_upload_journal(state.db.pool(), job_id, &journal)
                            .await
                            .map_err(WalletJobError::into_apalis_error)?;
                    }
                } else if let Some(claim) = state.key_pool.claim_least_loaded() {
                    // Claimed before the await below, so a concurrent worker
                    // cannot pick the same idle wallet in the meantime.
                    let free = claim.index();
                    let from = journal.wallet_index;
                    if steer_uncommitted_upload_wallet(&mut journal, free) {
                        persist_upload_journal(state.db.pool(), job_id, &journal)
                            .await
                            .map_err(WalletJobError::into_apalis_error)?;
                        tracing::info!(
                                "[wallet-job:upload] job_id={} moved uncommitted upload off wallet {} onto {}",
                                job_id,
                                from,
                                journal.wallet_index,
                            );
                    }
                    wallet_index = journal.wallet_index;
                    if claim.index() == wallet_index {
                        claimed_slot = Some(claim);
                    }
                }
            }
            // Mark this wallet busy for the rest of the attempt, so a
            // concurrently-enqueued job picks an idle wallet instead of
            // queueing behind this upload. Held by guard rather than paired
            // calls because every return below — and there are many — has to
            // release it.
            let _wallet_slot = match claimed_slot {
                Some(claim) => claim,
                None => state.key_pool.begin_attempt(wallet_index),
            };

            if wallet_index != enqueued_wallet_index || attempt_info.current > 1 {
                tracing::info!(
                    "[wallet-job:upload] selected wallet for attempt: enqueued={} executing={} attempt={}/{}",
                    enqueued_wallet_index,
                    wallet_index,
                    attempt_info.current,
                    attempt_info.max,
                );
            }
            if let (Some(job_id), Some(token)) =
                (remember_job_id.as_deref(), prepare_claim_token.as_deref())
            {
                let owns_claim: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM remember_jobs WHERE id = $1 AND prepare_claim_token = $2)",
                )
                .bind(job_id)
                .bind(token)
                .fetch_one(state.db.pool())
                .await
                .map_err(|e| {
                    WalletJobError::Transient(format!(
                        "failed to verify preparation fencing token: {}",
                        e
                    ))
                    .into_apalis_error()
                })?;
                if !owns_claim {
                    tracing::warn!(
                        "[wallet-job:upload] job_id={} stale preparation payload fenced before wallet execution",
                        job_id
                    );
                    return Ok(());
                }
            }
            execute_upload_and_transfer(
                state,
                wallet_index,
                encrypted_b64,
                vector,
                importance,
                owner,
                namespace,
                package_id,
                account_id,
                agent_public_key,
                remember_job_id,
                prepare_claim_token,
                epochs,
                congestion_requeues,
                attempt_info,
            )
            .await
        }
        WalletOperation::SetMetadataAndTransfer {
            blob_object_id,
            owner,
            namespace,
            package_id,
            agent_id,
            remember_job_id,
            blob_id,
            vector,
            blob_size_bytes,
            importance,
            encrypted_b64,
            account_id,
            policy_package_id,
            end_epoch,
        } => {
            // Mark the wallet busy for least-loaded assignment. This job signs
            // on the key that owns the blob, but it must not hold the upload
            // permit. A worker that already took this key's next upload can
            // register while the metadata transaction is in flight. Priority
            // still prefers this job over an upload that has not been prefetched.
            let _wallet_slot = state.key_pool.begin_attempt(enqueued_wallet_index);

            touch_uploaded_remember_job(state.db.pool(), remember_job_id.as_deref()).await;
            let result = execute_set_metadata_and_transfer(
                state,
                enqueued_wallet_index,
                &blob_object_id,
                &owner,
                &namespace,
                package_id.as_deref(),
                agent_id.as_deref(),
                encrypted_b64.as_deref(),
                account_id.as_deref(),
                policy_package_id.as_deref(),
            )
            .await;

            match result {
                Ok(()) => match (blob_id, vector, blob_size_bytes) {
                    (Some(blob_id), Some(vector), Some(blob_size_bytes)) => {
                        if let Err(err) = insert_vector_and_mark_remember_done(
                            state,
                            remember_job_id.as_deref(),
                            &owner,
                            &namespace,
                            &blob_id,
                            &vector,
                            blob_size_bytes,
                            importance,
                            enqueued_wallet_index,
                            agent_id.as_deref(),
                            package_id.as_deref(),
                            end_epoch,
                        )
                        .await
                        {
                            let finalize_remember_job_id = remember_job_id.clone();
                            if let Err(enqueue_err) = enqueue_finalize_uploaded_blob(
                                state,
                                enqueued_wallet_index,
                                owner,
                                namespace,
                                remember_job_id,
                                blob_id,
                                vector,
                                blob_size_bytes,
                                importance,
                                agent_id.clone(),
                                package_id.clone(),
                                end_epoch,
                            )
                            .await
                            {
                                let classified = classify_wallet_remember_handoff_failure(
                                    state.db.pool(),
                                    finalize_remember_job_id.as_deref(),
                                    enqueue_err.to_string(),
                                )
                                .await;
                                tracing::error!(
                                    "[wallet-job:set-metadata] job_id={} {}",
                                    finalize_remember_job_id.as_deref().unwrap_or("-"),
                                    classified,
                                );
                                return Err(classified.into_apalis_error());
                            }
                            tracing::warn!(
                                "[wallet-job:set-metadata] finalization failed after transfer; enqueued index-only retry: {}",
                                err
                            );
                        }
                        Ok(())
                    }
                    (None, None, None) => Ok(()),
                    _ => Err(WalletJobError::Permanent(
                        "metadata transfer recovery job missing finalization fields".into(),
                    )),
                },
                Err(err) => {
                    if let Some(outcome) = schedule_metadata_congestion_retry(
                        state,
                        enqueued_wallet_index,
                        congestion_requeues,
                        &err,
                        &blob_object_id,
                        &owner,
                        &namespace,
                        package_id.as_deref(),
                        agent_id.as_deref(),
                        remember_job_id.as_deref(),
                        blob_id.as_deref(),
                        vector.as_deref(),
                        blob_size_bytes,
                        importance,
                        encrypted_b64.as_deref(),
                        account_id.as_deref(),
                        policy_package_id.as_deref(),
                        end_epoch,
                    )
                    .await
                    {
                        return outcome;
                    }
                    // Pinned to the wallet that owns the blob, so a gas-budget
                    // failure escalates immediately instead of rotating.
                    Err(finish_metadata_attempt_error(
                        state,
                        remember_job_id.as_deref(),
                        &owner,
                        &namespace,
                        enqueued_wallet_index,
                        err,
                        attempt_info,
                    )
                    .await)
                }
            }
        }
        WalletOperation::FinalizeUploadedBlob {
            owner,
            namespace,
            remember_job_id,
            blob_id,
            vector,
            blob_size_bytes,
            importance,
            agent_id,
            package_id,
            end_epoch,
        } => {
            insert_vector_and_mark_remember_done(
                state,
                remember_job_id.as_deref(),
                &owner,
                &namespace,
                &blob_id,
                &vector,
                blob_size_bytes,
                importance,
                enqueued_wallet_index,
                agent_id.as_deref(),
                package_id.as_deref(),
                end_epoch,
            )
            .await
        }
    };

    result.map_err(|err| {
        if let WalletJobError::Permanent(ref msg) = err {
            tracing::warn!(
                target: "wallet_job.permanent",
                "permanent failure for wallet_index={} (will mark Dead): {}",
                enqueued_wallet_index,
                msg
            );
        }
        err.into_apalis_error()
    })
}

// ────────────────────────────────────────────────────────────
// WalletOperation::SetMetadataAndTransfer
// ────────────────────────────────────────────────────────────

fn recovery_seal_persistence<'a>(
    account_id: Option<&'a str>,
    registry_id: &'a str,
    policy_package_id: Option<&'a str>,
    encrypted_b64: Option<&str>,
) -> Result<crate::storage::walrus::SealPersistence<'a>, WalletJobError> {
    match (account_id, policy_package_id, encrypted_b64) {
        (Some(account_id), Some(policy_package_id), Some(ciphertext))
            if !account_id.is_empty()
                && !registry_id.is_empty()
                && !policy_package_id.is_empty()
                && !ciphertext.is_empty() =>
        {
            Ok(crate::storage::walrus::SealPersistence::V1New {
                account_id,
                registry_id,
                policy_package_id,
            })
        }
        _ => Err(WalletJobError::Permanent(
            "metadata recovery lacks a complete V1-new SEAL persistence fence".into(),
        )),
    }
}
async fn execute_set_metadata_and_transfer(
    state: &AppState,
    wallet_index: usize,
    blob_object_id: &str,
    owner: &str,
    namespace: &str,
    package_id: Option<&str>,
    agent_id: Option<&str>,
    encrypted_b64: Option<&str>,
    account_id: Option<&str>,
    policy_package_id: Option<&str>,
) -> Result<(), WalletJobError> {
    let seal_persistence = recovery_seal_persistence(
        account_id,
        &state.config.registry_id,
        policy_package_id,
        encrypted_b64,
    )?;
    let set_metadata_result = crate::storage::walrus::set_metadata_batch(
        &state.http_client,
        &state.config.sidecar_url,
        state.config.sidecar_secret.as_deref(),
        wallet_index,
        owner,
        package_id.unwrap_or(&state.config.package_id),
        agent_id,
        vec![SetMetadataBatchEntry {
            blob_object_id: blob_object_id.to_string(),
            namespace: namespace.to_string(),
            encrypted_data: encrypted_b64.map(str::to_string),
        }],
        seal_persistence,
    )
    .await;

    match set_metadata_result {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            let classified = WalletJobError::classify_sidecar_error(&msg);
            maybe_alert_walrus_low_wal_balance(
                state,
                &classified,
                wallet_index,
                None,
                Some(owner),
                Some(namespace),
                &msg,
            )
            .await;
            if classified.is_permanent() {
                tracing::error!(
                    "[wallet-job:set-metadata] permanent failure (will mark Dead): {}",
                    msg
                );
            }
            Err(classified)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_vector_and_mark_remember_done(
    state: &AppState,
    remember_job_id: Option<&str>,
    owner: &str,
    namespace: &str,
    blob_id: &str,
    vector: &[f32],
    blob_size_bytes: i64,
    importance: f32,
    wallet_index: usize,
    agent_id: Option<&str>,
    package_id: Option<&str>,
    end_epoch: Option<i32>,
) -> Result<(), WalletJobError> {
    let vector_id = remember_job_id
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if let Err(e) = state
        .db
        .insert_vector(
            &vector_id,
            owner,
            namespace,
            blob_id,
            vector,
            blob_size_bytes,
            importance,
            agent_id,
            package_id,
            end_epoch,
        )
        .await
    {
        let msg = format!("insert_vector failed: {}", e);
        let classified = WalletJobError::classify_sidecar_error(&msg);
        update_remember_job_after_wallet_error(
            state.db.pool(),
            remember_job_id,
            &classified,
            &msg,
            None,
        )
        .await;
        tracing::error!(
            "[wallet-job:upload] job_id={} {} classification={} retryable={}",
            remember_job_id.unwrap_or("-"),
            msg,
            classified.kind(),
            !classified.aborts_retries()
        );
        return Err(classified);
    }

    if let Some(jid) = remember_job_id {
        let _ = sqlx::query(
            "UPDATE remember_jobs SET status = 'done', blob_id = $1, prepare_claimed_at = NULL, prepare_claim_token = NULL, recovery_claimed_at = NULL, recovery_claim_token = NULL, error_msg = NULL, updated_at = NOW() WHERE id = $2",
        )
        .bind(blob_id)
        .bind(jid)
        .execute(state.db.pool())
        .await;

        // Release only now that the vector row is committed. The row carries
        // the bytes from here on, so holding the reservation would double count
        // them; releasing before the insert would instead open a window where
        // neither counts and a concurrent burst could slip past the quota.
        crate::rate_limit::release_storage_quota_one(state, jid).await;
    }

    tracing::info!(
        "[wallet-job:upload] done job_id={} blob_id={} owner={} ns={} key={}",
        remember_job_id.unwrap_or("-"),
        blob_id,
        &owner[..10.min(owner.len())],
        namespace,
        wallet_index,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_finalize_uploaded_blob(
    state: &AppState,
    wallet_index: usize,
    owner: String,
    namespace: String,
    remember_job_id: Option<String>,
    blob_id: String,
    vector: Vec<f32>,
    blob_size_bytes: i64,
    importance: f32,
    agent_id: Option<String>,
    package_id: Option<String>,
    end_epoch: Option<i32>,
) -> Result<(), WalletJobError> {
    let job = WalletJob {
        wallet_index,
        congestion_requeues: 0,
        operation: WalletOperation::FinalizeUploadedBlob {
            owner,
            namespace,
            remember_job_id,
            blob_id,
            vector,
            blob_size_bytes,
            importance,
            agent_id,
            package_id,
            end_epoch,
        },
    };
    let mut storage = wallet_job_queue(state, &job.operation);
    storage
        .push_request(wallet_job_request(job))
        .await
        .map_err(|e| {
            WalletJobError::Transient(format!(
                "failed to enqueue uploaded-blob finalization job: {}",
                e
            ))
        })
        .map(|_| ())
}

// ────────────────────────────────────────────────────────────
// WalletOperation::UploadAndTransfer
// ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
/// What `execute_upload_and_transfer` should do given a job's already-persisted
/// state — the idempotency decision, split out so it can be unit-tested against
/// the real `remember_jobs` table without a live Walrus sidecar.
#[derive(Debug, PartialEq, Eq)]
enum UploadResume {
    /// Job already reached its terminal `done` state — nothing to redo.
    AlreadyDone { blob_id: String },
    /// Paid blob already minted AND its object id is known, but metadata/transfer
    /// (and indexing) may not have finished. Resume via the metadata/transfer
    /// recovery path with the stored object id — never re-mint, never prematurely
    /// finalize an un-transferred blob.
    ResumeTransfer {
        blob_id: String,
        blob_object_id: String,
    },
    /// Paid blob already minted but no object id was recorded (a full-success
    /// upload where the sidecar already did metadata+transfer atomically, or a
    /// pre-`blob_object_id` legacy row). The blob exists and is transferred, only
    /// the vector index may be missing — resume indexing, NEVER re-upload.
    ResumeIndex { blob_id: String },
    /// No paid blob is recorded in the durable job row. Proceed with a normal
    /// upload; the per-job advisory lock prevents concurrent attempts.
    Upload,
    /// The status lookup itself failed. We CANNOT tell whether a paid blob exists,
    /// so we must not upload (fail closed) — the caller returns a retriable error
    /// and Apalis re-reads on the next attempt.
    Indeterminate,
}

/// Decide whether a (possibly retried) upload job should re-upload or resume.
///
/// A row **never re-uploads once a paid blob is recorded** (any non-NULL
/// `blob_id`): `done` → `AlreadyDone`; `uploaded` + object_id → `ResumeTransfer`;
/// `uploaded` without object_id → `ResumeIndex` (the blob is minted+transferred,
/// only indexing may be pending). Any row with a NULL `blob_id` → `Upload`: the
/// database is the source of truth, and the per-job advisory lock prevents two
/// live attempts from entering the paid upload concurrently.
///
/// A lookup **error** returns `Indeterminate` (fail closed): after a possible
/// mint we must not re-upload on a transient read failure, so the caller retries
/// without uploading rather than risking a duplicate paid blob.
async fn upload_resume_disposition(pool: &sqlx::PgPool, job_id: &str) -> UploadResume {
    let looked_up: Result<Option<(String, Option<String>, Option<String>)>, sqlx::Error> =
        sqlx::query_as("SELECT status, blob_id, blob_object_id FROM remember_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_optional(pool)
            .await;

    let existing = match looked_up {
        Ok(row) => row,
        Err(_) => return UploadResume::Indeterminate,
    };

    match existing {
        // Any recorded blob_id means the paid mint already happened → never upload.
        Some((status, Some(blob_id), _)) if status == "done" => {
            UploadResume::AlreadyDone { blob_id }
        }
        Some((_, Some(blob_id), Some(blob_object_id))) => UploadResume::ResumeTransfer {
            blob_id,
            blob_object_id,
        },
        Some((_, Some(blob_id), None)) => UploadResume::ResumeIndex { blob_id },
        // No durable blob record means there is nothing to resume. Trust the DB;
        // scanning every historical server-wallet Blob is both redundant and too
        // slow for the sidecar read deadline.
        _ => UploadResume::Upload,
    }
}

/// Per-job upload mutex, held for the guard-read → mint → persist critical
/// section of `execute_upload_and_transfer`. Backed by a transaction-level
/// Postgres advisory lock (`pg_try_advisory_xact_lock` — non-blocking) on a hash
/// of the job id, taken on a dedicated connection from `wallet_lock_pool`. If
/// another attempt of the SAME job already holds it, acquisition returns `None`
/// and the caller must NOT upload. Different jobs never contend.
///
/// The caller holds the wallet upload permit before this checkout. Waiting for
/// that permit with a connection already open pins one pool slot per prefetched
/// job, and the jobs that lose the checkout were then parked on the relay backoff.
///
/// A transaction lock is cancellation-safe: SQLx queues a rollback when a
/// dropped transaction returns its connection to the pool, and PostgreSQL
/// releases the advisory lock with that transaction. A session advisory lock
/// can survive cancellation and leak into an unrelated pooled borrower.
struct JobUploadLock {
    transaction: sqlx::Transaction<'static, sqlx::Postgres>,
}

impl JobUploadLock {
    /// Try to acquire the per-job lock. `Ok(Some(lock))` = acquired (proceed);
    /// `Ok(None)` = another attempt of this job holds it (do not upload);
    /// `Err` = could not reach the lock pool (fail closed — treat like held).
    async fn try_acquire(pool: &sqlx::PgPool, job_id: &str) -> Result<Option<Self>, sqlx::Error> {
        let mut transaction = pool.begin().await?;
        // hashtext() → int4; advisory locks take int8. Deterministic per job id.
        let acquired: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
                .bind(job_id)
                .fetch_one(&mut *transaction)
                .await?;
        if acquired {
            Ok(Some(JobUploadLock { transaction }))
        } else {
            Ok(None)
        }
    }

    /// Commit the lock-only transaction on the normal path. Cancellation drops
    /// it instead, and SQLx rolls it back before the connection is reused.
    async fn release(self, _job_id: &str) {
        let _ = self.transaction.commit().await;
    }
}

/// Decision derived from a `JobUploadLock::try_acquire` result: either we hold
/// the lock and may proceed, or we must NOT upload (deferred because another
/// attempt holds it, or fail-closed because the lock pool was unreachable — both
/// return a retriable error). Split out so the "never mint without the lock"
/// rule is unit-testable without a live pool.
enum LockOutcome {
    Proceed(JobUploadLock),
    Defer {
        error: WalletJobError,
        reason: LockDeferReason,
    },
}

fn lock_outcome(acquired: Result<Option<JobUploadLock>, sqlx::Error>, job_id: &str) -> LockOutcome {
    match acquired {
        Ok(Some(lock)) => LockOutcome::Proceed(lock),
        Ok(None) => LockOutcome::Defer {
            error: WalletJobError::Transient(format!(
                "another attempt of upload job {} is in progress",
                job_id
            )),
            reason: LockDeferReason::SameJob,
        },
        Err(e) => LockOutcome::Defer {
            error: WalletJobError::Transient(format!(
                "could not acquire upload lock for job {}: {}",
                job_id, e
            )),
            reason: LockDeferReason::Pool,
        },
    }
}

/// Durably persist the `uploaded` state (status + blob_id + blob_object_id) that
/// records a completed paid mint. Unlike the surrounding best-effort status
/// writes, a failure here is returned as a **retriable** error: the mint already
/// happened and is irreversible, so if we can't record it we must let Apalis
/// retry (the idempotency guard will then see the state on the next attempt)
/// rather than press on and risk the record being lost — which would let a later
/// retry re-mint. `blob_object_id` is stored so a retry can resume transfer.
#[derive(sqlx::FromRow)]
struct StoredUploadJournal {
    upload_wallet_index: Option<i32>,
    upload_wallet_address: Option<String>,
    upload_execution_identity: Option<serde_json::Value>,
    upload_resume_step: Option<serde_json::Value>,
    upload_register_transaction: Option<serde_json::Value>,
}

fn parse_journal_value<T: serde::de::DeserializeOwned>(
    value: Option<serde_json::Value>,
) -> Result<Option<T>, WalletJobError> {
    value
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| WalletJobError::Permanent(format!("invalid persisted upload journal: {}", e)))
}

async fn load_upload_journal(
    pool: &sqlx::PgPool,
    job_id: &str,
    fallback_wallet_index: usize,
) -> Result<UploadJournal, WalletJobError> {
    let stored = sqlx::query_as::<_, StoredUploadJournal>(
        "SELECT upload_wallet_index, upload_wallet_address, upload_execution_identity, upload_resume_step, upload_register_transaction FROM remember_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .map_err(|e| WalletJobError::Transient(format!("failed to load upload journal: {}", e)))?;

    Ok(UploadJournal {
        wallet_index: stored
            .upload_wallet_index
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(fallback_wallet_index),
        wallet_address: stored.upload_wallet_address,
        execution_identity: parse_journal_value(stored.upload_execution_identity)?,
        resume_step: stored.upload_resume_step,
        register_transaction: parse_journal_value(stored.upload_register_transaction)?,
    })
}

async fn persist_upload_journal(
    pool: &sqlx::PgPool,
    job_id: &str,
    journal: &UploadJournal,
) -> Result<(), WalletJobError> {
    let wallet_index = i32::try_from(journal.wallet_index)
        .map_err(|_| WalletJobError::Permanent("wallet index exceeds i32".into()))?;
    let identity = journal
        .execution_identity
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| {
            WalletJobError::Permanent(format!("failed to encode upload identity: {}", e))
        })?;
    let register = journal
        .register_transaction
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| {
            WalletJobError::Permanent(format!("failed to encode register journal: {}", e))
        })?;
    sqlx::query(
        "UPDATE remember_jobs SET upload_wallet_index = $1, upload_wallet_address = $2, upload_execution_identity = $3, upload_resume_step = $4, upload_register_transaction = $5, updated_at = NOW() WHERE id = $6",
    )
    .bind(wallet_index)
    .bind(&journal.wallet_address)
    .bind(identity)
    .bind(&journal.resume_step)
    .bind(register)
    .bind(job_id)
    .execute(pool)
    .await
    .map_err(|e| WalletJobError::Transient(format!("failed to persist upload journal: {}", e)))?;
    Ok(())
}

async fn consume_preparation_claim(
    pool: &sqlx::PgPool,
    job_id: &str,
    token: &str,
) -> Result<bool, WalletJobError> {
    let consumed = sqlx::query(
        "UPDATE remember_jobs SET status = 'running', prepare_claimed_at = NULL, updated_at = NOW() WHERE id = $1 AND prepare_claim_token = $2 AND blob_id IS NULL AND status IN ('pending', 'running')",
    )
    .bind(job_id)
    .bind(token)
    .execute(pool)
    .await
    .map_err(|e| WalletJobError::Transient(format!("failed to consume preparation claim: {}", e)))?;
    Ok(consumed.rows_affected() == 1)
}

async fn persist_uploaded_state(
    pool: &sqlx::PgPool,
    remember_job_id: &str,
    blob_id: &str,
    blob_object_id: Option<&str>,
) -> Result<(), WalletJobError> {
    sqlx::query(
        "UPDATE remember_jobs SET status = 'uploaded', blob_id = $1, blob_object_id = $2, prepare_claimed_at = NULL, prepare_claim_token = NULL, error_msg = NULL, updated_at = NOW() WHERE id = $3",
    )
    .bind(blob_id)
    .bind(blob_object_id)
    .bind(remember_job_id)
    .execute(pool)
    .await
    .map_err(|e| {
        WalletJobError::Transient(format!(
            "failed to persist uploaded state for job {} (blob minted, must retry to record): {}",
            remember_job_id, e
        ))
    })?;
    Ok(())
}

/// Resume an `uploaded`-but-not-`done` job by re-enqueuing the metadata/transfer
/// Build the `SetMetadataAndTransfer` job that resumes an `uploaded`-but-pending
/// write. Pure (no I/O) so a test can assert the resume routes to the transfer
/// recovery op — carrying the stored blob object id — rather than an index/`done`
/// finalize, which would prematurely complete an un-transferred blob.
#[allow(clippy::too_many_arguments)]
fn build_resume_transfer_job(
    wallet_index: usize,
    remember_job_id: &str,
    blob_id: &str,
    blob_object_id: String,
    owner: &str,
    namespace: &str,
    package_id: &str,
    account_id: &str,
    agent_public_key: Option<&str>,
    encrypted_b64: &str,
    vector: &[f32],
    blob_size_bytes: i64,
    importance: f32,
    seal_policy_package_id: &str,
) -> WalletJob {
    WalletJob {
        wallet_index,
        congestion_requeues: 0,
        operation: WalletOperation::SetMetadataAndTransfer {
            blob_object_id,
            owner: owner.to_string(),
            namespace: namespace.to_string(),
            package_id: Some(package_id.to_string()),
            agent_id: agent_public_key.map(str::to_string),
            remember_job_id: Some(remember_job_id.to_string()),
            blob_id: Some(blob_id.to_string()),
            vector: Some(vector.to_vec()),
            blob_size_bytes: Some(blob_size_bytes),
            importance,
            encrypted_b64: Some(encrypted_b64.to_string()),
            account_id: Some(account_id.to_string()),
            policy_package_id: Some(seal_policy_package_id.to_string()),
            // Resuming after a restart from persisted `remember_jobs` state,
            // which doesn't carry end_epoch — the periodic expiry
            // re-verification sweep backfills it on its next pass, same as
            // any other row that starts out with an unknown expiry.
            end_epoch: None,
        },
    }
}

/// recovery job with the stored blob object id — the same handoff the
/// upload-then-metadata-failed path uses. This never re-mints the (already paid)
/// blob and never marks the row `done` while its transfer is still outstanding;
/// `SetMetadataAndTransfer` finishes the transfer and only then indexes + marks
/// `done`.
#[allow(clippy::too_many_arguments)]
async fn resume_metadata_and_transfer(
    state: &AppState,
    wallet_index: usize,
    remember_job_id: &str,
    blob_id: &str,
    blob_object_id: String,
    owner: &str,
    namespace: &str,
    package_id: &str,
    account_id: &str,
    agent_public_key: Option<&str>,
    encrypted_b64: &str,
    vector: &[f32],
    blob_size_bytes: i64,
    importance: f32,
) -> Result<(), WalletJobError> {
    let job = build_resume_transfer_job(
        wallet_index,
        remember_job_id,
        blob_id,
        blob_object_id,
        owner,
        namespace,
        package_id,
        account_id,
        agent_public_key,
        encrypted_b64,
        vector,
        blob_size_bytes,
        importance,
        &state.config.seal_policy_package_id,
    );
    let mut storage = wallet_job_queue(state, &job.operation);
    if let Err(e) = storage.push_request(wallet_job_request(job)).await {
        let classified = classify_wallet_remember_handoff_failure(
            state.db.pool(),
            Some(remember_job_id),
            format!("failed to enqueue metadata/transfer recovery job: {}", e),
        )
        .await;
        tracing::error!(
            "[wallet-job:upload] job_id={} {}",
            remember_job_id,
            classified,
        );
        return Err(classified);
    }
    tracing::info!(
        "[wallet-job:upload] job_id={} resume enqueued metadata/transfer for blob_id={} key={}",
        remember_job_id,
        blob_id,
        wallet_index,
    );
    Ok(())
}

fn durable_step_field(step: &serde_json::Value, field: &str) -> Result<String, WalletJobError> {
    step.get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            WalletJobError::Permanent(format!(
                "durable upload step is missing required field {}",
                field
            ))
        })
}

/// Five happy-path boundaries (encode, prepare, register, upload, certify),
/// plus one spare. Each proven reset gets room for its failed boundary and
/// replacement preparation, with at most two rebuilds per wallet attempt.
struct DurableUploadBudget {
    remaining_steps: u32,
    rebuilds: u32,
    last_reset: Option<String>,
}

impl DurableUploadBudget {
    fn new() -> Self {
        Self {
            remaining_steps: 6,
            rebuilds: 0,
            last_reset: None,
        }
    }

    fn take_step(&mut self) -> bool {
        if self.remaining_steps == 0 {
            return false;
        }
        self.remaining_steps -= 1;
        true
    }

    fn rebuild(&mut self, reason: String) -> bool {
        self.last_reset = Some(reason);
        if self.rebuilds == 2 {
            return false;
        }
        self.rebuilds += 1;
        self.remaining_steps += 2;
        true
    }

    fn exhausted(&self, job_id: &str) -> WalletJobError {
        WalletJobError::Transient(format!(
            "durable upload for job {} exceeded step budget after {} rebuild(s){}",
            job_id,
            self.rebuilds,
            self.last_reset
                .as_ref()
                .map(|reason| format!("; last reset: {}", reason))
                .unwrap_or_default(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_durable_upload(
    state: &AppState,
    fallback_wallet_index: usize,
    encrypted: &[u8],
    encrypted_b64: &str,
    vector: &[f32],
    importance: f32,
    owner: &str,
    namespace: &str,
    package_id: &str,
    account_id: &str,
    agent_public_key: Option<&str>,
    remember_job_id: &str,
    epochs: u32,
) -> Result<(), WalletJobError> {
    let mut journal =
        load_upload_journal(state.db.pool(), remember_job_id, fallback_wallet_index).await?;
    // `prepare_admitted_upload` already holds this wallet's only permit.
    // Taking it again deadlocks the semaphore. A different journal signer
    // would upload on a key that was never admitted.
    if journal.wallet_index != fallback_wallet_index {
        return Err(WalletJobError::Transient(format!(
            "upload permit is for wallet {fallback_wallet_index} but the journal signer is {}",
            journal.wallet_index
        )));
    }

    // Each sidecar call advances one checkpointable step. Persist the returned
    // checkpoint before asking the sidecar to perform the next side effect.
    let mut budget = DurableUploadBudget::new();
    while budget.take_step() {
        let mut attaches = 0u32;
        let advanced = loop {
            let _ = sqlx::query(
                "UPDATE remember_jobs SET updated_at = NOW() WHERE id = $1 AND status = 'running'",
            )
            .bind(remember_job_id)
            .execute(state.db.pool())
            .await;
            match crate::storage::walrus::advance_durable_upload(
                &state.http_client,
                &state.config.sidecar_url,
                state.config.sidecar_secret.as_deref(),
                encrypted,
                epochs as u64,
                owner,
                namespace,
                package_id,
                remember_job_id,
                journal.clone(),
            )
            .await
            .map_err(|e| WalletJobError::classify_sidecar_error(&e.to_string()))
            {
                Ok(advanced) => break advanced,
                Err(err)
                    if attaches < SAME_JOURNAL_ATTACHES
                        && matches!(
                            &err,
                            WalletJobError::UploadSlotCongestion(msg)
                                if WalletJobError::is_sidecar_upload_transport_error(msg)
                        ) =>
                {
                    attaches += 1;
                    tracing::info!(
                        "[wallet-job:upload] job_id={} dropped upload connection; reattaching same journal ({}/{})",
                        remember_job_id,
                        attaches,
                        SAME_JOURNAL_ATTACHES,
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(err) => return Err(err),
            }
        };

        match advanced {
            DurableUploadAdvance::Reset {
                journal: next,
                reason,
            } => {
                // Save the cleared journal even at the rebuild limit, so the
                // next wallet attempt cannot replay the rejected transaction.
                persist_upload_journal(state.db.pool(), remember_job_id, &next).await?;
                journal = next;
                tracing::warn!(
                    "[wallet-job:upload] job_id={} resetting durable upload: {}",
                    remember_job_id,
                    reason,
                );
                if !budget.rebuild(reason) {
                    return Err(budget.exhausted(remember_job_id));
                }
            }
            DurableUploadAdvance::Prepared(next) => {
                // This is the critical pre-submit barrier: exact signed bytes
                // and digest are durable before the next request can submit.
                persist_upload_journal(state.db.pool(), remember_job_id, &next).await?;
                journal = next;
            }
            DurableUploadAdvance::Step {
                journal: mut next,
                step,
            } => {
                next.resume_step = Some(step.clone());
                persist_upload_journal(state.db.pool(), remember_job_id, &next).await?;
                let kind = step
                    .get("step")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if kind != "certified" {
                    journal = next;
                    continue;
                }

                let blob_id = durable_step_field(&step, "blobId")?;
                let object_id = durable_step_field(&step, "blobObjectId")?;
                persist_uploaded_state(
                    state.db.pool(),
                    remember_job_id,
                    &blob_id,
                    Some(&object_id),
                )
                .await?;
                warm_blob_cache_after_upload(state, &blob_id, encrypted).await;
                return resume_metadata_and_transfer(
                    state,
                    next.wallet_index,
                    remember_job_id,
                    &blob_id,
                    object_id,
                    owner,
                    namespace,
                    package_id,
                    account_id,
                    agent_public_key,
                    encrypted_b64,
                    vector,
                    encrypted.len() as i64,
                    importance,
                )
                .await;
            }
        }
    }

    Err(budget.exhausted(remember_job_id))
}

enum PreparedUpload {
    Ready {
        lock: Option<JobUploadLock>,
        /// Held until the upload returns. Resume paths leave this empty so
        /// metadata does not block the next blob on this key.
        admission: Option<tokio::sync::SemaphorePermit<'static>>,
        wallet_index: usize,
    },
    Deferred {
        error: WalletJobError,
        reason: LockDeferReason,
        wallet_index: usize,
    },
}

/// Wait for the wallet permit before checking out a lock-pool connection.
///
/// Prefetch runs many upload jobs at once. If each one opens a transaction
/// and then waits for the one-per-wallet semaphore, the lock pool runs out
/// and the losers are requeued for half a minute or more. Jobs that only
/// need to resume metadata never take the permit.
async fn prepare_admitted_upload(
    db_pool: &sqlx::PgPool,
    lock_pool: &sqlx::PgPool,
    pool_len: usize,
    mut wallet_index: usize,
    remember_job_id: Option<&str>,
) -> Result<PreparedUpload, WalletJobError> {
    let mut admission = None;
    let mut upload_lock = None;
    for pass in 0..3 {
        let needs_slot = match remember_job_id {
            Some(jid) => resume_needs_upload_slot(&upload_resume_disposition(db_pool, jid).await),
            None => false,
        };
        if needs_slot && admission.is_none() {
            if let Some(jid) = remember_job_id {
                let _ = sqlx::query(
                    "UPDATE remember_jobs SET updated_at = NOW() WHERE id = $1 AND status IN ('pending', 'running')",
                )
                .bind(jid)
                .execute(db_pool)
                .await;
            }
            admission = Some(admit_wallet_upload(wallet_index, pool_len).await?);
        } else if !needs_slot {
            drop(admission.take());
        }

        let Some(jid) = remember_job_id else {
            return Ok(PreparedUpload::Ready {
                lock: None,
                admission,
                wallet_index,
            });
        };

        if upload_lock.is_none() {
            match lock_outcome(JobUploadLock::try_acquire(lock_pool, jid).await, jid) {
                LockOutcome::Proceed(lock) => upload_lock = Some(lock),
                LockOutcome::Defer { error, reason } => {
                    drop(admission.take());
                    return Ok(PreparedUpload::Deferred {
                        error,
                        reason,
                        wallet_index,
                    });
                }
            }
        }

        if resume_needs_upload_slot(&upload_resume_disposition(db_pool, jid).await) {
            let journal = match load_upload_journal(db_pool, jid, wallet_index).await {
                Ok(journal) => journal,
                Err(err) => {
                    if let Some(lock) = upload_lock.take() {
                        lock.release(jid).await;
                    }
                    return Err(err);
                }
            };
            if journal.wallet_index != wallet_index || admission.is_none() {
                if journal.wallet_index != wallet_index {
                    tracing::info!(
                        "[wallet-job:upload] job_id={} upload permit was for wallet {} but the journal signer is {}; waiting on the signer",
                        jid,
                        wallet_index,
                        journal.wallet_index,
                    );
                }
                if let Some(lock) = upload_lock.take() {
                    lock.release(jid).await;
                }
                drop(admission.take());
                wallet_index = journal.wallet_index;
                if pass == 2 {
                    return Err(WalletJobError::Transient(format!(
                        "upload signer for job {jid} changed while waiting for a wallet slot"
                    )));
                }
                continue;
            }
        } else {
            drop(admission.take());
        }

        return Ok(PreparedUpload::Ready {
            lock: upload_lock,
            admission,
            wallet_index,
        });
    }
    Err(WalletJobError::Transient(
        "upload admission did not settle".into(),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn execute_upload_and_transfer(
    state: &AppState,
    wallet_index: usize,
    encrypted_b64: String,
    vector: Vec<f32>,
    importance: f32,
    owner: String,
    namespace: String,
    package_id: String,
    account_id: String,
    agent_public_key: Option<String>,
    remember_job_id: Option<String>,
    prepare_claim_token: Option<String>,
    epochs: u32,
    congestion_requeues: u32,
    attempt_info: WalletJobAttemptInfo,
) -> Result<(), WalletJobError> {
    // Guard-read + mint + persist must be atomic per job: Apalis can run two
    // attempts of the same job, and both would mint. The permit is taken
    // before the lock connection so waiters do not exhaust wallet_lock_pool.
    let prepared = match prepare_admitted_upload(
        state.db.pool(),
        &state.wallet_lock_pool,
        state.key_pool.len(),
        wallet_index,
        remember_job_id.as_deref(),
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            // Admission failed before any paid side effect. Do not leave a
            // spent queue attempt reported as running until the stale sweep.
            update_remember_job_after_wallet_error(
                state.db.pool(),
                remember_job_id.as_deref(),
                &error,
                error.message(),
                Some(attempt_info),
            )
            .await;
            if let Some(delay) = upload_retry_backoff(&error, attempt_info) {
                tokio::time::sleep(delay).await;
            }
            return Err(error);
        }
    };
    let (mut upload_lock, admission, wallet_index) = match prepared {
        PreparedUpload::Deferred {
            error,
            reason,
            wallet_index,
        } => {
            // No WorkerBuilder retry layer is attached, so a bare Err is
            // re-polled immediately and burns the 5 upload attempts while the
            // other attempt is still minting. Re-enqueue with the attempt
            // budget intact. A pool miss is not that wait: it retries in a
            // second on the same wallet.
            let Some(jid) = remember_job_id.clone() else {
                return Err(error);
            };
            tracing::warn!(
                "[wallet-job:upload] job_id={} deferring upload (attempt {}/{}): {}",
                jid,
                attempt_info.current,
                attempt_info.max,
                error,
            );
            update_remember_job_after_wallet_error(
                state.db.pool(),
                Some(jid.as_str()),
                &error,
                error.message(),
                None,
            )
            .await;

            if congestion_requeues < MAX_CONGESTION_REQUEUES {
                let delay_secs = upload_lock_retry_delay(reason, congestion_requeues);
                let run_at = chrono::Utc::now().timestamp() + delay_secs as i64;
                let next_wallet =
                    upload_lock_retry_wallet(reason, wallet_index, state.key_pool.len());
                let why = match reason {
                    LockDeferReason::SameJob => "held by another attempt",
                    LockDeferReason::Pool => "pool exhausted",
                };
                update_remember_job_after_wallet_error(
                    state.db.pool(),
                    Some(jid.as_str()),
                    &error,
                    &congestion_wait_message(error.message()),
                    None,
                )
                .await;
                keep_upload_storage_reservation(state, &jid, &owner, &encrypted_b64).await;
                let mut storage = state.wallet_storage.clone();
                match storage
                    .schedule_request(
                        wallet_job_request(WalletJob {
                            wallet_index: next_wallet,
                            congestion_requeues: congestion_requeues + 1,
                            operation: WalletOperation::UploadAndTransfer {
                                encrypted_b64,
                                vector,
                                importance,
                                owner,
                                namespace,
                                package_id,
                                account_id,
                                agent_public_key,
                                remember_job_id,
                                prepare_claim_token,
                                epochs,
                            },
                        }),
                        run_at,
                    )
                    .await
                {
                    Ok(_) => {
                        tracing::warn!(
                            "[wallet-job:upload] job_id={} upload lock {}; requeued delay={}s requeue={}/{} next_wallet={}",
                            jid,
                            why,
                            delay_secs,
                            congestion_requeues + 1,
                            MAX_CONGESTION_REQUEUES,
                            next_wallet,
                        );
                        return Ok(());
                    }
                    Err(requeue_err) => {
                        tracing::error!(
                            "[wallet-job:upload] job_id={} upload lock requeue failed, falling back to Apalis retry: {}",
                            jid,
                            requeue_err,
                        );
                    }
                }
            }

            tokio::time::sleep(backoff_duration(attempt_info.current as u32)).await;
            return Err(error);
        }
        PreparedUpload::Ready {
            lock,
            admission,
            wallet_index,
        } => (lock, admission, wallet_index),
    };

    // Consume the preparation claim while holding the per-job upload lock,
    // immediately before any wallet side effect. This closes the TOCTOU window:
    // once consumed, the row is no longer reclaimable and a stale token cannot
    // pass even if its lease expired after an earlier queue-time check.
    if let (Some(jid), Some(token)) = (remember_job_id.as_deref(), prepare_claim_token.as_deref()) {
        if !consume_preparation_claim(state.db.pool(), jid, token).await? {
            tracing::warn!(
                "[wallet-job:upload] job_id={} stale preparation fenced inside upload lock",
                jid
            );
            if let Some(lock) = upload_lock.take() {
                lock.release(jid).await;
            }
            return Ok(());
        }
    }

    let result = execute_upload_and_transfer_locked(
        state,
        wallet_index,
        encrypted_b64,
        vector,
        importance,
        owner,
        namespace,
        package_id,
        account_id,
        agent_public_key,
        remember_job_id.clone(),
        prepare_claim_token,
        epochs,
        congestion_requeues,
        attempt_info,
        admission,
    )
    .await;

    if let (Some(lock), Some(jid)) = (upload_lock, remember_job_id.as_deref()) {
        lock.release(jid).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn execute_upload_and_transfer_locked(
    state: &AppState,
    wallet_index: usize,
    encrypted_b64: String,
    vector: Vec<f32>,
    importance: f32,
    owner: String,
    namespace: String,
    package_id: String,
    account_id: String,
    agent_public_key: Option<String>,
    remember_job_id: Option<String>,
    prepare_claim_token: Option<String>,
    epochs: u32,
    congestion_requeues: u32,
    attempt_info: WalletJobAttemptInfo,
    mut admission: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<(), WalletJobError> {
    // ── Idempotency guard ──────────────────────────────────────
    // `upload_blob` mints a paid on-chain Walrus Blob. On a retry (Apalis
    // re-run, or an ambiguous client timeout that requeued the job) the blob
    // may already have been uploaded and its id persisted. Re-uploading would
    // mint a *second* paid blob for the same write. Consult the job's persisted
    // state and resume from the point after the upload instead of redoing it.
    // (This runs under the per-job advisory lock taken by the caller.)
    if let Some(ref jid) = remember_job_id {
        match upload_resume_disposition(state.db.pool(), jid).await {
            UploadResume::AlreadyDone { blob_id } => {
                tracing::info!(
                    "[wallet-job:upload] job_id={} already done (blob_id={}) — skipping re-upload",
                    jid,
                    blob_id,
                );
                return Ok(());
            }
            UploadResume::ResumeTransfer {
                blob_id,
                blob_object_id,
            } => {
                tracing::info!(
                    "[wallet-job:upload] job_id={} already uploaded (blob_id={}) — skipping re-upload, resuming metadata/transfer",
                    jid,
                    blob_id,
                );
                // Decode only to recover the ciphertext byte length for quota
                // accounting; the bytes themselves aren't re-uploaded. A decode
                // failure here is a real error (the row says `uploaded`, so it
                // decoded once) — never silently record a zero-size row.
                let blob_size_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&encrypted_b64)
                    .map_err(|e| {
                        WalletJobError::Permanent(format!(
                            "resume: encrypted_b64 no longer decodes for job {}: {}",
                            jid, e
                        ))
                    })?
                    .len() as i64;
                return resume_metadata_and_transfer(
                    state,
                    wallet_index,
                    jid,
                    &blob_id,
                    blob_object_id,
                    &owner,
                    &namespace,
                    &package_id,
                    &account_id,
                    agent_public_key.as_deref(),
                    &encrypted_b64,
                    &vector,
                    blob_size_bytes,
                    importance,
                )
                .await;
            }
            UploadResume::ResumeIndex { blob_id } => {
                // Paid blob exists and (per the full-success route) was already
                // transferred; only indexing may be missing. Finish it — never
                // re-upload — with the stored blob_id.
                tracing::info!(
                    "[wallet-job:upload] job_id={} already uploaded (blob_id={}, no object id) — skipping re-upload, resuming indexing",
                    jid,
                    blob_id,
                );
                let blob_size_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&encrypted_b64)
                    .map_err(|e| {
                        WalletJobError::Permanent(format!(
                            "resume: encrypted_b64 no longer decodes for job {}: {}",
                            jid, e
                        ))
                    })?
                    .len() as i64;
                return insert_vector_and_mark_remember_done(
                    state,
                    Some(jid),
                    &owner,
                    &namespace,
                    &blob_id,
                    &vector,
                    blob_size_bytes,
                    importance,
                    wallet_index,
                    agent_public_key.as_deref(),
                    Some(&package_id),
                    // Resuming after a restart from persisted `remember_jobs`
                    // state, which doesn't carry end_epoch — the periodic
                    // expiry re-verification sweep backfills it on its next
                    // pass, same as any other row that starts out with an
                    // unknown expiry.
                    None,
                )
                .await;
            }
            UploadResume::Indeterminate => {
                // Couldn't read the job's state → can't tell whether a paid blob
                // already exists. Fail closed: retry without uploading rather than
                // risk a duplicate mint.
                return Err(WalletJobError::Transient(format!(
                    "could not read upload state for job {} — retrying without re-upload",
                    jid
                )));
            }
            UploadResume::Upload => {}
        }
    }

    // ── Mark running ───────────────────────────────────────────
    if let Some(ref jid) = remember_job_id {
        let _ = sqlx::query(
            "UPDATE remember_jobs SET status = 'running', error_msg = NULL, updated_at = NOW() WHERE id = $1",
        )
        .bind(jid)
        .execute(state.db.pool())
        .await;
    }

    // ── Decode encrypted bytes ─────────────────────────────────
    let encrypted = match base64::engine::general_purpose::STANDARD.decode(&encrypted_b64) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("base64 decode failed: {}", e);
            let classified = WalletJobError::Permanent(msg.clone());
            update_remember_job_after_wallet_error(
                state.db.pool(),
                remember_job_id.as_deref(),
                &classified,
                &msg,
                None,
            )
            .await;
            tracing::error!(
                "[wallet-job:upload] job_id={} {}",
                remember_job_id.as_deref().unwrap_or("-"),
                msg
            );
            return Err(classified);
        }
    };

    tracing::info!(
        "[wallet-job:upload] job_id={} owner={} ns={} key={} bytes={}",
        remember_job_id.as_deref().unwrap_or("-"),
        &owner[..10.min(owner.len())],
        namespace,
        wallet_index,
        encrypted.len(),
    );

    if let Some(ref jid) = remember_job_id {
        return match execute_durable_upload(
            state,
            wallet_index,
            &encrypted,
            &encrypted_b64,
            &vector,
            importance,
            &owner,
            &namespace,
            &package_id,
            &account_id,
            agent_public_key.as_deref(),
            jid,
            epochs,
        )
        .await
        {
            Ok(()) => Ok(()),
            Err(err) => {
                // The upload attempt is over. Free the wallet before any
                // backoff so the next blob on this key can register.
                drop(admission.take());
                // Sidecar failures are classified where they originate inside
                // execute_durable_upload. Preserve that classification here:
                // journal/state validation can already return Permanent, and
                // reclassifying its display text would incorrectly make it
                // retryable and leave the polling row running.
                let msg = err.message().to_string();
                // Park on the congestion budget instead of the 5-attempt one.
                if matches!(err, WalletJobError::UploadSlotCongestion(_))
                    && congestion_requeues < MAX_CONGESTION_REQUEUES
                {
                    update_remember_job_after_wallet_error(
                        state.db.pool(),
                        Some(jid.as_str()),
                        &err,
                        &congestion_wait_message(&msg),
                        None,
                    )
                    .await;
                    keep_upload_storage_reservation(state, jid, &owner, &encrypted_b64).await;
                    let delay_secs = congestion_backoff_secs(congestion_requeues);
                    let run_at = chrono::Utc::now().timestamp() + delay_secs as i64;
                    let next_wallet = congestion_resume_wallet(
                        wallet_index,
                        state.key_pool.len(),
                        WalletJobError::is_sidecar_upload_transport_error(&msg)
                            || WalletJobError::is_shared_upload_service_error(&msg),
                    );
                    let job_id_for_log = jid.clone();
                    let mut storage = state.wallet_storage.clone();
                    match storage
                        .schedule_request(
                            wallet_job_request(WalletJob {
                                wallet_index: next_wallet,
                                congestion_requeues: congestion_requeues + 1,
                                operation: WalletOperation::UploadAndTransfer {
                                    encrypted_b64,
                                    vector,
                                    importance,
                                    owner,
                                    namespace,
                                    package_id,
                                    account_id,
                                    agent_public_key,
                                    remember_job_id,
                                    prepare_claim_token,
                                    epochs,
                                },
                            }),
                            run_at,
                        )
                        .await
                    {
                        Ok(_) => {
                            tracing::warn!(
                                "[wallet-job:upload] job_id={} durable upload congested; requeued delay={}s requeue={}/{} next_wallet={}",
                                job_id_for_log,
                                delay_secs,
                                congestion_requeues + 1,
                                MAX_CONGESTION_REQUEUES,
                                next_wallet,
                            );
                            return Ok(());
                        }
                        Err(requeue_err) => {
                            tracing::error!(
                                "[wallet-job:upload] job_id={} durable congestion requeue failed, falling back to Apalis retry: {}",
                                job_id_for_log,
                                requeue_err,
                            );
                            return Err(WalletJobError::Transient(format!(
                                "{}; congestion requeue failed: {}",
                                msg, requeue_err
                            )));
                        }
                    }
                }
                maybe_alert_walrus_upload_exhausted(
                    state,
                    &err,
                    attempt_info,
                    Some(jid.as_str()),
                    &owner,
                    &namespace,
                    wallet_index,
                    &msg,
                )
                .await;
                update_remember_job_after_wallet_error(
                    state.db.pool(),
                    Some(jid.as_str()),
                    &err,
                    &msg,
                    Some(attempt_info),
                )
                .await;
                tracing::error!(
                    "[wallet-job:upload] job_id={} {} classification={} retryable={}",
                    jid,
                    msg,
                    err.kind(),
                    !err.aborts_retries()
                );
                // The durable upload has its own exit, so it needs its own
                // spacing — this is the path a real retry actually took.
                // Observed on dev: `durable Walrus upload request failed`
                // classified transient at attempt 1/5, with the next attempt
                // starting in the same second because only the legacy exit
                // below had been given a backoff.
                if let Some(delay) = upload_retry_backoff(&err, attempt_info) {
                    tracing::info!(
                        "[wallet-job:upload] job_id={} backing off {:?} before attempt {}/{}",
                        jid,
                        delay,
                        attempt_info.current + 1,
                        attempt_info.max,
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(err)
            }
        };
    }

    // Legacy untracked jobs retain the atomic sidecar route.
    let upload_result = crate::storage::walrus::upload_blob(
        &state.http_client,
        &state.config.sidecar_url,
        state.config.sidecar_secret.as_deref(),
        &encrypted,
        epochs as u64,
        &owner,
        wallet_index,
        &namespace,
        &package_id,
        agent_public_key.as_deref(),
        remember_job_id.as_deref(),
        crate::storage::walrus::SealPersistence::V1New {
            account_id: &account_id,
            registry_id: &state.config.registry_id,
            policy_package_id: &state.config.seal_policy_package_id,
        },
    )
    .await;

    let upload = match upload_result {
        Ok(u) => u,
        Err(UploadBlobError::MetadataTransferFailed {
            blob_id,
            object_id,
            message,
            end_epoch,
        }) => {
            tracing::warn!(
                "[wallet-job:upload] job_id={} upload succeeded but metadata/transfer failed: {}",
                remember_job_id.as_deref().unwrap_or("-"),
                message,
            );

            warm_blob_cache_after_upload(state, &blob_id, &encrypted).await;

            // Durably record the paid mint + its object id before handing off to
            // the recovery job (see persist_uploaded_state). A retry that lands
            // here reads this to resume the transfer instead of re-minting.
            if let Some(ref jid) = remember_job_id {
                persist_uploaded_state(state.db.pool(), jid, &blob_id, Some(&object_id)).await?;
            }

            let job_id_for_log = remember_job_id.as_deref().unwrap_or("-").to_string();
            let recovery_remember_job_id = remember_job_id.clone();
            let mut storage = state.wallet_followup_storage.clone();
            if let Err(e) = storage
                .push_request(wallet_job_request(WalletJob {
                    wallet_index,
                    congestion_requeues: 0,
                    operation: WalletOperation::SetMetadataAndTransfer {
                        blob_object_id: object_id,
                        owner,
                        namespace,
                        package_id: Some(package_id),
                        agent_id: agent_public_key,
                        remember_job_id,
                        blob_id: Some(blob_id.clone()),
                        vector: Some(vector),
                        blob_size_bytes: Some(encrypted.len() as i64),
                        importance,
                        encrypted_b64: Some(encrypted_b64.clone()),
                        account_id: Some(account_id.clone()),
                        policy_package_id: Some(state.config.seal_policy_package_id.clone()),
                        end_epoch,
                    },
                }))
                .await
            {
                let classified = classify_wallet_remember_handoff_failure(
                    state.db.pool(),
                    recovery_remember_job_id.as_deref(),
                    format!("failed to enqueue metadata/transfer recovery job: {}", e),
                )
                .await;
                tracing::error!(
                    "[wallet-job:upload] job_id={} {}",
                    job_id_for_log,
                    classified,
                );
                return Err(classified);
            }

            tracing::info!(
                "[wallet-job:upload] job_id={} enqueued metadata/transfer recovery for blob_id={} key={}",
                job_id_for_log,
                blob_id,
                wallet_index,
            );
            return Ok(());
        }
        Err(UploadBlobError::App(e)) => {
            drop(admission.take());
            let msg = format!("walrus upload failed: {}", e);
            // A balance::split gas-budget failure stays retriable (rotates onto
            // another pool wallet) until every candidate wallet has failed it,
            // then escalates to an aborting GasPoolExhausted (+ ops alert below).
            let classified = escalate_if_gas_pool_exhausted(
                WalletJobError::classify_sidecar_error(&msg),
                attempt_info.current,
                attempt_info.max,
                state.key_pool.len(),
            );
            // Upload-slot congestion is the pipeline's fault, not this job's.
            // Re-enqueue a fresh delayed copy (minutes-scale backoff, wallet
            // rotated, attempt budget untouched) instead of burning all 5
            // wallet attempts inside the same backlog window. Past the
            // requeue budget, fall through to the normal retry path so a
            // never-ending saturation still ends in an "exhausted" alert.
            if matches!(classified, WalletJobError::UploadSlotCongestion(_))
                && congestion_requeues < MAX_CONGESTION_REQUEUES
            {
                // Keep the polling row alive ('running' + congestion message)
                // while the requeued copy waits out the backlog.
                update_remember_job_after_wallet_error(
                    state.db.pool(),
                    remember_job_id.as_deref(),
                    &classified,
                    &congestion_wait_message(&msg),
                    None,
                )
                .await;
                if let Some(job_id) = remember_job_id.as_deref() {
                    keep_upload_storage_reservation(state, job_id, &owner, &encrypted_b64).await;
                }

                let delay_secs = congestion_backoff_secs(congestion_requeues);
                let run_at = chrono::Utc::now().timestamp() + delay_secs as i64;
                let next_wallet = (wallet_index + 1) % state.key_pool.len().max(1);
                let job_id_for_log = remember_job_id.as_deref().unwrap_or("-").to_string();
                let mut storage = state.wallet_storage.clone();
                match storage
                    .schedule_request(
                        wallet_job_request(WalletJob {
                            wallet_index: next_wallet,
                            congestion_requeues: congestion_requeues + 1,
                            operation: WalletOperation::UploadAndTransfer {
                                encrypted_b64,
                                vector,
                                importance,
                                owner,
                                namespace,
                                package_id,
                                account_id,
                                agent_public_key,
                                remember_job_id,
                                prepare_claim_token,
                                epochs,
                            },
                        }),
                        run_at,
                    )
                    .await
                {
                    Ok(_) => {
                        tracing::warn!(
                            "[wallet-job:upload] job_id={} upload slots saturated; requeued delay={}s requeue={}/{} next_wallet={}",
                            job_id_for_log,
                            delay_secs,
                            congestion_requeues + 1,
                            MAX_CONGESTION_REQUEUES,
                            next_wallet,
                        );
                        return Ok(());
                    }
                    Err(requeue_err) => {
                        // The job payload was consumed by the failed schedule
                        // call — fall back to a plain transient error so
                        // Apalis keeps the original job alive on its own
                        // retry cadence. (Congestion fires none of the
                        // alert helpers below, and the polling row was
                        // already updated above.)
                        tracing::error!(
                            "[wallet-job:upload] job_id={} congestion requeue failed, falling back to Apalis retry: {}",
                            job_id_for_log,
                            requeue_err,
                        );
                        return Err(WalletJobError::Transient(format!(
                            "{}; congestion requeue failed: {}",
                            msg, requeue_err
                        )));
                    }
                }
            }
            maybe_alert_walrus_package_upgrade_detected(
                state,
                remember_job_id.as_deref(),
                Some(&owner),
                Some(&namespace),
                &msg,
            )
            .await;
            maybe_alert_walrus_object_locked(
                state,
                &classified,
                remember_job_id.as_deref(),
                Some(&owner),
                Some(&namespace),
                &msg,
            )
            .await;
            maybe_alert_walrus_low_wal_balance(
                state,
                &classified,
                wallet_index,
                remember_job_id.as_deref(),
                Some(&owner),
                Some(&namespace),
                &msg,
            )
            .await;
            maybe_alert_walrus_gas_pool_exhausted(
                state,
                &classified,
                remember_job_id.as_deref(),
                Some(&owner),
                Some(&namespace),
                wallet_index,
                &msg,
            )
            .await;
            maybe_alert_walrus_upload_exhausted(
                state,
                &classified,
                attempt_info,
                remember_job_id.as_deref(),
                &owner,
                &namespace,
                wallet_index,
                &msg,
            )
            .await;
            update_remember_job_after_wallet_error(
                state.db.pool(),
                remember_job_id.as_deref(),
                &classified,
                &msg,
                Some(attempt_info),
            )
            .await;
            tracing::error!(
                "[wallet-job:upload] job_id={} {} classification={} retryable={}",
                remember_job_id.as_deref().unwrap_or("-"),
                msg,
                classified.kind(),
                !classified.aborts_retries()
            );
            // The wallet slot stays held across this sleep. That is
            // deliberate: a backing-off job is still this wallet's turn, and
            // releasing it would invite another job onto a wallet that is
            // about to retry anyway.
            if let Some(delay) = upload_retry_backoff(&classified, attempt_info) {
                tracing::info!(
                    "[wallet-job:upload] job_id={} backing off {:?} before attempt {}/{}",
                    remember_job_id.as_deref().unwrap_or("-"),
                    delay,
                    attempt_info.current + 1,
                    attempt_info.max,
                );
                tokio::time::sleep(delay).await;
            }
            return Err(classified);
        }
    };
    let blob_id = upload.blob_id.clone();

    warm_blob_cache_after_upload(state, &blob_id, &encrypted).await;

    // Persist the paid mint durably BEFORE indexing. This UPDATE is the record
    // the idempotency guard reads on a retry; if it were lost, a retry would see
    // no blob_id and re-mint. Treat a persist failure as retriable (the mint is
    // irreversible, so we must not proceed as if it never happened) rather than
    // the old fire-and-forget `let _ =`. Also stores blob_object_id so an
    // uploaded-but-not-done retry can resume the transfer without re-minting.
    if let Some(ref jid) = remember_job_id {
        persist_uploaded_state(state.db.pool(), jid, &blob_id, upload.object_id.as_deref()).await?;
    }

    // The sidecar's `/walrus/upload` endpoint already performs metadata+transfer
    // atomically. A successful upload response means the blob is ready to index.
    insert_vector_and_mark_remember_done(
        state,
        remember_job_id.as_deref(),
        &owner,
        &namespace,
        &blob_id,
        &vector,
        encrypted.len() as i64,
        importance,
        wallet_index,
        agent_public_key.as_deref(),
        Some(&package_id),
        upload.end_epoch,
    )
    .await
}

/// Mirrors the TS sidecar's `isWalrusPackageVersionMismatch` detector. We
/// recheck the pattern on the Rust side so we can fire a one-shot informational
/// Slack alert when the sidecar surfaces an EWrongVersion MoveAbort, without
/// having to plumb a structured signal back from the subprocess.
///
/// Anchor: requires the literal `MoveAbort` token alongside either the
/// `::system::inner_mut` function-path fragment (cross-transport stable, since
/// the package component is always a numeric address) OR the symbolic
/// `EWrongVersion` (only present on gRPC/GraphQL clients). See
/// `services/server/scripts/walrus-error-detection.ts` for the same pattern.
fn is_walrus_package_version_mismatch(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    if !lower.contains("moveabort") && !lower.contains("move abort") {
        return false;
    }
    lower.contains("::system::inner_mut") || lower.contains("ewrongversion")
}

async fn maybe_alert_walrus_package_upgrade_detected(
    state: &AppState,
    remember_job_id: Option<&str>,
    owner: Option<&str>,
    namespace: Option<&str>,
    msg: &str,
) {
    if !is_walrus_package_version_mismatch(msg) {
        return;
    }

    let alert = WalrusPackageUpgradeDetectedAlert {
        remember_job_id: remember_job_id.map(str::to_owned),
        owner: owner.map(str::to_owned),
        namespace: namespace.map(str::to_owned),
        sui_network: state.config.sui_network.clone(),
        sidecar_walrus_dep_version: SIDECAR_WALRUS_DEP_VERSION.to_string(),
        on_chain_version_before: None,
        on_chain_version_after: None,
        action_taken: "Sidecar refreshed cached @mysten/walrus client; Apalis will retry against the new package metadata.".to_string(),
        error: msg.to_string(),
    };

    if let Err(err) = state
        .alerts
        .notify_walrus_package_upgrade_detected(alert)
        .await
    {
        tracing::warn!(
            "[wallet-job:upload] failed to send Slack alert for Walrus package upgrade detected: {}",
            err
        );
    }
}

/// Identifiers parsed from a Sui owned-object lock / equivocation error, used
/// to enrich the object-lock alert and the persisted job row. Every field is
/// best-effort: Sui error formatting varies, so a field stays `None` when its
/// token isn't present rather than failing the whole parse.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct LockedObjectInfo {
    object_id: Option<String>,
    version: Option<String>,
    locking_digest: Option<String>,
}

/// Extract the text between the first `open` delimiter and the next `close`
/// after it. Returns `None` if either delimiter is missing or the span is
/// empty.
fn extract_delimited(haystack: &str, open: &str, close: &str) -> Option<String> {
    let start = haystack.find(open)? + open.len();
    let rest = &haystack[start..];
    let end = rest.find(close)?;
    let value = rest[..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Extract the first `0x`-prefixed hex object id in the message (the locked
/// object always appears first inside `Object (0x…, …)`).
fn extract_first_object_id(haystack: &str) -> Option<String> {
    let idx = haystack.find("0x")?;
    let hex: String = haystack[idx + 2..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    (!hex.is_empty()).then(|| format!("0x{hex}"))
}

/// Parse the locked object id, version, and locking transaction digest out of
/// a Sui object-lock error string, e.g.:
/// `…[Object (0xabc…, SequenceNumber(884613305), o#…) already locked by a
///  different transaction: TransactionDigest(8bjFg…) … with 6842 stake]`.
fn parse_locked_object_info(msg: &str) -> LockedObjectInfo {
    LockedObjectInfo {
        object_id: extract_first_object_id(msg),
        version: extract_delimited(msg, "SequenceNumber(", ")"),
        locking_digest: extract_delimited(msg, "TransactionDigest(", ")"),
    }
}

/// Fire the distinct object-lock / equivocation alert when a wallet job fails
/// with `ObjectLockedUntilEpoch`. Kept separate from the "exhausted retries"
/// alert: this case never reaches retry exhaustion (it aborts immediately), so
/// the on-call message must name the real cause — an owned-object lock — and
/// surface the object id / version / locking digest for triage.
async fn maybe_alert_walrus_object_locked(
    state: &AppState,
    error: &WalletJobError,
    remember_job_id: Option<&str>,
    owner: Option<&str>,
    namespace: Option<&str>,
    msg: &str,
) {
    if !matches!(error, WalletJobError::ObjectLockedUntilEpoch(_)) {
        return;
    }

    let info = parse_locked_object_info(msg);
    let alert = WalrusObjectLockedAlert {
        remember_job_id: remember_job_id.map(str::to_owned),
        owner: owner.map(str::to_owned),
        namespace: namespace.map(str::to_owned),
        sui_network: state.config.sui_network.clone(),
        locked_object_id: info.object_id,
        locked_object_version: info.version,
        locking_transaction_digest: info.locking_digest,
        error: msg.to_string(),
    };

    if let Err(err) = state.alerts.notify_walrus_object_locked(alert).await {
        tracing::warn!(
            "[wallet-job:upload] failed to send Slack alert for Walrus object lock: {}",
            err
        );
    }
}

/// Attempts after which repeated gas-budget (`balance::split` ENotEnough)
/// failures are treated as candidate-level exhaustion rather than a single
/// starved wallet. Upload jobs pass the configured pool size because retries
/// walk that pool deterministically. Pinned operations pass 1 because they
/// cannot rotate onto another wallet.
fn gas_pool_exhaustion_threshold(candidate_wallets: usize, max_attempts: usize) -> usize {
    candidate_wallets.min(max_attempts).max(1)
}

/// Escalate a retriable gas-budget failure to an aborting `GasPoolExhausted`
/// once every candidate pool wallet has failed the same way. Below the
/// threshold the error stays `Transient` so Apalis rotates onto another wallet —
/// a single starved wallet must not fail an upload a healthy wallet could serve.
/// Non-gas-budget errors pass through unchanged.
fn escalate_if_gas_pool_exhausted(
    classified: WalletJobError,
    attempt: usize,
    max_attempts: usize,
    candidate_wallets: usize,
) -> WalletJobError {
    if let WalletJobError::Transient(ref msg) = classified {
        if WalletJobError::is_gas_pool_budget_error(msg)
            && attempt >= gas_pool_exhaustion_threshold(candidate_wallets, max_attempts)
        {
            return WalletJobError::GasPoolExhausted(msg.clone());
        }
    }
    classified
}

/// Fire the distinct gas-pool maintenance alert when a wallet job fails with
/// `GasPoolExhausted` (Enoki dry-run `balance::split` ENotEnough). Kept separate
/// from the "exhausted retries" alert: this case aborts immediately, so the
/// on-call message must name the real cause — fragmented/insufficient SUI gas on
/// the pool wallets — and point ops at gas-coin consolidation/top-up.
async fn maybe_alert_walrus_gas_pool_exhausted(
    state: &AppState,
    error: &WalletJobError,
    remember_job_id: Option<&str>,
    owner: Option<&str>,
    namespace: Option<&str>,
    wallet_index: usize,
    msg: &str,
) {
    if !matches!(error, WalletJobError::GasPoolExhausted(_)) {
        return;
    }

    let alert = WalrusGasPoolExhaustedAlert {
        remember_job_id: remember_job_id.map(str::to_owned),
        owner: owner.map(str::to_owned),
        namespace: namespace.map(str::to_owned),
        sui_network: state.config.sui_network.clone(),
        wallet_index,
        configured_wallets: state.key_pool.len(),
        error: msg.to_string(),
    };

    if let Err(err) = state.alerts.notify_walrus_gas_pool_exhausted(alert).await {
        tracing::warn!(
            "[wallet-job:upload] failed to send Slack alert for Walrus gas-pool exhaustion: {}",
            err
        );
    }
}

#[derive(Debug)]
struct WalrusWALBalanceAlert {
    required: Option<u64>,
    available: u64,
}

fn extract_u64_after_token(message: &str, token: &str) -> Option<u64> {
    let lower = message.to_ascii_lowercase();
    let start = lower.find(token)?;
    let mut saw_digit = false;
    let mut digits = String::new();
    for ch in lower[start + token.len()..].chars() {
        if ch.is_ascii_digit() {
            saw_digit = true;
            digits.push(ch);
        } else if saw_digit {
            break;
        }
    }
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn parse_wal_balance_alert_info(message: &str) -> Option<WalrusWALBalanceAlert> {
    let lower = message.to_ascii_lowercase();
    if !lower.contains("insufficient balance") || !lower.contains("::wal::wal") {
        return None;
    }

    let available = extract_u64_after_token(message, "available:")?;
    if available >= WAL_BALANCE_LOW_THRESHOLD_MIST {
        return None;
    }

    Some(WalrusWALBalanceAlert {
        required: extract_u64_after_token(message, "required:"),
        available,
    })
}

async fn maybe_alert_walrus_low_wal_balance(
    state: &AppState,
    error: &WalletJobError,
    wallet_index: usize,
    remember_job_id: Option<&str>,
    owner: Option<&str>,
    namespace: Option<&str>,
    msg: &str,
) {
    if !matches!(error, WalletJobError::WalrusBalanceLow(_)) {
        return;
    }

    let info = match parse_wal_balance_alert_info(msg) {
        Some(info) => info,
        None => return,
    };

    let alert = WalrusWalletBalanceLowAlert {
        remember_job_id: remember_job_id.map(str::to_owned),
        owner: owner.map(str::to_owned),
        namespace: namespace.map(str::to_owned),
        sui_network: state.config.sui_network.clone(),
        available: info.available,
        required: info.required,
        threshold: WAL_BALANCE_LOW_THRESHOLD_MIST,
        wallet_index,
        configured_wallets: state.key_pool.len(),
        error: msg.to_string(),
    };

    if let Err(err) = state.alerts.notify_walrus_low_wal_balance(alert).await {
        tracing::warn!(
            "[wallet-job:upload] failed to send Slack alert for low WAL balance: {}",
            err
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn maybe_alert_walrus_upload_exhausted(
    state: &AppState,
    error: &WalletJobError,
    attempt_info: WalletJobAttemptInfo,
    remember_job_id: Option<&str>,
    owner: &str,
    namespace: &str,
    wallet_index: usize,
    msg: &str,
) {
    if matches!(error, WalletJobError::WalrusBalanceLow(_)) {
        return;
    }

    if !attempt_info.exhausted_by(error) {
        return;
    }

    let alert = WalrusUploadExhaustedAlert {
        remember_job_id: remember_job_id.map(str::to_owned),
        owner: owner.to_string(),
        namespace: namespace.to_string(),
        attempt: attempt_info.current,
        max_attempts: attempt_info.max,
        wallet_index,
        configured_wallets: state.key_pool.len(),
        sui_network: state.config.sui_network.clone(),
        error: msg.to_string(),
    };

    if let Err(err) = state.alerts.notify_walrus_upload_exhausted(alert).await {
        tracing::warn!(
            "[wallet-job:upload] failed to send Slack alert for exhausted Walrus upload retries: {}",
            err
        );
    }
}

// ============================================================
// WalletJobError
// ============================================================

/// Failure classification for `WalletJob` handlers.
///
/// Apalis re-queues `Transient` for another attempt, up to `MAX_ATTEMPTS`.
/// No WorkerBuilder attaches a retry/backoff layer, so that re-queue has no
/// inherent delay — callers that need real spacing between attempts (lock
/// contention, congestion) must enforce it themselves (see `backoff_duration`,
/// `congestion_backoff_secs`). `Permanent` errors are returned as-is so the
/// job is marked Dead immediately and we don't burn retry budget on inputs
/// that can never succeed.
///
/// Mapping rules (enforced at the point of error origination):
/// - `MoveAbort(_)` → `Permanent` (deterministic Move-level failure)
/// - Walrus register `0x2::coin::destroy_zero` ENonZero → `Transient` (WAL
///   payment over-funded from a stale cached price; the sidecar refreshes the
///   client so the retry re-reads the live price and splits the exact amount)
/// - Enoki dry-run `0x2::balance::split` ENotEnough → `GasPoolExhausted`
///   (abort: pool SUI gas coins are fragmented/insufficient; retrying rotates
///   to the next starved wallet — needs ops gas consolidation/top-up)
/// - `ObjectLockedAtVersion(_)` → `Transient` (retry can rebuild with a fresh
///   wallet assignment)
/// - owned-object lock / equivocation ("already locked by a different
///   transaction", ">1/3 of validators … non-retriable", "equivocated") →
///   `ObjectLockedUntilEpoch` (abort: retrying within the epoch re-fails)
/// - `InsufficientGas` / `ObjectNotFound` /
///   `ObjectVersionUnavailableForConsumption` → `Transient` (refill wallet,
///   refresh local state, retry)
/// - Network 429 / 5xx / timeout → `Transient`
#[derive(Debug)]
pub enum WalletJobError {
    /// Transient failure — Apalis should retry with backoff.
    Transient(String),
    /// Permanent failure — Apalis should mark Dead immediately (no retry).
    Permanent(String),
    /// A wallet's WAL balance is below the alert threshold (default 2 WAL). This
    /// keeps retries enabled so other pool wallets can carry the request, while
    /// still surfacing a dedicated ops alert.
    WalrusBalanceLow(String),
    /// A Sui owned object/version is locked to a competing transaction. The
    /// lock does not clear with immediate retries — it holds until the lock
    /// resolves, typically at the next epoch boundary — so retrying within the
    /// epoch re-fails against the same object and only burns the wallet attempt
    /// budget. NOT `Permanent`: the same input can succeed in a later epoch.
    /// Apalis aborts so we surface a distinct object-lock alert rather than a
    /// misleading "wallet retries exhausted" one.
    ObjectLockedUntilEpoch(String),
    /// An Enoki sponsored dry-run aborted in `0x2::balance::split` with
    /// ENotEnough (abort code 2): the pool wallet's SUI gas coins are
    /// fragmented or too small to cover the sponsored budget. Retrying rotates
    /// to the next pool wallet and re-fails the same way, burning the attempt
    /// budget without progress. NOT `Permanent`: it succeeds again once ops
    /// consolidates / tops up SUI gas on the pool wallets. Apalis aborts so we
    /// surface a distinct gas-pool maintenance alert rather than a misleading
    /// "wallet retries exhausted" one.
    GasPoolExhausted(String),
    /// The sidecar's upload limiter timed out handing out a slot — every
    /// upload slot was busy for the whole acquire window. This is pure
    /// congestion: nothing is wrong with the job or the wallet, the pipeline
    /// is just saturated. Retrying on the normal 2-16s cadence burns the
    /// whole wallet-attempt budget inside one backlog window, so the caller
    /// re-enqueues a fresh delayed copy instead (minutes-scale backoff,
    /// attempt budget untouched) up to `MAX_CONGESTION_REQUEUES` times.
    UploadSlotCongestion(String),
}

impl WalletJobError {
    fn message(&self) -> &str {
        match self {
            WalletJobError::Transient(msg)
            | WalletJobError::Permanent(msg)
            | WalletJobError::WalrusBalanceLow(msg)
            | WalletJobError::ObjectLockedUntilEpoch(msg)
            | WalletJobError::GasPoolExhausted(msg)
            | WalletJobError::UploadSlotCongestion(msg) => msg,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            WalletJobError::Transient(_) => "transient",
            WalletJobError::Permanent(_) => "permanent",
            WalletJobError::WalrusBalanceLow(_) => "walrus_balance_low",
            WalletJobError::ObjectLockedUntilEpoch(_) => "object_locked_until_epoch",
            WalletJobError::GasPoolExhausted(_) => "gas_pool_exhausted",
            WalletJobError::UploadSlotCongestion(_) => "upload_slot_congestion",
        }
    }

    /// True if the error is `Permanent` — caller should NOT retry.
    pub fn is_permanent(&self) -> bool {
        matches!(self, WalletJobError::Permanent(_))
    }

    /// True if Apalis should stop retrying this job (abort rather than
    /// re-queue). Covers both `Permanent` (never valid) and
    /// `ObjectLockedUntilEpoch` (not valid again until the lock clears).
    /// Used to gate both the Apalis disposition and the "exhausted retries"
    /// alert so a single locked object doesn't burn the whole wallet budget.
    pub fn aborts_retries(&self) -> bool {
        matches!(
            self,
            WalletJobError::Permanent(_)
                | WalletJobError::ObjectLockedUntilEpoch(_)
                | WalletJobError::GasPoolExhausted(_)
        )
    }

    /// True if `msg` is an Enoki sponsored dry-run gas-budget failure: an abort
    /// in `0x2::balance::split` (ENotEnough). A single occurrence only proves the
    /// *selected* pool wallet is gas-starved, not the whole pool — escalation to
    /// `GasPoolExhausted` is gated on pool-level confirmation by the caller.
    pub fn is_gas_pool_budget_error(msg: &str) -> bool {
        let lower = msg.to_ascii_lowercase();
        let move_split = (lower.contains("moveabort") || lower.contains("move abort"))
            && lower.contains("balance")
            && lower.contains("split");
        let gas_selection = lower.contains("gas selection") && lower.contains("insufficient");
        let sui_balance = lower.contains("insufficient")
            && lower.contains("sui")
            && lower.contains("balance")
            && !lower.contains("::wal::wal");
        move_split || gas_selection || sui_balance
    }

    /// True if `msg` is the Walrus register PTB's `0x2::coin::destroy_zero`
    /// abort (ENonZero). The `@mysten/walrus` `#withWal` helper splits an exact
    /// WAL payment from the client's cached storage/write price and asserts the
    /// coin is empty afterwards; when mainnet price drops between the cached read
    /// and execution the contract deducts less WAL, leaving change that trips
    /// `destroy_zero`. Recoverable: retrying against a client that re-read the
    /// live price splits the correct amount, so this is Transient — never a
    /// Permanent MoveAbort.
    pub fn is_walrus_wal_payment_price_abort(msg: &str) -> bool {
        let lower = msg.to_ascii_lowercase();
        (lower.contains("moveabort") || lower.contains("move abort"))
            && lower.contains("destroy_zero")
    }

    /// Heuristic classification from the sidecar's error string. The sidecar
    /// surfaces Sui execution errors verbatim (Move abort codes, lock errors).
    /// Until the sidecar emits structured error codes, we match on substrings.
    /// True if `msg` is the sidecar's upload-limiter acquire timeout
    /// (`WalrusUploadLimitError`: "timed out waiting for wallet N upload
    /// slot" / "... global upload slot"). Matched on substrings because the
    /// message arrives wrapped in transport layers ("walrus upload failed:
    /// Internal Error: ...").
    pub fn is_upload_slot_congestion_error(msg: &str) -> bool {
        let lower = msg.to_ascii_lowercase();
        lower.contains("timed out waiting for") && lower.contains("upload slot")
    }

    /// The relayer's HTTP client lost the upload sidecar while a step was
    /// queued or in flight (`error sending request for url (.../walrus/upload...)`).
    /// The sidecar often still finishes that step. It is the same backlog as
    /// an acquire timeout, not a bad blob, so it must take the congestion
    /// requeue instead of the 5-attempt wallet budget.
    /// Trust the sidecar's structured availability code, not a bare 503 in
    /// arbitrary error text. A shared-service failure may follow submission;
    /// retry the same journal and signer on the bounded congestion schedule.
    pub fn is_shared_upload_service_error(msg: &str) -> bool {
        if !msg
            .to_ascii_lowercase()
            .contains("durable walrus upload failed (")
        {
            return false;
        }
        let Some(start) = msg.find('{') else {
            return false;
        };
        let Ok(body) = serde_json::from_str::<serde_json::Value>(&msg[start..]) else {
            return false;
        };
        body.get("code").and_then(serde_json::Value::as_str) == Some("SHARED_SERVICE_UNAVAILABLE")
            || (body.get("code").and_then(serde_json::Value::as_str) == Some("NO_SIDE_EFFECT")
                && body.get("causeCode").and_then(serde_json::Value::as_str)
                    == Some("SHARED_SERVICE_UNAVAILABLE"))
    }

    pub fn is_sidecar_upload_transport_error(msg: &str) -> bool {
        let lower = msg.to_ascii_lowercase();
        if !lower.contains("walrus/upload") && !lower.contains("walrus/set-metadata-batch") {
            return false;
        }
        lower.contains("error sending request for url")
            || lower.contains("error decoding response body")
            || lower.contains("request or response body error")
            || lower.contains("durable walrus upload response failed")
    }

    /// True if `msg` is one of the sidecar's register-transaction journal
    /// assertions (`validatePreparedRegisterTransaction` and friends in
    /// scripts/sidecar/routes/walrus-upload-journal.ts).
    ///
    /// These describe the SHAPE of a transaction the sidecar already built —
    /// wrong gas source, missing WAL withdrawal, sender/gas-owner mismatch,
    /// non-canonical bytes, digest mismatch. Replaying the journal rebuilds
    /// the same shape, so every retry re-fails identically; the job burns its
    /// whole retry budget before dying. Classify Permanent so it dies on the
    /// first attempt and the caller is told to send the fact again.
    ///
    /// Anchored on the assertion text rather than the transport's
    /// `NO_SIDE_EFFECT` code on purpose: that code means only "nothing reached
    /// the chain" and is also returned for pre-submission infra blips
    /// (`causeCode: SHARED_SERVICE_UNAVAILABLE` in retry/rpc.ts), which must
    /// stay retryable.
    pub fn is_register_transaction_shape_error(msg: &str) -> bool {
        let lower = msg.to_ascii_lowercase();
        Self::REGISTER_TRANSACTION_SHAPE_ASSERTIONS
            .iter()
            .any(|assertion| lower.contains(assertion))
    }

    /// The sidecar's register-transaction assertion sentences, lowercased and
    /// carrying the `registerTransaction` token they start with.
    ///
    /// Matched WHOLE, not as a `registertransaction`-anywhere guard plus a
    /// phrase-anywhere test. The text being classified is a wrapper
    /// (`durable Walrus upload failed (503 …): {json}`) that can carry a
    /// nested cause, so those two conditions can be satisfied by unrelated
    /// halves of one message: a transient RPC or relay failure that mentions
    /// the register step and, somewhere else entirely, a broad phrase like
    /// `digest mismatch` or `sender does not match`. Read loosely it becomes
    /// `Permanent`, `aborts_retries()` is true, the row is failed on attempt
    /// 1, and a write the next attempt would have landed is lost.
    ///
    /// The `sponsored registerTransaction …` variants are covered by the
    /// shorter forms here, which they contain.
    const REGISTER_TRANSACTION_SHAPE_ASSERTIONS: &'static [&'static str] = &[
        "registertransaction must use a validduring address-balance expiration",
        "registertransaction must pay gas from the address balance",
        "registertransaction has no wal address-balance withdrawal",
        "registertransaction resolved wal from an owned coin",
        "registertransaction resolved the relay tip from an owned sui coin",
        "registertransaction must use a distinct gas owner",
        "registertransaction sender does not match",
        "registertransaction gas owner does not match",
        "registertransaction.transactionbytes is not canonical base64",
        "registertransaction digest mismatch",
        "registertransaction contains invalid transactiondata",
    ];

    /// True if `msg` is a pool-wallet WAL shortfall. Deliberately the
    /// substring half of `parse_wal_balance_alert_info` without its
    /// `available < WAL_BALANCE_LOW_THRESHOLD_MIST` gate: that threshold
    /// decides whether ops gets paged, and a shortfall on a large blob can
    /// hold well over 2 WAL and still fail. Both are pool-wallet funding.
    pub fn is_walrus_wal_shortfall(msg: &str) -> bool {
        let lower = msg.to_ascii_lowercase();
        lower.contains("insufficient balance") && lower.contains("::wal::wal")
    }

    /// True if `msg` is a failure of the relayer's own pool wallets or upload
    /// pipeline rather than anything the caller controls. Gates client-facing
    /// error replacement; each arm matches on substrings only, with no
    /// alert-threshold coupling.
    pub fn is_infrastructure_funding_error(msg: &str) -> bool {
        msg.starts_with(CONGESTION_WAIT_ERROR_PREFIX)
            || Self::is_gas_pool_budget_error(msg)
            || Self::is_upload_slot_congestion_error(msg)
            || Self::is_sidecar_upload_transport_error(msg)
            || Self::is_walrus_wal_shortfall(msg)
    }

    pub fn classify_sidecar_error(msg: &str) -> Self {
        let lower = msg.to_ascii_lowercase();
        // PostgreSQL B-tree tuple-size failures are deterministic for the
        // same input. Retrying would repeat paid encrypt/upload work without
        // ever producing an index row.
        if lower.contains("index row requires")
            || lower.contains("index row size")
            || (lower.contains("index tuple") && lower.contains("too large"))
        {
            return WalletJobError::Permanent(msg.to_string());
        }
        if parse_wal_balance_alert_info(msg).is_some() {
            return WalletJobError::WalrusBalanceLow(msg.to_string());
        }
        // Register-transaction shape assertions are deterministic for the same
        // journal — see is_register_transaction_shape_error. Checked early so a
        // shape rejection cannot fall through to the Transient catch-all at the
        // end and spend the job's retry budget re-failing identically.
        if Self::is_register_transaction_shape_error(msg) {
            return WalletJobError::Permanent(msg.to_string());
        }
        // Sidecar upload limiter saturated — see UploadSlotCongestion docs.
        if Self::is_upload_slot_congestion_error(msg)
            || Self::is_shared_upload_service_error(msg)
            || Self::is_sidecar_upload_transport_error(msg)
        {
            return WalletJobError::UploadSlotCongestion(msg.to_string());
        }
        // A third party owns the blob. The uploader cannot transfer it, and
        // the relayer must not sign as the target.
        if lower.contains("blob_owner_mismatch") || lower.contains("metadata_receipt_mismatch") {
            return WalletJobError::Permanent(msg.to_string());
        }
        // The key at the journaled slot is a different wallet than the one
        // that prepared this upload. The same journal fails identically on
        // every retry, and another slot cannot sign the prepared bytes.
        if lower.contains("wallet_mapping_mismatch") {
            return WalletJobError::Permanent(msg.to_string());
        }
        // Enoki sponsored dry-run aborts in 0x2::balance::split with ENotEnough
        // (abort code 2) when the selected pool wallet's SUI gas coin cannot be
        // split to cover the sponsored budget (its SUI is fragmented or too low).
        // A single failure only proves THAT wallet is gas-starved, not the whole
        // pool, so classify Transient: Apalis rotates onto another pool wallet on
        // retry rather than failing an upload a healthy wallet could serve. The
        // wallet-job error arm escalates to an aborting GasPoolExhausted (+ ops
        // alert) only once every candidate wallet has failed the same way — see
        // escalate_if_gas_pool_exhausted.
        if Self::is_gas_pool_budget_error(msg) {
            return WalletJobError::Transient(msg.to_string());
        }
        // Walrus on-chain package upgrade — the cached @mysten/walrus client
        // carries stale package metadata until refreshed. The sidecar already
        // recreates the client on this error; classifying Transient lets
        // Apalis retry against the refreshed client instead of Dead-marking
        // a job that the next attempt will succeed on.
        if (lower.contains("moveabort") || lower.contains("move abort"))
            && (lower.contains("::system::inner_mut") || lower.contains("ewrongversion"))
        {
            return WalletJobError::Transient(msg.to_string());
        }
        // Walrus register PTB `0x2::coin::destroy_zero` abort (ENonZero). The
        // `@mysten/walrus` `#withWal` helper pre-funds an exact WAL payment from
        // the client's cached storage price, then asserts the coin is empty. When
        // the on-chain price drops between the cached read and execution the
        // contract deducts less WAL, leaving change that trips `destroy_zero`.
        // Not input-specific: the sidecar recreates the client on this error, so
        // classifying Transient lets Apalis retry against the refreshed (live)
        // price instead of Dead-marking a job the next attempt will succeed on.
        if Self::is_walrus_wal_payment_price_abort(msg) {
            return WalletJobError::Transient(msg.to_string());
        }
        // Sui owned-object lock / equivocation. The referenced object+version
        // is locked to a competing transaction and stays locked until the lock
        // clears (typically the next epoch boundary), so retrying within this
        // epoch deterministically re-fails against the same object. Distinct
        // from the recoverable `locked at version` case below — there is no
        // fresh version to rebuild against until the lock resolves.
        //
        // Requires a lock/equivocation-specific anchor. The "non-retriable" /
        // ">1/3 of validators by stake" preamble is NOT lock-specific on its
        // own (a generic invalid MoveAbort is also non-retriable), so it only
        // qualifies when corroborated by object-lock evidence in the same
        // message. Checked before the MoveAbort→Permanent catch so a genuine
        // lock isn't Dead-marked, while a bare non-retriable MoveAbort falls
        // through to Permanent.
        let has_lock_anchor = lower.contains("already locked by a different transaction")
            || lower.contains("reserved for another transaction")
            || lower.contains("equivocated")
            || lower.contains("equivocation");
        let corroborated_lock = (lower.contains("non-retriable")
            || lower.contains("rejected as invalid by more than 1/3 of validators by stake"))
            && lower.contains("object (")
            && lower.contains("locked");
        if has_lock_anchor || corroborated_lock {
            return WalletJobError::ObjectLockedUntilEpoch(msg.to_string());
        }
        if lower.contains("moveabort") || lower.contains("move abort") {
            return WalletJobError::Permanent(msg.to_string());
        }
        if lower.contains("objectlocked")
            || lower.contains("object_locked")
            || lower.contains("object is locked")
            || lower.contains("locked at version")
            || lower.contains("sponsor failed")
            || lower.contains("enoki api error")
            || lower.contains("sponsored transaction has expired")
        {
            return WalletJobError::Transient(msg.to_string());
        }
        WalletJobError::Transient(msg.to_string())
    }

    pub fn into_apalis_error(self) -> Error {
        let error = io::Error::other(self.to_string());
        match self {
            WalletJobError::Transient(_) => Error::Failed(Arc::new(Box::new(error))),
            WalletJobError::WalrusBalanceLow(_) => Error::Failed(Arc::new(Box::new(error))),
            // Congestion normally never reaches Apalis (the caller requeues a
            // delayed copy and returns Ok); past the requeue budget it rides
            // the normal retry track.
            WalletJobError::UploadSlotCongestion(_) => Error::Failed(Arc::new(Box::new(error))),
            WalletJobError::Permanent(_)
            | WalletJobError::ObjectLockedUntilEpoch(_)
            | WalletJobError::GasPoolExhausted(_) => Error::Abort(Arc::new(Box::new(error))),
        }
    }
}

impl std::fmt::Display for WalletJobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletJobError::Transient(msg) => write!(f, "wallet job error (transient): {}", msg),
            WalletJobError::Permanent(msg) => write!(f, "wallet job error (permanent): {}", msg),
            WalletJobError::ObjectLockedUntilEpoch(msg) => {
                write!(f, "wallet job error (object locked until epoch): {}", msg)
            }
            WalletJobError::WalrusBalanceLow(msg) => {
                write!(f, "wallet job error (insufficient WAL): {}", msg)
            }
            WalletJobError::GasPoolExhausted(msg) => {
                write!(f, "wallet job error (gas pool exhausted): {}", msg)
            }
            WalletJobError::UploadSlotCongestion(msg) => {
                write!(f, "wallet job error (upload slot congestion): {}", msg)
            }
        }
    }
}

impl std::error::Error for WalletJobError {}

// ============================================================
// RememberJob — legacy payload quarantine
// ============================================================

/// Legacy payload retained only to deserialize existing `apalis_jobs` rows.
/// Current routes enqueue `WalletOperation::UploadAndTransfer` instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RememberJob {
    /// Stable job ID returned to the client in the 202 response.
    pub job_id: String,
    /// SEAL-encrypted ciphertext (base64). Plaintext is NOT stored here.
    /// Embed + SEAL encrypt happen in the route handler before enqueuing.
    pub encrypted_b64: String,
    /// Pre-computed embedding vector (generated in route handler alongside encrypt).
    pub vector: Vec<f32>,
    /// Walrus Memory owner address (from auth middleware).
    pub owner: String,
    /// Namespace for isolation.
    pub namespace: String,
    /// Walrus Memory package ID (needed by metadata tx).
    pub package_id: String,
    /// Delegate public key (agent_id for upload metadata).
    pub agent_public_key: Option<String>,
}

/// Type alias for the RememberJob Apalis storage.
pub type RememberJobStorage = PostgresStorage<RememberJob>;

/// Reject pre-V1-new queue payloads before any external side effect.
///
/// `RememberJob` has no account ID or policy package, so it cannot satisfy the
/// destination SEAL persistence fence. Operators must drain or reconcile these
/// rows before enabling the V1-new contract.
pub async fn execute_remember(
    job: RememberJob,
    ctx: Data<Arc<AppState>>,
    _attempt_info: WalletJobAttemptInfo,
) -> Result<(), Error> {
    let state: &AppState = &ctx;
    let message = "legacy RememberJob lacks the V1-new SEAL persistence fence; reconcile it before enabling the V1-new contract".to_string();
    tracing::error!("[remember-job] {} job_id={}", message, job.job_id);

    let classified =
        classify_wallet_remember_handoff_failure(state.db.pool(), Some(&job.job_id), message).await;
    Err(classified.into_apalis_error())
}

// ============================================================
// BulkRememberJob
//
// Fans a preprocessed bulk request out into per-item wallet jobs.
// ============================================================

/// One pre-processed item (embed + encrypt already done in route handler).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRememberItem {
    /// remember_jobs row ID to update with status/blob_id.
    pub job_id: String,
    /// SEAL-encrypted ciphertext (base64). Pre-computed in route handler.
    pub encrypted_b64: String,
    /// Pre-computed embedding vector (1536-dim).
    pub vector: Vec<f32>,
    pub namespace: String,
    /// Wallet index assigned at enqueue time.
    pub wallet_index: usize,
    /// per-item importance score (defaults to "standard" 0.5 when
    /// the bulk-remember route doesn't run extraction — e.g. SDK passes
    /// pre-formed memories). `#[serde(default)]` so legacy bulk job rows
    /// drain cleanly at the neutral default.
    #[serde(default = "default_importance")]
    pub importance: f32,
}

/// Batch job payload — one BulkRememberJob per POST /api/remember/bulk call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRememberJob {
    pub owner: String,
    pub account_id: String,
    pub package_id: String,
    pub agent_public_key: Option<String>,
    pub items: Vec<BulkRememberItem>,
    #[serde(default = "default_epochs")]
    pub epochs: u32,
}

/// Type alias for the BulkRememberJob Apalis storage.
pub type BulkRememberJobStorage = PostgresStorage<BulkRememberJob>;

// ─────────────────────────────────────────────────────────────
// BulkRememberError
// ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum BulkRememberError {
    #[allow(dead_code)]
    Internal(String),
}

impl std::fmt::Display for BulkRememberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BulkRememberError::Internal(msg) => write!(f, "bulk-remember job error: {}", msg),
        }
    }
}

impl std::error::Error for BulkRememberError {}

// ─────────────────────────────────────────────────────────────
// execute_bulk_remember — Apalis handler
// ─────────────────────────────────────────────────────────────

/// Apalis worker handler for BulkRememberJob.
///
/// The bulk worker intentionally does not perform wallet work itself. It fans
/// out already-prepared items into the shared WalletJob queue so single-item
/// and bulk requests share the same retry/error-classification path.
pub async fn execute_bulk_remember(
    job: BulkRememberJob,
    ctx: Data<Arc<AppState>>,
) -> Result<(), BulkRememberError> {
    let state: Arc<AppState> = Arc::clone(&ctx);

    if job.items.is_empty() {
        return Ok(());
    }

    let items_total = job.items.len();

    tracing::info!(
        "[bulk-remember] start: {} items owner={} epochs={}",
        items_total,
        &job.owner[..10.min(job.owner.len())],
        job.epochs,
    );

    let mut storage = state.wallet_storage.clone();
    let mut enqueued_count = 0usize;
    for item in job.items {
        let job_id = item.job_id.clone();
        let namespace = item.namespace.clone();
        let wallet_index = item.wallet_index;
        storage
            .push_request(wallet_job_request(WalletJob {
                wallet_index,
                congestion_requeues: 0,
                operation: WalletOperation::UploadAndTransfer {
                    encrypted_b64: item.encrypted_b64,
                    vector: item.vector,
                    importance: item.importance,
                    owner: job.owner.clone(),
                    namespace,
                    package_id: job.package_id.clone(),
                    account_id: job.account_id.clone(),
                    agent_public_key: job.agent_public_key.clone(),
                    remember_job_id: Some(job_id.clone()),
                    prepare_claim_token: None,
                    epochs: job.epochs,
                },
            }))
            .await
            .map_err(|e| {
                BulkRememberError::Internal(format!(
                    "failed to enqueue wallet job for {}: {}",
                    job_id, e
                ))
            })?;
        enqueued_count += 1;
    }

    tracing::info!(
        "[bulk-remember] fanout complete: owner={} total={} enqueued={}",
        &job.owner[..10.min(job.owner.len())],
        items_total,
        enqueued_count,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;
    use std::time::Duration;

    use sqlx::postgres::PgPoolOptions;

    use super::{
        backoff_duration, build_resume_transfer_job, classify_wallet_remember_handoff_failure,
        congestion_backoff_secs, congestion_resume_wallet, congestion_wait_message,
        consume_preparation_claim, durable_step_field, escalate_if_gas_pool_exhausted,
        gas_pool_exhaustion_threshold, is_walrus_package_version_mismatch, load_upload_journal,
        lock_outcome, mark_remember_job_failed, metadata_congestion_retry_job,
        parse_locked_object_info, parse_wal_balance_alert_info, persist_upload_journal,
        persist_uploaded_state, pin_journal_wallet, record_uploaded_metadata_error,
        recovery_seal_persistence, resume_needs_upload_slot, steer_uncommitted_upload_wallet,
        touch_uploaded_remember_job, update_remember_job_after_wallet_error,
        upload_journal_signer_committed, upload_lock_retry_delay, upload_lock_retry_wallet,
        upload_resume_disposition, upload_retry_backoff, wallet_index_for_upload_attempt,
        wallet_job_request, wallet_job_uses_followup_queue, DurableUploadBudget, JobUploadLock,
        LockDeferReason, LockOutcome, UploadResume, WalletJob, WalletJobAttemptInfo,
        WalletJobError, WalletOperation, CONGESTION_WAIT_ERROR_PREFIX, MAX_ATTEMPTS,
        MAX_CONGESTION_REQUEUES, WALLET_LOCK_POOL_ACQUIRE_TIMEOUT,
    };
    use crate::storage::walrus::{
        PreparedRegisterTransaction, UploadExecutionIdentity, UploadJournal,
    };

    #[test]
    fn durable_upload_budget_finishes_after_sponsorship_rebuilds() {
        for rebuilds in 0..=2 {
            let mut budget = DurableUploadBudget::new();
            assert!(budget.take_step(), "encode");
            assert!(budget.take_step(), "prepare");
            for _ in 0..rebuilds {
                assert!(budget.take_step(), "rejected register");
                assert!(budget.rebuild("sponsorship not found; rebuild".into()));
                assert!(budget.take_step(), "replacement prepare");
            }
            assert!(budget.take_step(), "register");
            assert!(budget.take_step(), "upload");
            assert!(
                budget.take_step(),
                "certify must fit in the same wallet attempt"
            );
        }
    }

    #[test]
    fn durable_upload_budget_bounds_repeated_resets_and_keeps_last_cause() {
        let mut budget = DurableUploadBudget::new();
        for _ in 0..2 {
            assert!(budget.take_step());
            assert!(budget.rebuild("previous reset".into()));
        }
        assert!(budget.take_step());
        assert!(!budget.rebuild("Enoki 404: Sponsored transaction not found".into()));
        let error = budget.exhausted("job-1");
        assert!(matches!(error, WalletJobError::Transient(_)));
        assert!(error.message().contains("after 2 rebuild(s)"));
        assert!(error
            .message()
            .contains("Enoki 404: Sponsored transaction not found"));

        let mut no_progress = DurableUploadBudget::new();
        let mut calls = 0;
        while no_progress.take_step() {
            calls += 1;
        }
        assert_eq!(
            calls, 6,
            "responses that never advance cannot extend the budget"
        );
    }

    /// The exact production error string from the object-lock incident
    /// (testnet job 3d607892…). Used to pin the classifier against real output.
    const PROD_OBJECT_LOCK_ERROR: &str =
        "walrus upload failed: Internal Error: walrus upload failed: \
Transaction is rejected as invalid by more than 1/3 of validators by stake (non-retriable). \
Non-retriable errors: [Object (0x36f866a4d400ec3dd5d8b0bac30cc36ab6d56172634a6b4dea9e2a554a43b08e, \
SequenceNumber(884613305), o#B61aVqEgDskxru255FTdzua2RxbbnhDMFxmQ8SCxvj3n) already locked by a \
different transaction: TransactionDigest(8bjFgRyXRRYwrzQapgEjpHnGhdfNDY7d6xA82BtHrp3F) \
{ k#80127c70.., k#81626d03.. } with 6842 stake].";

    /// The exact production error string from the dev-relayer write outage of
    /// 2026-09-17 (job d67d1fc2…, trace 12b3e920…). Every remember on dev failed
    /// with this shape and, classified Transient, burned its retry budget before
    /// dying — 0 blobs certified over the whole window.
    const PROD_REGISTER_SHAPE_ERROR: &str =
        "durable Walrus upload failed (503 Service Unavailable): \
{\"error\":\"registerTransaction must use a ValidDuring address-balance expiration\",\
\"code\":\"NO_SIDE_EFFECT\",\"traceId\":\"12b3e920-b94b-4100-bb35-fc0f0a1804e1\"}";

    static DB_SETUP_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

    #[test]
    fn a_spent_budget_is_terminal_for_every_retryable_error() {
        let spent = WalletJobAttemptInfo {
            current: MAX_ATTEMPTS as usize,
            max: MAX_ATTEMPTS as usize,
        };
        let low = WalletJobError::WalrusBalanceLow("wallet 0 WAL balance low".into());

        assert!(!spent.exhausted_by(&low));
        assert!(spent.retries_exhausted(&low));

        for err in [
            WalletJobError::Transient("durable Walrus upload failed (503)".into()),
            WalletJobError::UploadSlotCongestion("timed out waiting for upload slot".into()),
        ] {
            assert!(spent.retries_exhausted(&err), "{}", err.kind());
        }

        let mid = WalletJobAttemptInfo {
            current: 1,
            max: MAX_ATTEMPTS as usize,
        };
        assert!(!mid.retries_exhausted(&low));
        let permanent = WalletJobError::Permanent("registerTransaction digest mismatch".into());
        assert!(!spent.retries_exhausted(&permanent) && permanent.aborts_retries());
    }

    #[test]
    fn register_shape_rejection_is_permanent() {
        assert!(matches!(
            WalletJobError::classify_sidecar_error(PROD_REGISTER_SHAPE_ERROR),
            WalletJobError::Permanent(_)
        ));
    }

    #[test]
    fn every_register_shape_assertion_is_permanent() {
        for msg in [
            "registerTransaction must pay gas from the address balance",
            "registerTransaction has no WAL address-balance withdrawal",
            "registerTransaction resolved WAL from an owned coin",
            "registerTransaction resolved the relay tip from an owned SUI coin",
            "sponsored registerTransaction must use a distinct gas owner",
            "sponsored registerTransaction sender does not match the wallet",
            "registerTransaction gas owner does not match the journaled wallet",
            "registerTransaction.transactionBytes is not canonical base64",
            "registerTransaction digest mismatch: expected abc, got def",
            "registerTransaction contains invalid TransactionData: bad bytes",
        ] {
            assert!(
                matches!(
                    WalletJobError::classify_sidecar_error(msg),
                    WalletJobError::Permanent(_)
                ),
                "expected Permanent for {msg}"
            );
        }
    }

    /// `NO_SIDE_EFFECT` alone must stay retryable: retry/rpc.ts returns it for
    /// any pre-submission failure, including shared-infra blips that the next
    /// attempt succeeds through.
    #[test]
    fn shared_service_failure_uses_bounded_congestion_retry() {
        assert!(matches!(
            WalletJobError::classify_sidecar_error(
                "durable Walrus upload failed (503 Service Unavailable): \
{\"error\":\"fetch failed\",\"code\":\"NO_SIDE_EFFECT\",\
\"causeCode\":\"SHARED_SERVICE_UNAVAILABLE\"}"
            ),
            WalletJobError::UploadSlotCongestion(_)
        ));
    }

    #[test]
    fn shared_upload_retry_requires_a_structured_availability_code() {
        for body in [
            r#"{"code":"SHARED_SERVICE_UNAVAILABLE","error":"connection reset"}"#,
            r#"{"code":"NO_SIDE_EFFECT","causeCode":"SHARED_SERVICE_UNAVAILABLE"}"#,
        ] {
            let message = format!("durable Walrus upload failed (503 Service Unavailable): {body}");
            let error = WalletJobError::classify_sidecar_error(&message);
            assert!(matches!(error, WalletJobError::UploadSlotCongestion(_)));
            assert_eq!(
                congestion_resume_wallet(
                    3,
                    6,
                    WalletJobError::is_shared_upload_service_error(&message)
                ),
                3
            );
        }
        for body in [
            r#"{"code":"NO_SIDE_EFFECT","error":"MoveAbort code 503"}"#,
            r#"{"code":"DURABLE_SIDE_EFFECT_VERIFY_FAILED","causeCode":"SHARED_SERVICE_UNAVAILABLE"}"#,
            r#"{"error":"SHARED_SERVICE_UNAVAILABLE"}"#,
        ] {
            let message = format!("durable Walrus upload failed (503 Service Unavailable): {body}");
            assert!(!WalletJobError::is_shared_upload_service_error(&message));
        }
        assert!(!WalletJobError::is_shared_upload_service_error(
            "unrelated SHARED_SERVICE_UNAVAILABLE"
        ));
    }

    /// The shape check keys on the assertion text, so an unrelated message that
    /// merely mentions a sender mismatch must not be swallowed by it.
    #[test]
    fn unrelated_sender_mismatch_is_not_a_shape_rejection() {
        assert!(!WalletJobError::is_register_transaction_shape_error(
            "sponsor failed: sender does not match the wallet"
        ));
    }

    /// The assertion must follow the `registerTransaction` token, not merely
    /// share a message with it. The classified text is a wrapper that can
    /// carry a nested cause, so a transient failure naming the register step
    /// in one clause and a broad phrase in another must stay retryable —
    /// read as Permanent it dies on attempt 1 and the fact is lost.
    #[test]
    fn a_broad_phrase_elsewhere_in_the_message_is_not_a_shape_rejection() {
        for msg in [
            "durable Walrus upload failed (503 Service Unavailable): \
{\"error\":\"timed out submitting registerTransaction\",\"code\":\"NO_SIDE_EFFECT\",\
\"cause\":\"checkpoint digest mismatch on the fullnode\"}",
            "registerTransaction step: upstream RPC error, sender does not match \
the checkpoint it replied about",
        ] {
            assert!(
                !WalletJobError::is_register_transaction_shape_error(msg),
                "expected retryable for {msg}"
            );
            assert!(
                matches!(
                    WalletJobError::classify_sidecar_error(msg),
                    WalletJobError::Transient(_)
                ),
                "expected Transient for {msg}"
            );
        }
    }

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://memwal:memwal_secret@localhost:5432/memwal".into())
    }

    async fn test_pool() -> sqlx::PgPool {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&test_database_url())
            .await
            .unwrap();

        let _guard = DB_SETUP_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        sqlx::raw_sql(include_str!("../migrations/005_remember_jobs.sql"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!(
            "../migrations/012_remember_write_idempotency.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql(include_str!(
            "../migrations/013_remember_write_idempotency_index.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql(include_str!("../migrations/014_storage_reservations.sql"))
            .execute(&pool)
            .await
            .unwrap();

        pool
    }

    #[test]
    fn classify_object_lock_as_transient() {
        let cases = [
            "ObjectLockedAtVersion { object_id: 0xabc, version: 42 }",
            "object is locked at version 17",
            "ObjectLocked: 0x1234",
        ];
        for msg in cases {
            assert!(
                !WalletJobError::classify_sidecar_error(msg).is_permanent(),
                "expected transient for: {}",
                msg
            );
            assert!(
                !WalletJobError::classify_sidecar_error(msg).aborts_retries(),
                "recoverable lock-at-version should stay retryable: {}",
                msg
            );
        }
    }

    #[test]
    fn classify_prod_equivocation_as_object_locked_until_epoch() {
        let classified = WalletJobError::classify_sidecar_error(PROD_OBJECT_LOCK_ERROR);
        assert!(
            matches!(classified, WalletJobError::ObjectLockedUntilEpoch(_)),
            "prod equivocation error must classify as ObjectLockedUntilEpoch, got {}",
            classified.kind()
        );
        // It aborts retries (doesn't burn the wallet budget) but is NOT
        // "permanent" — the same input can succeed in a later epoch.
        assert!(classified.aborts_retries());
        assert!(!classified.is_permanent());
    }

    #[test]
    fn object_locked_until_epoch_aborts_apalis() {
        let err = WalletJobError::ObjectLockedUntilEpoch("locked".to_string());
        assert!(matches!(
            err.into_apalis_error(),
            apalis::prelude::Error::Abort(_)
        ));
    }

    /// The exact production error string from the 2026-06-10 congestion
    /// incident — the sidecar's WalrusUploadLimitError wrapped by the Rust
    /// transport layers.
    const PROD_CONGESTION_ERROR: &str = "walrus upload failed: Internal Error: \
        walrus upload failed: timed out waiting for wallet 3 upload slot";

    #[test]
    fn classify_prod_congestion_error_as_upload_slot_congestion() {
        let classified = WalletJobError::classify_sidecar_error(PROD_CONGESTION_ERROR);
        assert!(
            matches!(classified, WalletJobError::UploadSlotCongestion(_)),
            "prod congestion error must classify as UploadSlotCongestion, got {}",
            classified.kind()
        );
        // Congestion is retryable — it must neither abort nor read as
        // permanent; the caller decides between delayed requeue and the
        // normal Apalis track.
        assert!(!classified.aborts_retries());
        assert!(!classified.is_permanent());

        // The global-limiter variant of the same timeout classifies too.
        assert!(matches!(
            WalletJobError::classify_sidecar_error(
                "walrus upload failed: timed out waiting for global upload slot"
            ),
            WalletJobError::UploadSlotCongestion(_)
        ));
    }

    #[test]
    fn metadata_transport_failure_preserves_bounded_recovery_budget() {
        let msg = "Internal Error: Sidecar walrus/set-metadata-batch request failed: error sending request for url (http://localhost:9000/walrus/set-metadata-batch)";
        assert!(matches!(
            WalletJobError::classify_sidecar_error(msg),
            WalletJobError::UploadSlotCongestion(_)
        ));
        let mismatch =
            "walrus set-metadata-batch failed: Transaction was not signed by the correct sender";
        assert!(!WalletJobError::is_sidecar_upload_transport_error(mismatch));
    }

    #[test]
    fn classify_dropped_upload_sidecar_connection_as_congestion() {
        let transport = "Internal Error: durable Walrus upload request failed: \
            error sending request for url (http://localhost:9000/walrus/upload-step-v3)";
        let classified = WalletJobError::classify_sidecar_error(transport);
        assert!(
            matches!(classified, WalletJobError::UploadSlotCongestion(_)),
            "a dropped upload-step connection is congestion, got {}",
            classified.kind()
        );
        assert!(!classified.aborts_retries());

        let slot = "Internal Error: durable Walrus upload failed (503 Service Unavailable): \
            {\"error\":\"timed out waiting for wallet 1 upload slot\",\"code\":\"NO_SIDE_EFFECT\"}";
        assert!(matches!(
            WalletJobError::classify_sidecar_error(slot),
            WalletJobError::UploadSlotCongestion(_)
        ));

        // A transport error that is not the upload sidecar stays on the
        // normal retry track.
        assert!(!matches!(
            WalletJobError::classify_sidecar_error(
                "error sending request for url (https://example.com/other)"
            ),
            WalletJobError::UploadSlotCongestion(_)
        ));

        // The source chain is appended after Display. It must stay congestion,
        // and both the raw failure and the waiting prefix are infrastructure
        // so a poller never sees the localhost URL.
        let with_source = format!("{transport}: connection reset by peer");
        assert!(matches!(
            WalletJobError::classify_sidecar_error(&with_source),
            WalletJobError::UploadSlotCongestion(_)
        ));
        assert!(WalletJobError::is_infrastructure_funding_error(
            &with_source
        ));
        assert!(WalletJobError::is_infrastructure_funding_error(
            &congestion_wait_message(&with_source)
        ));
        assert!(!WalletJobError::is_infrastructure_funding_error(
            "error sending request for url (https://example.com/other)"
        ));
    }

    #[test]
    fn a_dropped_upload_connection_resumes_the_same_wallet() {
        assert_eq!(congestion_resume_wallet(4, 16, true), 4);
        assert_eq!(congestion_resume_wallet(15, 16, false), 0);
        assert_eq!(congestion_resume_wallet(0, 0, false), 0);
    }

    #[test]
    fn a_congestion_resume_keeps_a_prepared_register_signer() {
        let prepared = UploadJournal {
            wallet_index: 4,
            wallet_address: Some("0xabc".into()),
            execution_identity: None,
            resume_step: Some(serde_json::json!({"step": "encoded"})),
            register_transaction: Some(PreparedRegisterTransaction {
                transaction_bytes: "aa".into(),
                signature: "bb".into(),
                digest: "cc".into(),
                sponsor_digest: None,
            }),
        };
        assert!(pin_journal_wallet(&prepared, 1));
        // A normal retry has the same hazard: the prepared bytes name a signer.
        assert!(pin_journal_wallet(&prepared, 0));
        assert!(!upload_journal_signer_committed(&prepared));
        let mut addressed = prepared.clone();
        addressed.register_transaction = None;
        assert!(pin_journal_wallet(&addressed, 0));
        let mut encoded_only = prepared.clone();
        encoded_only.wallet_address = None;
        encoded_only.register_transaction = None;
        assert!(!pin_journal_wallet(&encoded_only, 0));
        assert!(pin_journal_wallet(&encoded_only, 1));
        let fresh = UploadJournal {
            wallet_index: 4,
            wallet_address: None,
            execution_identity: None,
            resume_step: None,
            register_transaction: None,
        };
        assert!(!pin_journal_wallet(&fresh, 0));
        assert!(!pin_journal_wallet(&fresh, 1));
    }

    #[test]
    fn wallet_mapping_mismatch_stops_the_retry_budget() {
        let msg = "Internal Error: durable Walrus upload failed (409 Conflict): \
            {\"error\":\"keyIndex no longer maps to the journaled wallet\",\
            \"code\":\"WALLET_MAPPING_MISMATCH\",\
            \"expectedWalletAddress\":\"0xaa\",\"actualWalletAddress\":\"0x9b\"}";
        let classified = WalletJobError::classify_sidecar_error(msg);
        assert!(
            matches!(classified, WalletJobError::Permanent(_)),
            "a journaled-wallet mismatch is deterministic, got {}",
            classified.kind()
        );
        assert!(classified.aborts_retries());
    }

    #[test]
    fn a_lost_upload_response_body_is_the_same_transport_error() {
        let msg = "Internal Error: durable Walrus upload response failed for http://localhost:9000/walrus/upload-step-v3: error decoding response body";
        assert!(WalletJobError::is_sidecar_upload_transport_error(msg));
        assert!(matches!(
            WalletJobError::classify_sidecar_error(msg),
            WalletJobError::UploadSlotCongestion(_)
        ));
    }

    #[test]
    fn congestion_does_not_classify_unrelated_timeouts() {
        // A generic RPC timeout must stay on the normal Transient track —
        // only the sidecar's upload-slot acquire timeout is congestion.
        let classified =
            WalletJobError::classify_sidecar_error("walrus upload failed: request timeout");
        assert!(!matches!(
            classified,
            WalletJobError::UploadSlotCongestion(_)
        ));
    }

    #[test]
    fn durable_upload_preserves_preclassified_errors() {
        let permanent = durable_step_field(&serde_json::json!({}), "blobId").unwrap_err();
        assert!(matches!(permanent, WalletJobError::Permanent(_)));
        assert!(permanent.aborts_retries());
        assert_eq!(
            permanent.message(),
            "durable upload step is missing required field blobId"
        );

        let sidecar = WalletJobError::classify_sidecar_error(PROD_CONGESTION_ERROR);
        assert!(matches!(sidecar, WalletJobError::UploadSlotCongestion(_)));
    }

    #[test]
    fn lock_defer_backoff_matches_documented_schedule() {
        // 1→2s, 2→4s, 3→8s, 4→16s, 5→32s — see backoff_duration's doc comment.
        // Wired into the lock-contention Defer path so a job that repeatedly
        // loses the per-job advisory lock gets real spacing between attempts
        // instead of exhausting MAX_ATTEMPTS in milliseconds.
        assert_eq!(backoff_duration(1), std::time::Duration::from_secs(2));
        assert_eq!(backoff_duration(2), std::time::Duration::from_secs(4));
        assert_eq!(backoff_duration(3), std::time::Duration::from_secs(8));
        assert_eq!(backoff_duration(4), std::time::Duration::from_secs(16));
        assert_eq!(backoff_duration(5), std::time::Duration::from_secs(32));
    }

    #[test]
    fn upload_retry_backs_off_between_attempts() {
        // The production failure this exists for: attempts 2..5 against Walrus
        // 503 "Too Many Requests" inside one second, four wallet rotations
        // that never had a chance to land. Each attempt must now be spaced.
        let rate_limited = WalletJobError::Transient(
            "durable Walrus upload failed (503 Service Unavailable): {\"error\":\"Too Many Requests\"}"
                .into(),
        );
        for attempt in 1..5usize {
            assert_eq!(
                upload_retry_backoff(
                    &rate_limited,
                    WalletJobAttemptInfo {
                        current: attempt,
                        max: 5
                    }
                ),
                Some(backoff_duration(attempt as u32)),
                "attempt {attempt} should wait before the next one",
            );
        }
    }

    #[test]
    fn upload_retry_does_not_back_off_when_nothing_follows() {
        let transient = WalletJobError::Transient("upstream hiccup".into());
        // Final attempt: sleeping only delays the failure already being reported.
        assert_eq!(
            upload_retry_backoff(&transient, WalletJobAttemptInfo { current: 5, max: 5 }),
            None
        );
        // Aborting errors never retry, so spacing them buys nothing.
        let aborting = WalletJobError::GasPoolExhausted("balance::split ENotEnough".into());
        assert!(aborting.aborts_retries());
        assert_eq!(
            upload_retry_backoff(&aborting, WalletJobAttemptInfo { current: 1, max: 5 }),
            None
        );
    }

    #[test]
    fn congestion_backoff_is_minutes_scale_and_capped() {
        assert_eq!(congestion_backoff_secs(0), 30);
        assert_eq!(congestion_backoff_secs(1), 60);
        assert_eq!(congestion_backoff_secs(2), 120);
        assert_eq!(congestion_backoff_secs(3), 240);
        assert_eq!(congestion_backoff_secs(4), 480);
        assert_eq!(congestion_backoff_secs(5), 600);
        assert_eq!(congestion_backoff_secs(40), 600); // shift-safe at silly inputs

        // The whole requeue budget must outlive a realistic backlog drain
        // (the 2026-06-10 queue needed ~8 minutes at ~16 uploads/min).
        let total: u64 = (0..MAX_CONGESTION_REQUEUES)
            .map(congestion_backoff_secs)
            .sum();
        assert!(
            total >= 20 * 60,
            "congestion requeue budget should span >= 20 minutes, got {}s",
            total
        );
    }

    #[test]
    fn lock_pool_miss_retries_without_the_relay_backoff() {
        assert_eq!(
            WALLET_LOCK_POOL_ACQUIRE_TIMEOUT,
            std::time::Duration::from_secs(3)
        );
        assert_eq!(upload_lock_retry_delay(LockDeferReason::Pool, 0), 1);
        assert_eq!(upload_lock_retry_delay(LockDeferReason::Pool, 4), 1);
        assert_eq!(upload_lock_retry_wallet(LockDeferReason::Pool, 4, 17), 4);
        // The other attempt is actually uploading. That wait stays minutes-scale.
        assert_eq!(upload_lock_retry_delay(LockDeferReason::SameJob, 0), 30);
        assert_eq!(upload_lock_retry_delay(LockDeferReason::SameJob, 1), 60);
        assert_eq!(
            upload_lock_retry_wallet(LockDeferReason::SameJob, 16, 17),
            0
        );
    }

    #[test]
    fn resume_paths_do_not_take_the_upload_slot() {
        assert!(resume_needs_upload_slot(&UploadResume::Upload));
        assert!(!resume_needs_upload_slot(&UploadResume::Indeterminate));
        assert!(!resume_needs_upload_slot(&UploadResume::AlreadyDone {
            blob_id: "blob".into(),
        }));
        assert!(!resume_needs_upload_slot(&UploadResume::ResumeTransfer {
            blob_id: "blob".into(),
            blob_object_id: "0xobj".into(),
        }));
        assert!(!resume_needs_upload_slot(&UploadResume::ResumeIndex {
            blob_id: "blob".into(),
        }));
    }

    #[test]
    fn wallet_job_payload_without_congestion_field_deserializes() {
        // Jobs already queued in Postgres before the field existed must keep
        // deserializing (serde default = 0).
        let job = WalletJob {
            wallet_index: 2,
            congestion_requeues: 3,
            operation: WalletOperation::FinalizeUploadedBlob {
                owner: "0xabc".to_string(),
                namespace: "default".to_string(),
                remember_job_id: Some("job-1".to_string()),
                blob_id: "blob".to_string(),
                vector: vec![0.1],
                blob_size_bytes: 1,
                importance: 0.5,
                agent_id: None,
                package_id: None,
                end_epoch: None,
            },
        };
        let mut value = serde_json::to_value(&job).expect("serialize");
        value
            .as_object_mut()
            .expect("object")
            .remove("congestion_requeues");
        let legacy: WalletJob = serde_json::from_value(value).expect("legacy payload");
        assert_eq!(legacy.congestion_requeues, 0);
        assert_eq!(legacy.wallet_index, 2);
    }

    #[test]
    fn object_locked_until_epoch_does_not_exhaust_wallet_budget() {
        // At the final attempt, an object-lock error must NOT trigger the
        // "exhausted retries" alert — that gate is what produced the
        // misleading prod alert.
        let err = WalletJobError::ObjectLockedUntilEpoch("locked".to_string());
        assert!(!WalletJobAttemptInfo { current: 5, max: 5 }.exhausted_by(&err));
    }

    #[test]
    fn classify_equivocation_phrase_variants() {
        // Lock-specific anchors classify on their own.
        for msg in [
            "object 0xabc already locked by a different transaction: TransactionDigest(d)",
            "the input object is equivocated",
            "equivocation detected on gas coin",
            "object reserved for another transaction",
            // Corroborated: non-retriable preamble + object-lock evidence.
            "rejected as invalid by more than 1/3 of validators by stake (non-retriable). \
             Object (0xabc, SequenceNumber(1)) already locked",
        ] {
            assert!(
                matches!(
                    WalletJobError::classify_sidecar_error(msg),
                    WalletJobError::ObjectLockedUntilEpoch(_)
                ),
                "expected ObjectLockedUntilEpoch for: {}",
                msg
            );
        }
    }

    #[test]
    fn bare_non_retriable_is_not_an_object_lock() {
        // The "non-retriable" / ">1/3 of validators" preamble alone is not
        // lock-specific. Without object-lock evidence it must NOT be classified
        // as ObjectLockedUntilEpoch.
        // - generic invalid tx (no MoveAbort) → default Transient
        let invalid = "Transaction is rejected as invalid by more than 1/3 of validators by stake (non-retriable)";
        assert!(matches!(
            WalletJobError::classify_sidecar_error(invalid),
            WalletJobError::Transient(_)
        ));
        // - generic non-retriable MoveAbort → Permanent (not a lock)
        let move_abort = "MoveAbort in 1st command, abort code: 3 — non-retriable";
        assert!(matches!(
            WalletJobError::classify_sidecar_error(move_abort),
            WalletJobError::Permanent(_)
        ));
    }

    #[test]
    fn equivocation_does_not_regress_recoverable_classes() {
        // EWrongVersion and a lone balance::split ENotEnough must both stay
        // Transient (recoverable) — neither is swept into the object-lock abort
        // path. balance::split only escalates to GasPoolExhausted at the pool
        // level (see gas_pool_* tests below), not on a single occurrence.
        let balance = "Enoki dry run failed: MoveAbort(0x2::balance, split, 2)";
        let ewrong = "MoveAbort in 1st command, abort code: 1, in '0xabc::system::inner_mut'";
        assert!(matches!(
            WalletJobError::classify_sidecar_error(balance),
            WalletJobError::Transient(_)
        ));
        assert!(matches!(
            WalletJobError::classify_sidecar_error(ewrong),
            WalletJobError::Transient(_)
        ));
    }

    #[test]
    fn walrus_register_destroy_zero_is_transient() {
        // Verbatim prod error (issue #351): the register PTB over-funds the WAL
        // payment from a stale cached price and `coin::destroy_zero` aborts with
        // ENonZero. Must be Transient (retry re-reads the live price), NOT swept
        // into the MoveAbort→Permanent catch that would Dead-mark every write.
        let destroy_zero = "walrus upload failed: Enoki API error (400): {\"errors\":[{\"code\":\"dry_run_failed\",\"message\":\"Dry run failed, could not automatically determine a budget: MoveAbort(MoveLocation { module: ModuleId { address: 0000000000000000000000000000000000000000000000000000000000000002, name: Identifier(\\\"balance\\\") }, function: 9, instruction: 8, function_name: Some(\\\"destroy_zero\\\") }, 0) in command 2\"}]}";
        assert!(WalletJobError::is_walrus_wal_payment_price_abort(
            destroy_zero
        ));
        let classified = WalletJobError::classify_sidecar_error(destroy_zero);
        assert!(matches!(classified, WalletJobError::Transient(_)));
        assert!(!classified.is_permanent());
        assert!(!classified.aborts_retries());
    }

    #[test]
    fn parse_locked_object_info_from_prod_error() {
        let info = parse_locked_object_info(PROD_OBJECT_LOCK_ERROR);
        assert_eq!(
            info.object_id.as_deref(),
            Some("0x36f866a4d400ec3dd5d8b0bac30cc36ab6d56172634a6b4dea9e2a554a43b08e")
        );
        assert_eq!(info.version.as_deref(), Some("884613305"));
        assert_eq!(
            info.locking_digest.as_deref(),
            Some("8bjFgRyXRRYwrzQapgEjpHnGhdfNDY7d6xA82BtHrp3F")
        );
    }

    #[test]
    fn parse_locked_object_info_tolerates_missing_tokens() {
        let info = parse_locked_object_info("some unrelated error with no object tokens");
        assert!(info.object_id.is_none());
        assert!(info.version.is_none());
        assert!(info.locking_digest.is_none());
    }

    #[test]
    fn classify_move_abort_as_permanent() {
        for msg in [
            "MoveAbort(MoveLocation { module: ... }, 1)",
            "Move abort at code 7",
        ] {
            assert!(
                WalletJobError::classify_sidecar_error(msg).is_permanent(),
                "expected permanent for: {}",
                msg
            );
        }
    }

    #[test]
    fn classify_postgres_index_tuple_size_as_permanent() {
        for message in [
            "Failed to insert vector: index row requires 21816 bytes, maximum size is 8191",
            "index row size 3000 exceeds btree version 4 maximum 2704",
            "index tuple too large for index idx_vector_entries_owner_ns",
        ] {
            let classified = WalletJobError::classify_sidecar_error(message);
            assert!(matches!(classified, WalletJobError::Permanent(_)));
            assert!(classified.aborts_retries());
        }
    }

    const BALANCE_SPLIT_ERR: &str = "walrus upload failed: Enoki API error (400): {\"errors\":[{\"code\":\"dry_run_failed\",\"message\":\"Dry run failed: MoveAbort(MoveLocation { module: 0x2::balance, function_name: Some(\\\"split\\\") }, 2)\"}]}";
    const LOW_WAL_BALANCE_ERR: &str =
        "walrus upload failed: Insufficient balance of 0x356a26eb9e012a68958082340d4c4116e7f55615cf27affcff209cf0ae544f59::wal::WAL for owner 0xabc...def. Required: 64367730, Available: 10708877";

    #[test]
    fn parse_wal_balance_alert_info_extracts_required_and_available() {
        let parsed =
            parse_wal_balance_alert_info(LOW_WAL_BALANCE_ERR).expect("expected low WAL signal");
        assert_eq!(parsed.required, Some(64367730));
        assert_eq!(parsed.available, 10708877);
    }

    #[test]
    fn classify_low_wal_balance_is_dedicated_transient() {
        let classified = WalletJobError::classify_sidecar_error(LOW_WAL_BALANCE_ERR);
        assert!(matches!(classified, WalletJobError::WalrusBalanceLow(_)));
        assert!(!classified.aborts_retries());
        assert!(!classified.is_permanent());
        assert_eq!(classified.kind(), "walrus_balance_low");
    }

    #[test]
    fn low_wal_balance_does_not_trigger_exhausted_retries_alert_gate() {
        let classified = WalletJobError::classify_sidecar_error(LOW_WAL_BALANCE_ERR);
        assert!(!WalletJobAttemptInfo { current: 5, max: 5 }.exhausted_by(&classified));
    }

    #[test]
    fn classify_balance_split_is_retriable_transient_by_default() {
        // A single balance::split ENotEnough is Transient (retriable) so Apalis
        // rotates onto another pool wallet — it must NOT abort on its own.
        for msg in [BALANCE_SPLIT_ERR, "move abort during balance split"] {
            let classified = WalletJobError::classify_sidecar_error(msg);
            assert!(
                matches!(classified, WalletJobError::Transient(_)),
                "expected transient for: {}",
                msg
            );
            assert!(!classified.aborts_retries(), "must retry: {}", msg);
            assert!(WalletJobError::is_gas_pool_budget_error(msg));
        }
    }

    #[test]
    fn gas_selection_insufficient_sui_is_pool_budget_error() {
        let msg = "Internal Error: durable Walrus upload failed (503 Service Unavailable): Unable to perform gas selection due to insufficient SUI balance";
        assert!(WalletJobError::is_gas_pool_budget_error(msg));
        let classified = WalletJobError::classify_sidecar_error(msg);
        assert!(matches!(classified, WalletJobError::Transient(_)));
        assert!(!WalletJobError::is_gas_pool_budget_error(
            LOW_WAL_BALANCE_ERR
        ));
    }

    #[test]
    fn gas_pool_threshold_tracks_pool_then_caps_at_max_attempts() {
        assert_eq!(gas_pool_exhaustion_threshold(1, 5), 1); // single wallet → escalate immediately
        assert_eq!(gas_pool_exhaustion_threshold(2, 5), 2); // try both wallets first
        assert_eq!(gas_pool_exhaustion_threshold(10, 5), 5); // capped by max attempts
        assert_eq!(gas_pool_exhaustion_threshold(0, 5), 1); // never 0
    }

    #[test]
    fn wallet_retry_selection_walks_pool_from_enqueued_wallet() {
        // This selection is per-job and does not depend on the global KeyPool
        // cursor, so concurrent jobs cannot consume this job's next wallet.
        let picked: Vec<_> = (1..=5)
            .map(|attempt| wallet_index_for_upload_attempt(3, attempt, 4).unwrap())
            .collect();
        assert_eq!(picked, vec![3, 0, 1, 2, 3]);
    }

    fn empty_journal(wallet_index: usize) -> UploadJournal {
        UploadJournal {
            wallet_index,
            wallet_address: None,
            execution_identity: None,
            resume_step: None,
            register_transaction: None,
        }
    }

    fn prepared_register() -> PreparedRegisterTransaction {
        PreparedRegisterTransaction {
            transaction_bytes: "aa".into(),
            signature: "bb".into(),
            digest: "cc".into(),
            sponsor_digest: None,
        }
    }

    #[test]
    fn uncommitted_upload_moves_onto_a_free_wallet() {
        let mut encoded = empty_journal(4);
        encoded.wallet_address = Some("0xold".into());
        encoded.resume_step = Some(serde_json::json!({
            "step": "encoded",
            "blobId": "blob",
            "rootHash": "root",
            "unencodedSize": 4
        }));
        encoded.register_transaction = Some(prepared_register());
        assert!(!upload_journal_signer_committed(&encoded));
        assert!(steer_uncommitted_upload_wallet(&mut encoded, 12));
        assert_eq!(encoded.wallet_index, 12);
        assert!(encoded.wallet_address.is_none());
        assert!(encoded.register_transaction.is_none());
        assert!(encoded.resume_step.is_some());
        // Already there: keep a prepared register signed by this wallet.
        encoded.register_transaction = Some(prepared_register());
        assert!(!steer_uncommitted_upload_wallet(&mut encoded, 12));
        assert!(encoded.register_transaction.is_some());
    }

    #[test]
    fn committed_upload_stays_on_its_signer() {
        for step in ["registered", "uploaded", "certified"] {
            let mut journal = empty_journal(5);
            journal.resume_step = Some(serde_json::json!({ "step": step }));
            assert!(upload_journal_signer_committed(&journal));
            assert!(!steer_uncommitted_upload_wallet(&mut journal, 14));
            assert_eq!(journal.wallet_index, 5);
        }
    }

    #[test]
    fn metadata_recovery_requires_complete_v1_new_seal_fence() {
        assert!(matches!(
            recovery_seal_persistence(None, "0xregistry", None, None),
            Err(WalletJobError::Permanent(_))
        ));
        assert!(matches!(
            recovery_seal_persistence(Some("0xaccount"), "", Some("0xpackage"), Some("ciphertext"),),
            Err(WalletJobError::Permanent(_))
        ));
        assert!(matches!(
            recovery_seal_persistence(
                Some("0xaccount"),
                "0xregistry",
                Some("0xpackage"),
                Some("ciphertext"),
            ),
            Ok(crate::storage::walrus::SealPersistence::V1New { .. })
        ));
    }

    #[test]
    fn gas_pool_one_bad_wallet_keeps_retrying_onto_healthy_wallet() {
        // pool of 2: the first wallet's balance::split must stay retriable so the
        // job rotates onto the second (healthy) wallet instead of failing.
        let classified = WalletJobError::classify_sidecar_error(BALANCE_SPLIT_ERR);
        let after = escalate_if_gas_pool_exhausted(
            classified, /*attempt*/ 1, /*max*/ 5, /*pool*/ 2,
        );
        assert!(
            matches!(after, WalletJobError::Transient(_)) && !after.aborts_retries(),
            "single bad wallet must keep retrying, got {:?}",
            after
        );
    }

    #[test]
    fn gas_pool_all_wallets_failed_escalates_and_aborts() {
        // pool of 2, both wallets hit balance::split → at attempt 2 we have tried
        // every candidate wallet → escalate to an aborting GasPoolExhausted.
        let classified = WalletJobError::classify_sidecar_error(BALANCE_SPLIT_ERR);
        let after = escalate_if_gas_pool_exhausted(
            classified, /*attempt*/ 2, /*max*/ 5, /*pool*/ 2,
        );
        assert!(
            matches!(after, WalletJobError::GasPoolExhausted(_)),
            "exhausted pool must escalate, got {:?}",
            after
        );
        assert!(after.aborts_retries());
        assert!(!after.is_permanent());
        assert_eq!(after.kind(), "gas_pool_exhausted");
    }

    #[test]
    fn gas_pool_pinned_wallet_escalates_immediately() {
        // Metadata-transfer recovery is pinned to the blob owner wallet, so
        // there are no alternate pool candidates to try.
        let classified = WalletJobError::classify_sidecar_error(BALANCE_SPLIT_ERR);
        let after =
            escalate_if_gas_pool_exhausted(classified, /*attempt*/ 1, /*max*/ 5, 1);
        assert!(matches!(after, WalletJobError::GasPoolExhausted(_)));
    }

    #[test]
    fn escalation_ignores_non_gas_budget_transient() {
        // A generic transient (e.g. timeout) must never be escalated to the
        // gas-pool abort path, even past the threshold.
        let other = WalletJobError::Transient("network timeout".into());
        let after = escalate_if_gas_pool_exhausted(other, 5, 5, 2);
        assert!(matches!(after, WalletJobError::Transient(_)));
    }

    #[test]
    fn classify_walrus_version_mismatch_as_transient() {
        // The sidecar refreshes the cached @mysten/walrus client on EWrongVersion;
        // Apalis must retry against the refreshed client instead of marking Dead.
        for msg in [
            // JSON-RPC production format (common): only "abort code: 1", no symbolic name
            "walrus upload failed: MoveAbort in 1st command, abort code: 1, in '0xc1b6::system::inner_mut' (instruction 0)",
            // gRPC/GraphQL: symbolic EWrongVersion
            "walrus upload failed: MoveAbort in 1st command, 'EWrongVersion': 1, in '0xc1b6::system::inner_mut' (line 42)",
            // Defensive: lowercase + only symbolic name
            "moveabort ewrongversion",
        ] {
            assert!(
                !WalletJobError::classify_sidecar_error(msg).is_permanent(),
                "expected transient for: {}",
                msg
            );
        }
    }

    #[test]
    fn classify_non_walrus_moveabort_stays_permanent() {
        // The walrus-specific carve-out must NOT widen — other modules' MoveAborts
        // still classify Permanent (the existing contract for non-retryable errors).
        for msg in [
            // generic move abort with no walrus-specific anchors
            "MoveAbort in 1st command, abort code: 5, in '0x2::coin::join' (instruction 0)",
            "MoveAbort(MoveLocation { module: 0x3::foo }, 1)",
        ] {
            assert!(
                WalletJobError::classify_sidecar_error(msg).is_permanent(),
                "expected permanent for: {}",
                msg
            );
        }
    }

    #[test]
    fn walrus_version_mismatch_detector_pattern() {
        // Mirrors the sidecar's isWalrusPackageVersionMismatch; keep both in sync.
        assert!(is_walrus_package_version_mismatch(
            "MoveAbort in 1st command, abort code: 1, in '0xc1b6::system::inner_mut'"
        ));
        assert!(is_walrus_package_version_mismatch(
            "MoveAbort 'EWrongVersion': 1"
        ));
        // Lowercase / case-insensitive matching
        assert!(is_walrus_package_version_mismatch(
            "moveabort ewrongversion"
        ));
        // Anchors required — bare tokens alone don't match
        assert!(!is_walrus_package_version_mismatch("EWrongVersion"));
        assert!(!is_walrus_package_version_mismatch(
            "::system::inner_mut without context"
        ));
        // Balance-split MoveAbort (the existing handler's domain) does not match
        assert!(!is_walrus_package_version_mismatch(
            "MoveAbort(MoveLocation { module: 0x2::balance, function_name: Some(\"split\") }, 2)"
        ));
        assert!(!is_walrus_package_version_mismatch(""));
    }

    #[test]
    fn classify_network_errors_as_transient() {
        for msg in [
            "sidecar timeout",
            "503 service unavailable",
            "ECONNRESET",
            "insufficient gas",
            "Enoki API error (400): {\"errors\":[{\"code\":\"expired\",\"message\":\"Sponsored transaction has expired\"}]}",
        ] {
            assert!(
                !WalletJobError::classify_sidecar_error(msg).is_permanent(),
                "expected transient for: {}",
                msg
            );
        }
    }

    #[test]
    fn display_includes_classification_tag() {
        let perm = WalletJobError::Permanent("locked".to_string());
        let trans = WalletJobError::Transient("network".to_string());
        assert!(perm.to_string().contains("permanent"));
        assert!(trans.to_string().contains("transient"));
    }

    #[test]
    fn permanent_errors_abort_apalis_retries() {
        let error = WalletJobError::Permanent("move abort".to_string()).into_apalis_error();
        assert!(matches!(error, apalis::prelude::Error::Abort(_)));
    }

    #[test]
    fn transient_errors_remain_retryable() {
        let error = WalletJobError::Transient("timeout".to_string()).into_apalis_error();
        assert!(matches!(error, apalis::prelude::Error::Failed(_)));
    }

    #[test]
    fn alert_gate_only_opens_on_final_transient_attempt() {
        let transient = WalletJobError::Transient("timeout".to_string());
        assert!(!WalletJobAttemptInfo { current: 4, max: 5 }.exhausted_by(&transient));
        assert!(WalletJobAttemptInfo { current: 5, max: 5 }.exhausted_by(&transient));
    }

    #[test]
    fn alert_gate_stays_closed_for_permanent_errors() {
        let permanent = WalletJobError::Permanent("move abort".to_string());
        assert!(!WalletJobAttemptInfo { current: 5, max: 5 }.exhausted_by(&permanent));
    }

    #[test]
    fn wallet_job_request_sets_explicit_max_attempts() {
        let req = wallet_job_request(WalletJob {
            wallet_index: 0,
            congestion_requeues: 0,
            operation: WalletOperation::FinalizeUploadedBlob {
                owner: "0xowner".to_string(),
                namespace: "default".to_string(),
                remember_job_id: None,
                blob_id: "blob".to_string(),
                vector: vec![],
                blob_size_bytes: 0,
                importance: crate::services::extractor::IMPORTANCE_STANDARD,
                agent_id: None,
                package_id: None,
                end_epoch: None,
            },
        });

        assert_eq!(req.parts.context.max_attempts(), MAX_ATTEMPTS as i32);
        assert_eq!(*req.parts.context.priority(), 2);
    }

    #[test]
    fn wallet_job_priority_finishes_finalize_before_metadata() {
        let upload = WalletJob {
            wallet_index: 1,
            congestion_requeues: 0,
            operation: WalletOperation::UploadAndTransfer {
                encrypted_b64: String::new(),
                vector: vec![],
                importance: 0.0,
                owner: String::new(),
                namespace: String::new(),
                package_id: String::new(),
                account_id: String::new(),
                agent_public_key: None,
                remember_job_id: None,
                prepare_claim_token: None,
                epochs: 1,
            },
        };
        let metadata_job = metadata_congestion_retry_job(
            4,
            2,
            "0xblob",
            "0xowner",
            "ns",
            None,
            None,
            Some("job"),
            Some("blob"),
            None,
            Some(1),
            0.5,
            None,
            None,
            None,
            None,
        );
        let finalize = WalletJob {
            wallet_index: 4,
            congestion_requeues: 0,
            operation: WalletOperation::FinalizeUploadedBlob {
                owner: "0xowner".into(),
                namespace: "ns".into(),
                remember_job_id: Some("job".into()),
                blob_id: "blob".into(),
                vector: vec![0.1],
                blob_size_bytes: 1,
                importance: 0.5,
                agent_id: None,
                package_id: None,
                end_epoch: None,
            },
        };

        assert!(!wallet_job_uses_followup_queue(&upload.operation));
        assert!(wallet_job_uses_followup_queue(&metadata_job.operation));
        assert!(wallet_job_uses_followup_queue(&finalize.operation));

        let upload = wallet_job_request(upload);
        let metadata = wallet_job_request(metadata_job);
        let finalize = wallet_job_request(finalize);
        assert_eq!(*upload.parts.context.priority(), 0);
        assert_eq!(*metadata.parts.context.priority(), 1);
        assert_eq!(*finalize.parts.context.priority(), 2);
        assert!(
            *finalize.parts.context.priority() > *metadata.parts.context.priority()
                && *metadata.parts.context.priority() > *upload.parts.context.priority()
        );
    }

    async fn insert_job_full(
        pool: &sqlx::PgPool,
        job_id: &str,
        status: &str,
        blob_id: Option<&str>,
        blob_object_id: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, blob_id, blob_object_id) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(job_id)
        .bind("0xtest-owner")
        .bind("test-ns")
        .bind(status)
        .bind(blob_id)
        .bind(blob_object_id)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_job_with_status(
        pool: &sqlx::PgPool,
        job_id: &str,
        status: &str,
        blob_id: Option<&str>,
    ) {
        insert_job_full(pool, job_id, status, blob_id, None).await;
    }

    // GH #477: a retried upload job must not re-mint a paid Walrus blob. These
    // pin the idempotency decision that gates the (paid) upload_blob call.
    #[tokio::test]
    async fn upload_resume_resumes_transfer_when_uploaded_with_object_id() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        // uploaded WITH a stored object id → resume the transfer, never re-mint.
        insert_job_full(
            &pool,
            &job_id,
            "uploaded",
            Some("blob-abc"),
            Some("0xobj-abc"),
        )
        .await;

        assert_eq!(
            upload_resume_disposition(&pool, &job_id).await,
            UploadResume::ResumeTransfer {
                blob_id: "blob-abc".into(),
                blob_object_id: "0xobj-abc".into(),
            },
        );

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn upload_resume_indexes_when_uploaded_without_object_id() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        // uploaded but no object id (full-success route / legacy row): the paid
        // blob exists and is transferred → resume INDEXING, never re-upload.
        insert_job_full(&pool, &job_id, "uploaded", Some("blob-legacy"), None).await;

        assert_eq!(
            upload_resume_disposition(&pool, &job_id).await,
            UploadResume::ResumeIndex {
                blob_id: "blob-legacy".into()
            },
        );

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn upload_resume_fails_closed_on_lookup_error() {
        // A closed pool makes the guard SELECT error → Indeterminate, so the
        // caller retries WITHOUT uploading (never a fail-open re-mint).
        let dead = PgPoolOptions::new()
            .max_connections(1)
            .connect(&test_database_url())
            .await
            .unwrap();
        dead.close().await;
        assert_eq!(
            upload_resume_disposition(&dead, "any-job").await,
            UploadResume::Indeterminate,
        );
    }

    #[tokio::test]
    async fn upload_resume_is_noop_when_already_done() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &job_id, "done", Some("blob-xyz")).await;

        assert_eq!(
            upload_resume_disposition(&pool, &job_id).await,
            UploadResume::AlreadyDone {
                blob_id: "blob-xyz".into()
            },
        );

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn upload_resume_uploads_when_no_blob_is_recorded() {
        let pool = test_pool().await;
        // The DB is authoritative: running + NULL blob means there is no paid
        // upload to resume, and the advisory lock prevents concurrent uploads.
        let running = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &running, "running", None).await;
        assert_eq!(
            upload_resume_disposition(&pool, &running).await,
            UploadResume::Upload,
        );

        // pending → fresh job.
        let pending = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &pending, "pending", None).await;
        assert_eq!(
            upload_resume_disposition(&pool, &pending).await,
            UploadResume::Upload
        );

        // failed with NO blob → no paid mint recorded, so upload.
        let failed = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &failed, "failed", None).await;
        assert_eq!(
            upload_resume_disposition(&pool, &failed).await,
            UploadResume::Upload
        );

        // #3: a FAILED row that DOES carry a blob_id was marked failed after a
        // successful mint (recovery-handoff failure / stale sweeper) → resume,
        // NEVER re-upload and discard the paid blob.
        let failed_with_blob = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_full(
            &pool,
            &failed_with_blob,
            "failed",
            Some("blob-paid"),
            Some("0xobj"),
        )
        .await;
        assert_eq!(
            upload_resume_disposition(&pool, &failed_with_blob).await,
            UploadResume::ResumeTransfer {
                blob_id: "blob-paid".into(),
                blob_object_id: "0xobj".into()
            },
        );

        // unknown job id → Upload (no row = no write ever happened).
        let missing = format!("remember-job-{}", uuid::Uuid::new_v4());
        assert_eq!(
            upload_resume_disposition(&pool, &missing).await,
            UploadResume::Upload
        );

        for id in [&running, &pending, &failed, &failed_with_blob] {
            let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
    }

    /// A queued upload must not reserve the scarce DB lock connection while
    /// another upload owns its wallet. Uses a missing random job ID, so no
    /// remember row is created or updated and no sidecar is called.
    #[tokio::test]
    async fn waiting_for_wallet_does_not_checkout_lock_connection() {
        let db = PgPoolOptions::new()
            .max_connections(2)
            .connect(&test_database_url())
            .await
            .unwrap();
        let locks = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_lazy(&test_database_url())
            .unwrap();
        let holder = super::admit_wallet_upload(0, 1).await.unwrap();
        let id = format!("admission-test-{}", uuid::Uuid::new_v4());
        let waiting = super::prepare_admitted_upload(&db, &locks, 1, 0, Some(&id));
        tokio::pin!(waiting);
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut waiting)
            .await
            .is_err());
        assert_eq!(
            locks.size(),
            0,
            "wallet wait must not consume lock-pool capacity"
        );
        drop(holder);
        // With the slot free the helper now reaches the lock checkout and
        // journal read. The latter fails for this deliberately absent row.
        let _ = tokio::time::timeout(Duration::from_secs(5), &mut waiting)
            .await
            .expect("lock checkout should settle after wallet slot release");
        assert_eq!(locks.size(), 1);
        locks.close().await;
        db.close().await;
    }

    // GH #477 RC-3: two concurrent attempts of the SAME job must not both mint.
    // The per-job advisory lock is the mutex; this proves the second acquirer is
    // refused while the first holds it, and succeeds again after release.
    #[tokio::test]
    async fn upload_lock_is_mutually_exclusive_per_job() {
        // Needs >1 connection: the holder pins one while a second attempt tries to
        // acquire on another (the real cross-session advisory-lock behavior). The
        // shared test_pool is max_connections(1), which would deadlock here.
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&test_database_url())
            .await
            .unwrap();
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());

        // First attempt acquires the lock.
        let lock = JobUploadLock::try_acquire(&pool, &job_id)
            .await
            .unwrap()
            .expect("first acquire should succeed");

        // A concurrent second attempt of the SAME job is refused → it must NOT
        // upload (returns None, which the caller turns into a Transient defer).
        assert!(
            JobUploadLock::try_acquire(&pool, &job_id)
                .await
                .unwrap()
                .is_none(),
            "second concurrent acquire of the same job must be refused",
        );

        // A DIFFERENT job never contends.
        let other = format!("remember-job-{}", uuid::Uuid::new_v4());
        assert!(
            JobUploadLock::try_acquire(&pool, &other)
                .await
                .unwrap()
                .is_some(),
            "a different job must be able to acquire its own lock",
        );

        // After the holder releases, the job is acquirable again.
        lock.release(&job_id).await;
        assert!(
            JobUploadLock::try_acquire(&pool, &job_id)
                .await
                .unwrap()
                .is_some(),
            "lock must be re-acquirable after release",
        );
    }

    // A wallet-job future can be cancelled at any await point, which drops its
    // transaction without calling the async release method. SQLx must roll it
    // back and release the transaction lock before the connection is reused.
    #[tokio::test]
    async fn upload_lock_transaction_rolls_back_when_guard_is_dropped() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&test_database_url())
            .await
            .unwrap();
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());

        let lock = JobUploadLock::try_acquire(&pool, &job_id)
            .await
            .unwrap()
            .expect("first acquire should succeed");
        drop(lock); // Simulate cancellation: no explicit async release.

        let reacquired = JobUploadLock::try_acquire(&pool, &job_id).await.unwrap();
        assert!(
            reacquired.is_some(),
            "dropping a cancelled guard must roll back and release the lock"
        );
        reacquired.unwrap().release(&job_id).await;
    }

    // RC-3 wiring: the caller must NOT upload when the lock is contended or the
    // lock pool is unreachable. lock_outcome is the decision the outer fn keys on;
    // a regression that treated either as "proceed" would double-mint.
    #[test]
    fn lock_outcome_defers_when_contended_and_fails_closed_on_error() {
        // Contended (Ok(None)) → Defer with a retriable error, never Proceed.
        match lock_outcome(Ok(None), "job-x") {
            LockOutcome::Defer {
                error: WalletJobError::Transient(msg),
                reason: LockDeferReason::SameJob,
            } => {
                assert!(msg.contains("in progress"), "contended message: {msg}");
            }
            _ => panic!("contended lock must Defer(Transient), never Proceed"),
        }
        // Lock-pool error → fail closed to a retriable Defer, never Proceed.
        // A checkout miss is not same-job contention: it must not use that backoff.
        match lock_outcome(Err(sqlx::Error::PoolClosed), "job-y") {
            LockOutcome::Defer {
                error: WalletJobError::Transient(msg),
                reason: LockDeferReason::Pool,
            } => {
                assert!(msg.contains("could not acquire"), "error message: {msg}");
            }
            _ => panic!("lock-pool error must fail closed to Defer(Transient)"),
        }
    }

    #[tokio::test]
    async fn lock_outcome_proceeds_when_acquired() {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&test_database_url())
            .await
            .unwrap();
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        let acquired = JobUploadLock::try_acquire(&pool, &job_id).await;
        match lock_outcome(acquired, &job_id) {
            LockOutcome::Proceed(lock) => lock.release(&job_id).await,
            LockOutcome::Defer { .. } => panic!("a free lock must Proceed"),
        }
    }

    #[tokio::test]
    async fn prepared_register_journal_round_trips_before_submission() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &job_id, "running", None).await;
        let expected = UploadJournal {
            wallet_index: 2,
            wallet_address: Some(format!("0x{}", "1".repeat(64))),
            execution_identity: Some(UploadExecutionIdentity {
                chain_identifier: "testnet-chain".into(),
                walrus_package_id: format!("0x{}", "2".repeat(64)),
            }),
            resume_step: Some(serde_json::json!({
                "step": "encoded",
                "blobId": "blob-1",
                "rootHash": "root",
                "unencodedSize": 42
            })),
            register_transaction: Some(PreparedRegisterTransaction {
                transaction_bytes: "dHgtYnl0ZXM=".into(),
                signature: "signature".into(),
                digest: "digest-1".into(),
                sponsor_digest: None,
            }),
        };

        persist_upload_journal(&pool, &job_id, &expected)
            .await
            .unwrap();
        let loaded = load_upload_journal(&pool, &job_id, 0).await.unwrap();
        assert_eq!(loaded.wallet_index, 2);
        assert_eq!(loaded.wallet_address, expected.wallet_address);
        assert_eq!(
            loaded.register_transaction.unwrap().digest,
            "digest-1",
            "the exact prepared digest must survive the pre-submit checkpoint"
        );
        assert_eq!(
            loaded.resume_step.unwrap()["step"],
            "encoded",
            "encoded intent must be replayed with the prepared transaction"
        );

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn consumed_generation_remains_valid_for_durable_retry() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        let token = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, prepare_claim_token, prepare_claimed_at) VALUES ($1, '0xowner', 'ns', 'pending', $2, NOW())",
        )
        .bind(&job_id)
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();

        assert!(consume_preparation_claim(&pool, &job_id, &token)
            .await
            .unwrap());
        assert!(
            consume_preparation_claim(&pool, &job_id, &token)
                .await
                .unwrap(),
            "same durable generation must remain retryable after pending → running"
        );
        let stored: (String, Option<String>) =
            sqlx::query_as("SELECT status, prepare_claim_token FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored.0, "running");
        assert_eq!(stored.1.as_deref(), Some(token.as_str()));

        assert!(
            !consume_preparation_claim(&pool, &job_id, "superseding-token")
                .await
                .unwrap(),
            "a different generation must remain fenced"
        );
    }

    // RC-2: the durable persist must (a) actually store blob_object_id on success
    // and (b) return a RETRIABLE error on DB failure — never swallow it, or a lost
    // `uploaded` record lets a retry re-mint.
    #[tokio::test]
    async fn persist_uploaded_state_stores_object_id_and_is_retriable_on_failure() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &job_id, "running", None).await;

        persist_uploaded_state(&pool, &job_id, "blob-1", Some("0xobj-1"))
            .await
            .expect("persist should succeed");

        let row: (String, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT status, blob_id, blob_object_id FROM remember_jobs WHERE id = $1",
        )
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "uploaded");
        assert_eq!(row.1.as_deref(), Some("blob-1"));
        assert_eq!(
            row.2.as_deref(),
            Some("0xobj-1"),
            "blob_object_id must be persisted for RC-4 resume"
        );

        // A closed pool → the mint record can't be written → must be retriable.
        let dead = PgPoolOptions::new()
            .max_connections(1)
            .connect(&test_database_url())
            .await
            .unwrap();
        dead.close().await;
        match persist_uploaded_state(&dead, &job_id, "blob-1", Some("0xobj-1")).await {
            Err(WalletJobError::Transient(msg)) => {
                assert!(
                    msg.contains("must retry to record"),
                    "retriable persist failure: {msg}"
                );
            }
            other => panic!("persist failure must be Transient (retriable), got {other:?}"),
        }

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn wallet_error_persist_does_not_clobber_a_row_a_concurrent_attempt_already_finished() {
        // Regression for a race the lock-contention backoff introduced:
        // LockOutcome::Defer calls update_remember_job_after_wallet_error
        // specifically when this worker does NOT hold the per-job upload
        // lock — i.e. exactly while another attempt of the same job may be
        // concurrently writing 'uploaded' (persist_uploaded_state) or 'done'
        // (insert_vector_and_mark_remember_done). Without a status guard, a
        // loser's write landing after the winner's downgrades a genuinely-
        // succeeding row back to 'running' with a stale error_msg.
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &job_id, "uploaded", Some("blob-winner")).await;

        update_remember_job_after_wallet_error(
            &pool,
            Some(job_id.as_str()),
            &WalletJobError::Transient("another attempt of upload job is in progress".into()),
            "another attempt of upload job is in progress",
            None,
        )
        .await;

        let row: (String, Option<String>, Option<String>) =
            sqlx::query_as("SELECT status, error_msg, blob_id FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            row.0, "uploaded",
            "a lock-contention loser must not clobber a row the winner already finished"
        );
        assert_eq!(row.1, None, "error_msg must not be overwritten either");
        assert_eq!(row.2.as_deref(), Some("blob-winner"));

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    const ENOKI_DRY_RUN: &str = "Enoki API error (400): {\"code\":\"dry_run_failed\",\"message\":\"Could not find the referenced object 0xa2cf3a6d91952320d2f8262826e9f56b9520829934b8405e90ccb1963103a472 at version Some(SequenceNumber(1025755045))\"}";

    async fn seed_storage_reservation(pool: &sqlx::PgPool, job_id: &str) {
        sqlx::query(
            "INSERT INTO storage_reservations (id, owner, bytes, expires_at) VALUES ($1, '0xtest-owner', 128, NOW() + INTERVAL '15 minutes')",
        )
        .bind(job_id)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn reservation_exists(pool: &sqlx::PgPool, job_id: &str) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_reservations WHERE id = $1)")
            .bind(job_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn uploaded_metadata_error_keeps_the_row_uploaded_and_records_enoki() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &job_id, "uploaded", Some("blob-1")).await;
        seed_storage_reservation(&pool, &job_id).await;
        sqlx::query(
            "UPDATE remember_jobs SET updated_at = NOW() - INTERVAL '30 minutes' WHERE id = $1",
        )
        .bind(&job_id)
        .execute(&pool)
        .await
        .unwrap();
        let stale_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let err = WalletJobError::Transient(ENOKI_DRY_RUN.to_string());
        let msg = err.message().to_string();
        record_uploaded_metadata_error(
            &pool,
            Some(job_id.as_str()),
            &err,
            &msg,
            WalletJobAttemptInfo { current: 1, max: 5 },
        )
        .await;

        let row: (String, Option<String>, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT status, error_msg, updated_at FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, "uploaded");
        let msg = row.1.unwrap_or_default();
        assert!(msg.contains("dry_run_failed"), "{msg}");
        assert!(
            msg.contains("Could not find the referenced object"),
            "{msg}"
        );
        assert!(
            row.2 > stale_at,
            "updated_at must move so the sweep does not treat a live retry as stale"
        );
        assert!(reservation_exists(&pool, &job_id).await);

        let _ = sqlx::query("DELETE FROM storage_reservations WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn terminal_uploaded_metadata_error_fails_the_row_and_releases_quota() {
        let pool = test_pool().await;
        let exhausted_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &exhausted_id, "uploaded", Some("blob-1")).await;
        seed_storage_reservation(&pool, &exhausted_id).await;
        let exhausted = WalletJobError::Transient(ENOKI_DRY_RUN.to_string());
        let exhausted_msg = exhausted.message().to_string();
        record_uploaded_metadata_error(
            &pool,
            Some(exhausted_id.as_str()),
            &exhausted,
            &exhausted_msg,
            WalletJobAttemptInfo {
                current: MAX_ATTEMPTS as usize,
                max: MAX_ATTEMPTS as usize,
            },
        )
        .await;
        let exhausted_row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error_msg FROM remember_jobs WHERE id = $1")
                .bind(&exhausted_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(exhausted_row.0, "failed");
        let exhausted_text = exhausted_row.1.unwrap_or_default();
        assert!(
            exhausted_text.contains("dry_run_failed"),
            "{exhausted_text}"
        );
        assert!(!reservation_exists(&pool, &exhausted_id).await);

        let permanent_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &permanent_id, "uploaded", Some("blob-2")).await;
        seed_storage_reservation(&pool, &permanent_id).await;
        let permanent = WalletJobError::Permanent(ENOKI_DRY_RUN.to_string());
        let permanent_msg = permanent.message().to_string();
        record_uploaded_metadata_error(
            &pool,
            Some(permanent_id.as_str()),
            &permanent,
            &permanent_msg,
            WalletJobAttemptInfo { current: 1, max: 5 },
        )
        .await;
        let permanent_row: (String,) =
            sqlx::query_as("SELECT status FROM remember_jobs WHERE id = $1")
                .bind(&permanent_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(permanent_row.0, "failed");
        assert!(!reservation_exists(&pool, &permanent_id).await);

        for id in [&exhausted_id, &permanent_id] {
            let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
    }

    #[tokio::test]
    async fn uploaded_metadata_recorder_leaves_running_and_done_rows_alone() {
        let pool = test_pool().await;
        let err = WalletJobError::Transient(ENOKI_DRY_RUN.to_string());
        let msg = err.message().to_string();
        for status in ["running", "done"] {
            let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
            insert_job_with_status(&pool, &job_id, status, Some("blob-1")).await;
            seed_storage_reservation(&pool, &job_id).await;
            record_uploaded_metadata_error(
                &pool,
                Some(job_id.as_str()),
                &err,
                &msg,
                WalletJobAttemptInfo { current: 1, max: 5 },
            )
            .await;
            let row: (String, Option<String>) =
                sqlx::query_as("SELECT status, error_msg FROM remember_jobs WHERE id = $1")
                    .bind(&job_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(row.0, status);
            assert_eq!(row.1, None, "{status} error_msg must stay empty");
            assert!(reservation_exists(&pool, &job_id).await, "{status}");
            let _ = sqlx::query("DELETE FROM storage_reservations WHERE id = $1")
                .bind(&job_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .execute(&pool)
                .await;
        }
    }

    #[tokio::test]
    async fn uploaded_metadata_touch_refreshes_updated_at_and_keeps_error_msg() {
        let pool = test_pool().await;
        let uploaded_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &uploaded_id, "uploaded", Some("blob-1")).await;
        sqlx::query(
            "UPDATE remember_jobs SET error_msg = 'enoki-still-here', updated_at = NOW() - INTERVAL '30 minutes' WHERE id = $1",
        )
        .bind(&uploaded_id)
        .execute(&pool)
        .await
        .unwrap();
        let before: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT updated_at FROM remember_jobs WHERE id = $1")
                .bind(&uploaded_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        touch_uploaded_remember_job(&pool, Some(uploaded_id.as_str())).await;

        let uploaded: (String, Option<String>, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT status, error_msg, updated_at FROM remember_jobs WHERE id = $1")
                .bind(&uploaded_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(uploaded.0, "uploaded");
        assert_eq!(uploaded.1.as_deref(), Some("enoki-still-here"));
        assert!(uploaded.2 > before, "uploaded updated_at must move");

        let running_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &running_id, "running", None).await;
        sqlx::query(
            "UPDATE remember_jobs SET error_msg = 'leave-running', updated_at = NOW() - INTERVAL '30 minutes' WHERE id = $1",
        )
        .bind(&running_id)
        .execute(&pool)
        .await
        .unwrap();
        let running_before: (Option<String>, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT error_msg, updated_at FROM remember_jobs WHERE id = $1")
                .bind(&running_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        touch_uploaded_remember_job(&pool, Some(running_id.as_str())).await;

        let running_after: (String, Option<String>, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT status, error_msg, updated_at FROM remember_jobs WHERE id = $1")
                .bind(&running_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(running_after.0, "running");
        assert_eq!(running_after.1, running_before.0);
        assert_eq!(running_after.2, running_before.1);

        for id in [&uploaded_id, &running_id] {
            let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
    }

    #[test]
    fn uploaded_metadata_congestion_retry_pins_the_wallet() {
        let vector = vec![0.25_f32, 0.5];
        let job = metadata_congestion_retry_job(
            4,
            2,
            "0xblob-object",
            "0xowner",
            "bench-ns",
            Some("0xpkg"),
            Some("0xagent"),
            Some("job-1"),
            Some("blob-1"),
            Some(vector.as_slice()),
            Some(64),
            0.5,
            Some("ciphertext-b64"),
            Some("0xacct"),
            Some("0xpolicy"),
            Some(12),
        );
        assert_eq!(job.wallet_index, 4);
        assert_eq!(job.congestion_requeues, 3);
        match job.operation {
            WalletOperation::SetMetadataAndTransfer {
                blob_object_id,
                encrypted_b64,
                remember_job_id,
                ..
            } => {
                assert_eq!(blob_object_id, "0xblob-object");
                assert_eq!(encrypted_b64.as_deref(), Some("ciphertext-b64"));
                assert_eq!(remember_job_id.as_deref(), Some("job-1"));
            }
            other => panic!("expected SetMetadataAndTransfer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn uploaded_metadata_congestion_wait_keeps_uploaded_and_reservation() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &job_id, "uploaded", Some("blob-1")).await;
        seed_storage_reservation(&pool, &job_id).await;
        let err = WalletJobError::UploadSlotCongestion(
            "timed out waiting for wallet 4 upload slot".into(),
        );
        let msg = congestion_wait_message(err.message());
        record_uploaded_metadata_error(
            &pool,
            Some(job_id.as_str()),
            &err,
            &msg,
            WalletJobAttemptInfo { current: 1, max: 5 },
        )
        .await;

        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error_msg FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, "uploaded");
        let text = row.1.unwrap_or_default();
        assert!(text.starts_with(CONGESTION_WAIT_ERROR_PREFIX), "{text}");
        assert!(reservation_exists(&pool, &job_id).await);

        let _ = sqlx::query("DELETE FROM storage_reservations WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn exhausted_transient_upload_marks_the_row_failed_immediately() {
        // Dev 2026-09-17: after attempt 5/5 of a Walrus 503 timeout the row
        // stayed `running` until the 10-minute stale sweeper. Clients polling
        // the job then reported "still uploading" long after every wallet
        // attempt was spent. The final attempt must mark failed itself.
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &job_id, "running", None).await;

        let err = WalletJobError::Transient(
            "Internal Error: durable Walrus upload failed (503 Service Unavailable)".into(),
        );
        update_remember_job_after_wallet_error(
            &pool,
            Some(job_id.as_str()),
            &err,
            err.message(),
            Some(WalletJobAttemptInfo {
                current: MAX_ATTEMPTS as usize,
                max: MAX_ATTEMPTS as usize,
            }),
        )
        .await;

        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error_msg FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, "failed");
        assert!(
            row.1.as_deref().unwrap_or("").contains("503"),
            "error_msg must keep the upload failure: {:?}",
            row.1
        );

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;

        // An earlier attempt must still leave the row running for the next try.
        let mid_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        insert_job_with_status(&pool, &mid_id, "running", None).await;
        update_remember_job_after_wallet_error(
            &pool,
            Some(mid_id.as_str()),
            &err,
            err.message(),
            Some(WalletJobAttemptInfo {
                current: (MAX_ATTEMPTS as usize) - 1,
                max: MAX_ATTEMPTS as usize,
            }),
        )
        .await;
        let mid: (String,) = sqlx::query_as("SELECT status FROM remember_jobs WHERE id = $1")
            .bind(&mid_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mid.0, "running");

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&mid_id)
            .execute(&pool)
            .await;
    }

    // RC-4: an uploaded-but-pending resume must route to the TRANSFER recovery op
    // (carrying the stored object id), NOT to an index/done finalize — otherwise a
    // never-transferred blob is prematurely marked done.
    #[test]
    fn resume_builds_a_set_metadata_and_transfer_job_with_object_id() {
        let job = build_resume_transfer_job(
            3,
            "job-abc",
            "blob-abc",
            "0xobj-abc".into(),
            "0xowner",
            "ns",
            "0xpkg",
            "0xacct",
            Some("0xagent"),
            "ciphertext-b64",
            &[0.1, 0.2, 0.3],
            123,
            0.5,
            "0xpolicy",
        );
        match job.operation {
            WalletOperation::SetMetadataAndTransfer {
                blob_object_id,
                blob_id,
                remember_job_id,
                encrypted_b64,
                ..
            } => {
                assert_eq!(
                    blob_object_id, "0xobj-abc",
                    "must carry the stored object id"
                );
                assert_eq!(blob_id.as_deref(), Some("blob-abc"));
                assert_eq!(remember_job_id.as_deref(), Some("job-abc"));
                assert_eq!(
                    encrypted_b64.as_deref(),
                    Some("ciphertext-b64"),
                    "ciphertext needed for SEAL persistence"
                );
            }
            other => panic!("resume must build SetMetadataAndTransfer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recovery_enqueue_failure_marks_remember_job_failed() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        let msg = "failed to enqueue metadata/transfer recovery job: synthetic queue down";

        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status) VALUES ($1, $2, $3, 'uploaded')",
        )
        .bind(&job_id)
        .bind("0xtest-owner")
        .bind("test-ns")
        .execute(&pool)
        .await
        .unwrap();

        let classified =
            classify_wallet_remember_handoff_failure(&pool, Some(&job_id), msg.to_string()).await;

        match classified {
            WalletJobError::Permanent(ref got) => assert_eq!(got, msg),
            other => panic!("expected permanent handoff error, got {other}"),
        }

        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error_msg FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(row.0, "failed");
        assert_eq!(row.1.as_deref(), Some(msg));

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn terminal_recovery_handoff_failure_overrides_transient_looking_queue_error() {
        let pool = test_pool().await;
        let job_id = format!("remember-job-{}", uuid::Uuid::new_v4());
        let msg = "failed to enqueue metadata/transfer recovery job: 503 service unavailable";

        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status) VALUES ($1, $2, $3, 'uploaded')",
        )
        .bind(&job_id)
        .bind("0xtest-owner")
        .bind("test-ns")
        .execute(&pool)
        .await
        .unwrap();

        let classified =
            classify_wallet_remember_handoff_failure(&pool, Some(&job_id), msg.to_string()).await;

        match classified {
            WalletJobError::Permanent(ref got) => assert_eq!(got, msg),
            other => panic!("expected permanent handoff error, got {other}"),
        }

        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error_msg FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(row.0, "failed");
        assert_eq!(row.1.as_deref(), Some(msg));

        let _ = sqlx::query("DELETE FROM remember_jobs WHERE id = $1")
            .bind(&job_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn failed_status_persistence_keeps_wallet_handoff_retryable() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&test_database_url())
            .await
            .unwrap();
        pool.close().await;

        let msg = "failed to enqueue uploaded-blob finalization job: synthetic queue down";
        let classified =
            classify_wallet_remember_handoff_failure(&pool, Some("job-closed-pool"), msg.into())
                .await;

        match classified {
            WalletJobError::Transient(got) => {
                assert!(got.contains(msg));
                assert!(got.contains("failed to persist remember_jobs failed status"));
            }
            other => panic!("expected transient handoff error, got {other}"),
        }
    }

    #[tokio::test]
    async fn mark_remember_job_failed_returns_real_update_error() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&test_database_url())
            .await
            .unwrap();
        pool.close().await;

        let err = mark_remember_job_failed(&pool, Some("job-closed-pool"), "synthetic")
            .await
            .expect_err("closed pool should fail");

        assert!(err.to_string().contains("closed"));
    }

    #[tokio::test]
    async fn missing_remember_job_keeps_handoff_retryable() {
        let pool = test_pool().await;
        let job_id = format!("missing-remember-job-{}", uuid::Uuid::new_v4());
        let msg = "failed to enqueue metadata/transfer recovery job: synthetic queue down";

        let classified =
            classify_wallet_remember_handoff_failure(&pool, Some(&job_id), msg.to_string()).await;

        match classified {
            WalletJobError::Transient(got) => {
                assert!(got.contains(msg));
                assert!(got.contains("failed to persist remember_jobs failed status"));
                assert!(got.contains("no rows returned"));
            }
            other => panic!("expected transient handoff error, got {other}"),
        }
    }
}
