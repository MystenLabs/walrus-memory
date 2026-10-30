use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::types::AppError;

pub const BLOB_DELETABLE: &str = "deletable";
pub const BLOB_DELETING: &str = "deleting";
pub const BLOB_DELETED: &str = "deleted";
pub const BLOB_DELETED_EXTERNAL: &str = "deleted_external";
pub const BLOB_NOT_OWNER: &str = "not_owner";
pub const BLOB_EXPIRED: &str = "expired";

pub const BATCH_AWAITING_SIGNATURE: &str = "awaiting_signature";
pub const BATCH_EXECUTING: &str = "executing";
pub const BATCH_COMPLETED: &str = "completed";
pub const BATCH_FAILED: &str = "failed";
pub const BATCH_ROLLED_BACK: &str = "rolled_back";

// deletion_batch_members outcomes. Terminal eviction/success outcomes reuse
// the BLOB_* constants (same wire values by design); these two are the
// member-only states (design: security-delete-invariants.md §4).
pub const MEMBER_CLAIMED: &str = "claimed";
pub const MEMBER_RELEASED: &str = "released";

// Two-key advisory locks use a separate keyspace from the bigint locks used
// elsewhere. 21316 is ASCII "SD" (security delete).
const RESOLVER_OWNER_LOCK_NAMESPACE: i32 = 21_316;

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct BlobRow {
    pub blob_id: String,
    pub object_id: Option<String>,
    pub created_at: DateTime<Utc>,
    #[allow(dead_code)] // audit timestamp; resolver ordering uses tracked_seq
    pub tracked_at: DateTime<Utc>,
    #[allow(dead_code)] // exposed for resolver-generation diagnostics
    pub tracked_seq: i64,
    pub state: String,
    #[allow(dead_code)] // exposed for generation diagnostics and race assertions
    pub batch_id: Option<Uuid>,
}

#[derive(Clone, Debug, Default)]
pub struct Counts {
    pub total: i64,
    pub deletable: i64,
    pub deleting: i64,
    pub deleted: i64,
    pub deleted_external: i64,
    pub not_owner: i64,
    pub expired: i64,
}

#[derive(Debug)]
pub struct ClaimResult {
    pub rows: Vec<BlobRow>,
}

#[derive(Debug)]
pub enum ClaimError {
    ActiveBatchLimit(Vec<Uuid>),
    Conflict(Vec<String>),
    Storage(AppError),
}

#[derive(Clone, Debug)]
pub struct BatchRow {
    pub id: Uuid,
    pub owner: String,
    pub state: String,
    pub digest: Option<String>,
    pub tx_bytes: Option<Vec<u8>>,
    pub input_blob_ids: Option<Vec<String>>,
    pub blob_count: i32,
    #[allow(dead_code)] // persisted for nonce collision/reconciliation diagnostics
    pub nonce: i64,
    pub expire_epoch: i64,
    #[allow(dead_code)] // retained for claim/retry timing diagnostics
    pub claimed_at: DateTime<Utc>,
    pub signatures: Option<Vec<Vec<u8>>>,
    #[allow(dead_code)] // retained for execution timing diagnostics
    pub executing_at: Option<DateTime<Utc>>,
    #[allow(dead_code)] // persisted for retry scheduling and telemetry
    pub last_submit_at: Option<DateTime<Utc>>,
    pub submit_attempts: i32,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct BatchDbRow {
    id: Uuid,
    owner: String,
    state: String,
    digest: Option<String>,
    tx_bytes: Option<Vec<u8>>,
    input_blob_ids: Option<Vec<u8>>,
    blob_count: i32,
    nonce: i64,
    expire_epoch: i64,
    claimed_at: DateTime<Utc>,
    signatures: Option<Vec<u8>>,
    executing_at: Option<DateTime<Utc>>,
    last_submit_at: Option<DateTime<Utc>>,
    submit_attempts: i32,
    resolved_at: Option<DateTime<Utc>>,
}

impl TryFrom<BatchDbRow> for BatchRow {
    type Error = AppError;

    fn try_from(row: BatchDbRow) -> Result<Self, Self::Error> {
        let input_blob_ids = row
            .input_blob_ids
            .map(|bytes| {
                bcs::from_bytes(&bytes).map_err(|error| {
                    AppError::Internal(format!("decode batch input mapping: {error}"))
                })
            })
            .transpose()?;
        let signatures = row
            .signatures
            .map(|bytes| {
                bcs::from_bytes(&bytes).map_err(|error| {
                    AppError::Internal(format!("decode batch signatures: {error}"))
                })
            })
            .transpose()?;
        Ok(Self {
            id: row.id,
            owner: row.owner,
            state: row.state,
            digest: row.digest,
            tx_bytes: row.tx_bytes,
            input_blob_ids,
            blob_count: row.blob_count,
            nonce: row.nonce,
            expire_epoch: row.expire_epoch,
            claimed_at: row.claimed_at,
            signatures,
            executing_at: row.executing_at,
            last_submit_at: row.last_submit_at,
            submit_attempts: row.submit_attempts,
            resolved_at: row.resolved_at,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SweepCursor {
    pub updated_at: DateTime<Utc>,
    pub owner: String,
    pub blob_id: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct SweepRow {
    pub owner: String,
    pub blob_id: String,
    pub object_id: Option<String>,
    pub updated_at: DateTime<Utc>,
}

fn storage(context: &str, error: sqlx::Error) -> AppError {
    AppError::Internal(format!("security-delete {context}: {error}"))
}

fn valid_blob_state(state: &str) -> bool {
    matches!(
        state,
        BLOB_DELETABLE
            | BLOB_DELETING
            | BLOB_DELETED
            | BLOB_DELETED_EXTERNAL
            | BLOB_NOT_OWNER
            | BLOB_EXPIRED
    )
}

fn valid_batch_state(state: &str) -> bool {
    matches!(
        state,
        BATCH_AWAITING_SIGNATURE
            | BATCH_EXECUTING
            | BATCH_COMPLETED
            | BATCH_FAILED
            | BATCH_ROLLED_BACK
    )
}

pub async fn list_blobs(
    pool: &PgPool,
    owner: &str,
    states: &[&str],
    cursor: Option<(DateTime<Utc>, String)>,
    limit: i64,
) -> Result<Vec<BlobRow>, AppError> {
    if states.iter().any(|state| !valid_blob_state(state)) || !(1..=1000).contains(&limit) {
        return Err(AppError::BadRequest("invalid deletion list query".into()));
    }
    let states: Vec<String> = states.iter().map(|state| (*state).to_owned()).collect();
    let (cursor_time, cursor_blob) = cursor
        .map(|(time, blob)| (Some(time), Some(blob)))
        .unwrap_or((None, None));
    sqlx::query_as::<_, BlobRow>(
        "SELECT blob_id, object_id, created_at, tracked_at, tracked_seq, state, batch_id
         FROM delete_blobs_tracking
         WHERE owner=$1 AND (cardinality($2::text[])=0 OR state=ANY($2))
           AND ($3::timestamptz IS NULL OR (created_at, blob_id) > ($3, $4))
         ORDER BY created_at, blob_id LIMIT $5",
    )
    .bind(owner)
    .bind(states)
    .bind(cursor_time)
    .bind(cursor_blob)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|error| storage("list blobs", error))
}

pub async fn counts(pool: &PgPool, owner: &str) -> Result<Counts, AppError> {
    let row: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),
          count(*) FILTER (WHERE state='deletable'),
          count(*) FILTER (WHERE state='deleting'),
          count(*) FILTER (WHERE state='deleted'),
          count(*) FILTER (WHERE state='deleted_external'),
          count(*) FILTER (WHERE state='not_owner'),
          count(*) FILTER (WHERE state='expired')
         FROM delete_blobs_tracking WHERE owner=$1",
    )
    .bind(owner)
    .fetch_one(pool)
    .await
    .map_err(|error| storage("count blobs", error))?;
    Ok(Counts {
        total: row.0,
        deletable: row.1,
        deleting: row.2,
        deleted: row.3,
        deleted_external: row.4,
        not_owner: row.5,
        expired: row.6,
    })
}

#[allow(dead_code)] // public store diagnostic used by cap tests and operations tooling
pub async fn active_batch_ids(pool: &PgPool, owner: &str) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM deletion_batches WHERE owner=$1
         AND state IN ('awaiting_signature','executing') ORDER BY claimed_at, id",
    )
    .bind(owner)
    .fetch_all(pool)
    .await
    .map_err(|error| storage("list active batches", error))
}

async fn lock_and_check_cap(
    tx: &mut Transaction<'_, Postgres>,
    owner: &str,
    active_cap: i64,
) -> Result<(), ClaimError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(|error| ClaimError::Storage(storage("lock owner", error)))?;
    let active: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM deletion_batches WHERE owner=$1
         AND state IN ('awaiting_signature','executing') ORDER BY claimed_at, id FOR UPDATE",
    )
    .bind(owner)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| ClaimError::Storage(storage("check active cap", error)))?;
    if active.len() as i64 >= active_cap {
        return Err(ClaimError::ActiveBatchLimit(active));
    }
    Ok(())
}

async fn insert_batch(
    tx: &mut Transaction<'_, Postgres>,
    owner: &str,
    batch_id: Uuid,
) -> Result<(), ClaimError> {
    sqlx::query(
        "INSERT INTO deletion_batches (id, owner, state)
         VALUES ($1,$2,'awaiting_signature')",
    )
    .bind(batch_id)
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(|error| ClaimError::Storage(storage("insert batch", error)))?;
    Ok(())
}

/// Append the just-claimed rows to the lineage ledger, in the SAME
/// transaction as the claim CAS -- membership must never be observable
/// without its ledger entry (design: security-delete-invariants.md §4).
/// The batch id was created in this transaction, so `batch_id=$1` selects
/// exactly the rows the claim UPDATE touched.
async fn insert_claimed_members(
    tx: &mut Transaction<'_, Postgres>,
    batch_id: Uuid,
) -> Result<(), ClaimError> {
    sqlx::query(
        "INSERT INTO deletion_batch_members (batch_id, owner, blob_id, object_id)
         SELECT batch_id, owner, blob_id, object_id FROM delete_blobs_tracking
         WHERE batch_id=$1",
    )
    .bind(batch_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| ClaimError::Storage(storage("insert batch members", error)))?;
    Ok(())
}

pub async fn create_batch_and_claim_selection(
    pool: &PgPool,
    owner: &str,
    batch_id: Uuid,
    blob_ids: &[String],
    active_cap: i64,
) -> Result<ClaimResult, ClaimError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| ClaimError::Storage(storage("begin claim", error)))?;
    lock_and_check_cap(&mut tx, owner, active_cap).await?;
    insert_batch(&mut tx, owner, batch_id).await?;
    let rows = sqlx::query_as::<_, BlobRow>(
        "UPDATE delete_blobs_tracking SET state='deleting', batch_id=$3, updated_at=NOW()
         WHERE owner=$1 AND blob_id=ANY($2::text[]) AND state='deletable'
         RETURNING blob_id, object_id, created_at, tracked_at, tracked_seq, state, batch_id",
    )
    .bind(owner)
    .bind(blob_ids)
    .bind(batch_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| ClaimError::Storage(storage("claim selection", error)))?;
    if rows.len() != blob_ids.len() {
        let claimed: HashSet<&str> = rows.iter().map(|row| row.blob_id.as_str()).collect();
        let conflicts = blob_ids
            .iter()
            .filter(|blob_id| !claimed.contains(blob_id.as_str()))
            .cloned()
            .collect();
        tx.rollback()
            .await
            .map_err(|error| ClaimError::Storage(storage("rollback conflict", error)))?;
        return Err(ClaimError::Conflict(conflicts));
    }
    sqlx::query("UPDATE deletion_batches SET blob_count=$2 WHERE id=$1")
        .bind(batch_id)
        .bind(rows.len() as i32)
        .execute(&mut *tx)
        .await
        .map_err(|error| ClaimError::Storage(storage("set claimed count", error)))?;
    insert_claimed_members(&mut tx, batch_id).await?;
    tx.commit()
        .await
        .map_err(|error| ClaimError::Storage(storage("commit claim", error)))?;
    Ok(ClaimResult { rows })
}

pub async fn create_batch_and_claim_all(
    pool: &PgPool,
    owner: &str,
    batch_id: Uuid,
    max: i64,
    active_cap: i64,
) -> Result<ClaimResult, ClaimError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| ClaimError::Storage(storage("begin claim all", error)))?;
    lock_and_check_cap(&mut tx, owner, active_cap).await?;
    insert_batch(&mut tx, owner, batch_id).await?;
    let rows = sqlx::query_as::<_, BlobRow>(
        "UPDATE delete_blobs_tracking tracking
         SET state='deleting', batch_id=$2, updated_at=NOW()
         WHERE (tracking.owner, tracking.blob_id) IN (
           SELECT owner, blob_id FROM delete_blobs_tracking
           WHERE owner=$1 AND state='deletable' ORDER BY created_at, blob_id
           LIMIT $3 FOR UPDATE SKIP LOCKED)
         RETURNING blob_id, object_id, created_at, tracked_at, tracked_seq, state, batch_id",
    )
    .bind(owner)
    .bind(batch_id)
    .bind(max)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| ClaimError::Storage(storage("claim all", error)))?;
    if rows.is_empty() {
        tx.rollback()
            .await
            .map_err(|error| ClaimError::Storage(storage("rollback empty claim", error)))?;
        return Ok(ClaimResult { rows });
    }
    sqlx::query("UPDATE deletion_batches SET blob_count=$2 WHERE id=$1")
        .bind(batch_id)
        .bind(rows.len() as i32)
        .execute(&mut *tx)
        .await
        .map_err(|error| ClaimError::Storage(storage("set claimed count", error)))?;
    insert_claimed_members(&mut tx, batch_id).await?;
    tx.commit()
        .await
        .map_err(|error| ClaimError::Storage(storage("commit claim all", error)))?;
    Ok(ClaimResult { rows })
}

pub async fn batch_blobs(
    pool: &PgPool,
    batch_id: Uuid,
    owner: &str,
) -> Result<Vec<BlobRow>, AppError> {
    sqlx::query_as(
        "SELECT blob_id, object_id, created_at, tracked_at, tracked_seq, state, batch_id
         FROM delete_blobs_tracking WHERE batch_id=$1 AND owner=$2
         ORDER BY created_at, blob_id",
    )
    .bind(batch_id)
    .bind(owner)
    .fetch_all(pool)
    .await
    .map_err(|error| storage("batch blobs", error))
}

pub async fn evict_claimed_blob(
    pool: &PgPool,
    owner: &str,
    blob_id: &str,
    expected_batch_id: Uuid,
    to_state: &str,
) -> Result<bool, AppError> {
    if !matches!(
        to_state,
        BLOB_DELETED_EXTERNAL | BLOB_NOT_OWNER | BLOB_EXPIRED
    ) {
        return Err(AppError::BadRequest("invalid terminal blob state".into()));
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| storage("begin evict", error))?;
    let result = sqlx::query(
        "UPDATE delete_blobs_tracking SET state=$5, batch_id=NULL, updated_at=NOW()
         WHERE owner=$1 AND blob_id=$2 AND state=$3 AND batch_id=$4",
    )
    .bind(owner)
    .bind(blob_id)
    .bind(BLOB_DELETING)
    .bind(expected_batch_id)
    .bind(to_state)
    .execute(&mut *tx)
    .await
    .map_err(|error| storage("evict claimed blob", error))?;
    if result.rows_affected() != 1 {
        tx.rollback()
            .await
            .map_err(|error| storage("rollback evict", error))?;
        return Ok(false);
    }
    // Lineage: the member's outcome advances atomically with the eviction.
    // Object id is backfilled from the tracking row in case resolution
    // landed after the claim copied a NULL.
    sqlx::query(
        "UPDATE deletion_batch_members m
         SET outcome=$5, resolved_at=NOW(),
             object_id=COALESCE(m.object_id, t.object_id)
         FROM delete_blobs_tracking t
         WHERE m.batch_id=$4 AND m.owner=$1 AND m.blob_id=$2 AND m.outcome=$3
           AND t.owner=m.owner AND t.blob_id=m.blob_id",
    )
    .bind(owner)
    .bind(blob_id)
    .bind(MEMBER_CLAIMED)
    .bind(expected_batch_id)
    .bind(to_state)
    .execute(&mut *tx)
    .await
    .map_err(|error| storage("evict batch member", error))?;
    tx.commit()
        .await
        .map_err(|error| storage("commit evict", error))?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub async fn set_batch_prepared(
    pool: &PgPool,
    batch_id: Uuid,
    digest: &str,
    tx_bytes: &[u8],
    input_blob_ids_bcs: &[u8],
    blob_count: i32,
    nonce: i64,
    expire_epoch: i64,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE deletion_batches b SET digest=$2, tx_bytes=$3, input_blob_ids=$4,
            blob_count=$5, nonce=$6, expire_epoch=$7
         WHERE b.id=$1 AND b.state='awaiting_signature'
           AND b.tx_bytes IS NULL
           AND (SELECT count(*) FROM delete_blobs_tracking t
                WHERE t.batch_id=b.id AND t.state='deleting')=$5",
    )
    .bind(batch_id)
    .bind(digest)
    .bind(tx_bytes)
    .bind(input_blob_ids_bcs)
    .bind(blob_count as i64)
    .bind(nonce)
    .bind(expire_epoch)
    .execute(pool)
    .await
    .map_err(|error| storage("prepare batch", error))?;
    Ok(result.rows_affected() == 1)
}

pub async fn cas_batch_state(
    pool: &PgPool,
    batch_id: Uuid,
    from: &str,
    to: &str,
) -> Result<bool, AppError> {
    let allowed = matches!(
        (from, to),
        (BATCH_AWAITING_SIGNATURE, BATCH_EXECUTING)
            | (BATCH_AWAITING_SIGNATURE, BATCH_FAILED)
            | (BATCH_AWAITING_SIGNATURE, BATCH_ROLLED_BACK)
            | (BATCH_EXECUTING, BATCH_COMPLETED)
            | (BATCH_EXECUTING, BATCH_FAILED)
    );
    if !valid_batch_state(from) || !valid_batch_state(to) || !allowed {
        return Err(AppError::BadRequest("invalid batch state".into()));
    }
    let result = sqlx::query(
        "UPDATE deletion_batches SET state=$3,
         resolved_at=CASE WHEN $3 IN ('completed','failed','rolled_back') THEN NOW() ELSE resolved_at END,
         signatures=CASE WHEN $3 IN ('completed','failed','rolled_back') THEN NULL ELSE signatures END
         WHERE id=$1 AND state=$2",
    )
    .bind(batch_id)
    .bind(from)
    .bind(to)
    .execute(pool)
    .await
    .map_err(|error| storage("CAS batch state", error))?;
    Ok(result.rows_affected() == 1)
}

/// Atomically persist the signatures and expose the batch as executing.
/// The reconciler can safely replay these exact bytes if the process dies
/// before or during the first Sui submission.
pub async fn begin_batch_execution(
    pool: &PgPool,
    batch_id: Uuid,
    signatures: &[Vec<u8>],
) -> Result<bool, AppError> {
    let signatures = bcs::to_bytes(signatures)
        .map_err(|error| AppError::Internal(format!("encode batch signatures: {error}")))?;
    let result = sqlx::query(
        "UPDATE deletion_batches
         SET state='executing', signatures=$2, executing_at=NOW(),
             last_submit_at=NOW(), submit_attempts=1
         WHERE id=$1 AND state='awaiting_signature' AND tx_bytes IS NOT NULL",
    )
    .bind(batch_id)
    .bind(signatures)
    .execute(pool)
    .await
    .map_err(|error| storage("begin batch execution", error))?;
    Ok(result.rows_affected() == 1)
}

/// Claim a due retry. Updating last_submit_at before the network call prevents
/// multiple server replicas from replaying the same batch simultaneously.
pub async fn claim_batch_retry(
    pool: &PgPool,
    batch_id: Uuid,
    retry_after: Duration,
) -> Result<bool, AppError> {
    let retry_before = Utc::now() - retry_after;
    let result = sqlx::query(
        "UPDATE deletion_batches
         SET last_submit_at=NOW(), submit_attempts=submit_attempts+1
         WHERE id=$1 AND state='executing' AND signatures IS NOT NULL
           AND COALESCE(last_submit_at, executing_at) < $2",
    )
    .bind(batch_id)
    .bind(retry_before)
    .execute(pool)
    .await
    .map_err(|error| storage("claim batch retry", error))?;
    Ok(result.rows_affected() == 1)
}

pub async fn rollback_batch(
    pool: &PgPool,
    batch_id: Uuid,
    expected_batch_state: &str,
    batch_to: &str,
) -> Result<bool, AppError> {
    if !valid_batch_state(expected_batch_state)
        || !matches!(batch_to, BATCH_FAILED | BATCH_ROLLED_BACK)
    {
        return Err(AppError::BadRequest("invalid rollback state".into()));
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| storage("begin rollback", error))?;
    let updated = sqlx::query(
        "UPDATE deletion_batches SET state=$3, resolved_at=NOW(), signatures=NULL
         WHERE id=$1 AND state=$2",
    )
    .bind(batch_id)
    .bind(expected_batch_state)
    .bind(batch_to)
    .execute(&mut *tx)
    .await
    .map_err(|error| storage("CAS rollback batch", error))?;
    if updated.rows_affected() == 0 {
        tx.rollback()
            .await
            .map_err(|error| storage("rollback lost race", error))?;
        return Ok(false);
    }
    sqlx::query(
        "UPDATE delete_blobs_tracking SET state='deletable', batch_id=NULL, updated_at=NOW()
         WHERE batch_id=$1 AND state='deleting'",
    )
    .bind(batch_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| storage("restore batch blobs", error))?;
    // Lineage: surviving claims are released back to the pool atomically
    // with the batch going terminal; already-evicted members keep their
    // terminal outcome.
    sqlx::query(
        "UPDATE deletion_batch_members SET outcome=$2, resolved_at=NOW()
         WHERE batch_id=$1 AND outcome=$3",
    )
    .bind(batch_id)
    .bind(MEMBER_RELEASED)
    .bind(MEMBER_CLAIMED)
    .execute(&mut *tx)
    .await
    .map_err(|error| storage("release batch members", error))?;
    tx.commit()
        .await
        .map_err(|error| storage("commit rollback", error))?;
    Ok(true)
}

pub async fn finalize_batch_deleted(
    pool: &PgPool,
    batch_id: Uuid,
    expected_batch_state: &str,
) -> Result<Option<u64>, AppError> {
    if expected_batch_state != BATCH_EXECUTING {
        return Err(AppError::BadRequest("invalid finalize state".into()));
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| storage("begin finalize", error))?;
    let Some(rows) = finalize_batch_deleted_in_tx(&mut tx, batch_id, expected_batch_state).await?
    else {
        tx.rollback()
            .await
            .map_err(|error| storage("finalize lost race", error))?;
        return Ok(None);
    };
    tx.commit()
        .await
        .map_err(|error| storage("commit finalize", error))?;
    Ok(Some(rows))
}

pub(crate) async fn finalize_batch_deleted_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    batch_id: Uuid,
    expected_batch_state: &str,
) -> Result<Option<u64>, AppError> {
    if expected_batch_state != BATCH_EXECUTING {
        return Err(AppError::BadRequest("invalid finalize state".into()));
    }
    let updated = sqlx::query(
        "UPDATE deletion_batches SET state='completed', resolved_at=NOW(), signatures=NULL
         WHERE id=$1 AND state=$2",
    )
    .bind(batch_id)
    .bind(expected_batch_state)
    .execute(&mut **tx)
    .await
    .map_err(|error| storage("CAS finalize batch", error))?;
    if updated.rows_affected() == 0 {
        return Ok(None);
    }
    // Security-delete erases the Walrus blob, so every memory row pointing at
    // that blob_id is dangling. Identify rows by memory id (not a bare
    // (owner, blob_id) delete) so each tombstone carries the row's own
    // namespace. Tracking has no namespace column — PK is (owner, blob_id) —
    // and a shared blob_id across namespaces is unreadable after the blob is
    // gone, so every matching row is purged. Acquire the shared per-owner sync
    // advisory lock (classid 20261029) for every affected owner so concurrent
    // incremental sync polls hold their watermark horizon until this delete
    // transaction finishes.
    sqlx::query(
        "WITH tracked AS (
            SELECT v.id, v.owner, v.namespace, v.blob_id
            FROM delete_blobs_tracking t
            INNER JOIN vector_entries v
              ON v.owner = t.owner AND v.blob_id = t.blob_id
            WHERE t.batch_id=$1 AND t.state='deleting'
         ),
         affected_owners AS (
            SELECT DISTINCT owner FROM tracked
            UNION
            SELECT DISTINCT owner FROM delete_blobs_tracking WHERE batch_id=$1 AND state='deleting'
            UNION
            SELECT owner FROM deletion_batches WHERE id=$1
         ),
         owner_locks AS (
            SELECT pg_advisory_xact_lock_shared(20261029, hashtext(owner))
            FROM affected_owners
            WHERE owner IS NOT NULL AND owner <> ''
         ),
         removed AS (
            DELETE FROM vector_entries v
            USING tracked t
            WHERE v.id = t.id
              AND (SELECT COUNT(*) FROM owner_locks) >= 0
            RETURNING v.id, v.owner, v.namespace, v.blob_id
         )
         INSERT INTO memory_tombstones (memory_id, owner, namespace, blob_id, deleted_at)
         SELECT id, owner, namespace, blob_id, clock_timestamp() FROM removed
         ON CONFLICT (memory_id) DO UPDATE SET deleted_at = clock_timestamp()",
    )
    .bind(batch_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| storage("tombstone security-delete rows", error))?;
    let rows = sqlx::query(
        "UPDATE delete_blobs_tracking SET state='deleted', batch_id=NULL, updated_at=NOW()
         WHERE batch_id=$1 AND state='deleting'",
    )
    .bind(batch_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| storage("finalize blobs", error))?
    .rows_affected();
    // Lineage: every surviving claim resolved as an on-chain delete, in the
    // same transaction that tombstones the tracking rows and clears their
    // current-claim pointer. Object id backfilled from tracking in case
    // resolution landed after the claim copied a NULL.
    sqlx::query(
        "UPDATE deletion_batch_members m
         SET outcome=$2, resolved_at=NOW(),
             object_id=COALESCE(m.object_id, t.object_id)
         FROM delete_blobs_tracking t
         WHERE m.batch_id=$1 AND m.outcome=$3
           AND t.owner=m.owner AND t.blob_id=m.blob_id",
    )
    .bind(batch_id)
    .bind(BLOB_DELETED)
    .bind(MEMBER_CLAIMED)
    .execute(&mut **tx)
    .await
    .map_err(|error| storage("finalize batch members", error))?;
    Ok(Some(rows))
}

pub async fn get_batch(
    pool: &PgPool,
    batch_id: Uuid,
    owner: &str,
) -> Result<Option<BatchRow>, AppError> {
    sqlx::query_as::<_, BatchDbRow>(
        "SELECT id,owner,state,digest,tx_bytes,input_blob_ids,blob_count,nonce,
                expire_epoch,claimed_at,signatures,executing_at,last_submit_at,
                submit_attempts,resolved_at
         FROM deletion_batches WHERE id=$1 AND owner=$2",
    )
    .bind(batch_id)
    .bind(owner)
    .fetch_optional(pool)
    .await
    .map_err(|error| storage("get batch", error))?
    .map(TryInto::try_into)
    .transpose()
}

pub async fn stuck_batches(
    pool: &PgPool,
    awaiting_older_than: Duration,
    executing_older_than: Duration,
) -> Result<Vec<BatchRow>, AppError> {
    let awaiting_before = Utc::now() - awaiting_older_than;
    let executing_before = Utc::now() - executing_older_than;
    let rows = sqlx::query_as::<_, BatchDbRow>(
        "SELECT id,owner,state,digest,tx_bytes,input_blob_ids,blob_count,nonce,
                expire_epoch,claimed_at,signatures,executing_at,last_submit_at,
                submit_attempts,resolved_at FROM deletion_batches
         WHERE (state='awaiting_signature' AND claimed_at<$1)
            OR (state='executing' AND COALESCE(last_submit_at,executing_at,claimed_at)<$2)
         ORDER BY claimed_at,id",
    )
    .bind(awaiting_before)
    .bind(executing_before)
    .fetch_all(pool)
    .await
    .map_err(|error| storage("list stuck batches", error))?;
    rows.into_iter().map(TryInto::try_into).collect()
}

pub async fn sweep_candidates(
    pool: &PgPool,
    cursor: Option<SweepCursor>,
    limit: i64,
) -> Result<Vec<SweepRow>, AppError> {
    let (time, owner, blob) = cursor
        .map(|cursor| {
            (
                Some(cursor.updated_at),
                Some(cursor.owner),
                Some(cursor.blob_id),
            )
        })
        .unwrap_or((None, None, None));
    sqlx::query_as(
        "SELECT owner,blob_id,object_id,updated_at FROM delete_blobs_tracking
         WHERE state='deletable' AND object_id IS NOT NULL
           AND ($1::timestamptz IS NULL OR (updated_at,owner,blob_id)>($1,$2,$3))
         ORDER BY updated_at,owner,blob_id LIMIT $4",
    )
    .bind(time)
    .bind(owner)
    .bind(blob)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|error| storage("sweep candidates", error))
}

pub async fn sweep_mark_external(
    pool: &PgPool,
    owner: &str,
    blob_id: &str,
    to_state: &str,
) -> Result<bool, AppError> {
    if !matches!(
        to_state,
        BLOB_DELETED_EXTERNAL | BLOB_NOT_OWNER | BLOB_EXPIRED
    ) {
        return Err(AppError::BadRequest("invalid sweep state".into()));
    }
    let result = sqlx::query(
        "UPDATE delete_blobs_tracking SET state=$3,updated_at=NOW()
         WHERE owner=$1 AND blob_id=$2 AND state='deletable'",
    )
    .bind(owner)
    .bind(blob_id)
    .bind(to_state)
    .execute(pool)
    .await
    .map_err(|error| storage("mark swept blob", error))?;
    Ok(result.rows_affected() == 1)
}

pub async fn owners_needing_resolution(pool: &PgPool, limit: i64) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT t.owner FROM delete_blobs_tracking t
         LEFT JOIN deletion_job_state j ON j.key='resolver_completed:' || t.owner
         WHERE t.object_id IS NULL AND t.state='deletable'
           AND (j.value IS NULL OR t.tracked_seq > j.value::bigint)
         ORDER BY t.owner LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|error| storage("owners needing resolution", error))
}

pub async fn try_reserve_resolver_scan_fence(
    pool: &PgPool,
    owner: &str,
) -> Result<Option<i64>, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| storage("begin resolver scan fence", error))?;
    let fence = sqlx::query_scalar(
        "SELECT CASE
           WHEN pg_try_advisory_xact_lock(
             $1,
             hashtext(current_schema() || ':' || $2::text)
           )
           THEN nextval('delete_blobs_tracking_resolver_seq')
         END",
    )
    .bind(RESOLVER_OWNER_LOCK_NAMESPACE)
    .bind(owner)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| storage("try resolver owner lock", error))?;
    tx.commit()
        .await
        .map_err(|error| storage("commit resolver scan fence", error))?;
    Ok(fence)
}

pub async fn set_object_ids(
    pool: &PgPool,
    owner: &str,
    pairs: &[(String, String)],
) -> Result<u64, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| storage("begin object IDs", error))?;
    let mut updated = 0;
    for (blob_id, object_id) in pairs {
        updated += sqlx::query(
            "UPDATE delete_blobs_tracking SET object_id=$3,updated_at=NOW()
             WHERE owner=$1 AND blob_id=$2 AND object_id IS NULL AND state='deletable'",
        )
        .bind(owner)
        .bind(blob_id)
        .bind(object_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| storage("set object ID", error))?
        .rows_affected();
    }
    tx.commit()
        .await
        .map_err(|error| storage("commit object IDs", error))?;
    Ok(updated)
}

/// Resolve object ids for rows owned by one live prepare generation. The
/// batch predicate is mandatory: a slow owner scan from batch A must not
/// write through a rollback/reclaim into batch B.
pub async fn set_claimed_object_ids(
    pool: &PgPool,
    owner: &str,
    batch_id: Uuid,
    pairs: &[(String, String)],
) -> Result<u64, AppError> {
    if pairs.is_empty() {
        return Ok(0);
    }
    let blob_ids: Vec<&str> = pairs.iter().map(|(blob_id, _)| blob_id.as_str()).collect();
    let object_ids: Vec<&str> = pairs
        .iter()
        .map(|(_, object_id)| object_id.as_str())
        .collect();
    let updated: i64 = sqlx::query_scalar(
        "WITH input(blob_id,object_id) AS (
             SELECT * FROM unnest($4::text[],$5::text[])
         ), updated AS (
             UPDATE delete_blobs_tracking AS tracking
             SET object_id=input.object_id,updated_at=NOW()
             FROM input
             WHERE tracking.owner=$1 AND tracking.blob_id=input.blob_id
               AND tracking.batch_id=$2 AND tracking.state='deleting'
               AND tracking.object_id IS NULL
             RETURNING tracking.blob_id,tracking.object_id
         ), mirrored AS (
             UPDATE deletion_batch_members AS member
             SET object_id=updated.object_id
             FROM updated
             WHERE member.batch_id=$2 AND member.owner=$1
               AND member.blob_id=updated.blob_id AND member.outcome=$3
         )
         SELECT COUNT(*)::bigint FROM updated",
    )
    .bind(owner)
    .bind(batch_id)
    .bind(MEMBER_CLAIMED)
    .bind(blob_ids)
    .bind(object_ids)
    .fetch_one(pool)
    .await
    .map_err(|error| storage("set claimed object IDs", error))?;
    Ok(updated as u64)
}

pub async fn complete_resolver_scan(
    pool: &PgPool,
    owner: &str,
    scan_fence: i64,
) -> Result<u64, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| storage("begin resolver completion", error))?;
    let updated = sqlx::query(
        "UPDATE delete_blobs_tracking SET state='not_owner',updated_at=NOW()
         WHERE owner=$1 AND state='deletable' AND object_id IS NULL AND tracked_seq<$2",
    )
    .bind(owner)
    .bind(scan_fence)
    .execute(&mut *tx)
    .await
    .map_err(|error| storage("complete resolver rows", error))?
    .rows_affected();
    sqlx::query(
        "INSERT INTO deletion_job_state(key,value) VALUES ('resolver_completed:' || $1,$2)
         ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
    )
    .bind(owner)
    .bind(scan_fence.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|error| storage("save resolver scan fence", error))?;
    tx.commit()
        .await
        .map_err(|error| storage("commit resolver completion", error))?;
    Ok(updated)
}

pub async fn job_state_get(pool: &PgPool, key: &str) -> Result<Option<String>, AppError> {
    sqlx::query_scalar("SELECT value FROM deletion_job_state WHERE key=$1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(|error| storage("get job state", error))
}

pub async fn job_state_set(pool: &PgPool, key: &str, value: &str) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO deletion_job_state(key,value) VALUES($1,$2)
         ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .map_err(|error| storage("set job state", error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::legacy_db::tests::fixture;

    const OWNER: &str = "0x000000000000000000000000000000000000000000000000000000000000000a";

    async fn seed(pool: &PgPool, ids: &[&str]) {
        for (index, id) in ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO delete_blobs_tracking(owner,blob_id,created_at)
                 VALUES($1,$2,NOW()+($3 || ' milliseconds')::interval)",
            )
            .bind(OWNER)
            .bind(id)
            .bind(index.to_string())
            .execute(pool)
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_sweep_cursor_revisits_recently_updated_rows() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        sqlx::query(
            "INSERT INTO delete_blobs_tracking
                 (owner,blob_id,object_id,created_at,updated_at)
             VALUES
                 ($1,'rolled-back','0x01',NOW()-INTERVAL '2 days',NOW()-INTERVAL '2 days'),
                 ($1,'checkpoint','0x02',NOW()-INTERVAL '1 day',NOW()-INTERVAL '1 day')",
        )
        .bind(OWNER)
        .execute(legacy.pool())
        .await
        .unwrap();

        let initial = sweep_candidates(legacy.pool(), None, 2).await.unwrap();
        assert_eq!(
            initial
                .iter()
                .map(|row| row.blob_id.as_str())
                .collect::<Vec<_>>(),
            vec!["rolled-back", "checkpoint"]
        );
        let last = initial.last().unwrap();
        let cursor = SweepCursor {
            updated_at: last.updated_at,
            owner: last.owner.clone(),
            blob_id: last.blob_id.clone(),
        };

        // A TTL rollback updates an old row after the active cursor. It must be
        // eligible immediately instead of waiting for the cursor to wrap.
        sqlx::query(
            "UPDATE delete_blobs_tracking SET updated_at=NOW()
             WHERE owner=$1 AND blob_id='rolled-back'",
        )
        .bind(OWNER)
        .execute(legacy.pool())
        .await
        .unwrap();

        let resumed = sweep_candidates(legacy.pool(), Some(cursor), 2)
            .await
            .unwrap();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].blob_id, "rolled-back");

        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_claim_selection_is_all_or_nothing_and_aba_safe() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a", "b", "c"]).await;
        let first = Uuid::new_v4();
        create_batch_and_claim_selection(legacy.pool(), OWNER, first, &["b".into()], 16)
            .await
            .unwrap();
        let second = Uuid::new_v4();
        let result = create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            second,
            &["a".into(), "b".into(), "c".into()],
            16,
        )
        .await;
        assert!(matches!(result, Err(ClaimError::Conflict(ids)) if ids == vec!["b"]));
        assert!(get_batch(legacy.pool(), second, OWNER)
            .await
            .unwrap()
            .is_none());
        assert!(rollback_batch(
            legacy.pool(),
            first,
            BATCH_AWAITING_SIGNATURE,
            BATCH_ROLLED_BACK
        )
        .await
        .unwrap());
        let third = Uuid::new_v4();
        create_batch_and_claim_selection(legacy.pool(), OWNER, third, &["b".into()], 16)
            .await
            .unwrap();
        assert!(
            !evict_claimed_blob(legacy.pool(), OWNER, "b", first, BLOB_EXPIRED)
                .await
                .unwrap()
        );
        assert_eq!(
            set_claimed_object_ids(
                legacy.pool(),
                OWNER,
                first,
                &[("b".into(), "0xdead".into())],
            )
            .await
            .unwrap(),
            0
        );
        let row = batch_blobs(legacy.pool(), third, OWNER)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(row.batch_id, Some(third));
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_untracked_selection_cannot_enroll_blob() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        let batch = Uuid::new_v4();
        let result = create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            batch,
            &["wallet-owned-but-untracked".into()],
            16,
        )
        .await;
        assert!(
            matches!(result, Err(ClaimError::Conflict(ids)) if ids == vec!["wallet-owned-but-untracked"])
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM delete_blobs_tracking")
            .fetch_one(legacy.pool())
            .await
            .unwrap();
        let batches: i64 = sqlx::query_scalar("SELECT count(*) FROM deletion_batches")
            .fetch_one(legacy.pool())
            .await
            .unwrap();
        assert_eq!((rows, batches), (0, 0));
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_counts_and_pagination() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a", "b", "c", "d", "e"]).await;
        let first = list_blobs(legacy.pool(), OWNER, &[BLOB_DELETABLE], None, 2)
            .await
            .unwrap();
        let cursor = (first[1].created_at, first[1].blob_id.clone());
        let second = list_blobs(legacy.pool(), OWNER, &[BLOB_DELETABLE], Some(cursor), 10)
            .await
            .unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 3);
        let counts = counts(legacy.pool(), OWNER).await.unwrap();
        assert_eq!(counts.total, 5);
        assert_eq!(counts.deletable, 5);
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_active_cap_finalize_and_rollback_are_atomic() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a", "b"]).await;
        let first = Uuid::new_v4();
        create_batch_and_claim_selection(legacy.pool(), OWNER, first, &["a".into()], 1)
            .await
            .unwrap();
        let blocked = create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            Uuid::new_v4(),
            &["b".into()],
            1,
        )
        .await;
        assert!(matches!(blocked, Err(ClaimError::ActiveBatchLimit(ids)) if ids == vec![first]));
        assert!(cas_batch_state(
            legacy.pool(),
            first,
            BATCH_AWAITING_SIGNATURE,
            BATCH_EXECUTING
        )
        .await
        .unwrap());
        assert_eq!(
            finalize_batch_deleted(legacy.pool(), first, BATCH_EXECUTING)
                .await
                .unwrap(),
            Some(1)
        );
        let second = Uuid::new_v4();
        create_batch_and_claim_selection(legacy.pool(), OWNER, second, &["b".into()], 1)
            .await
            .unwrap();
        assert!(rollback_batch(
            legacy.pool(),
            second,
            BATCH_AWAITING_SIGNATURE,
            BATCH_ROLLED_BACK,
        )
        .await
        .unwrap());
        let states: Vec<String> = sqlx::query_scalar(
            "SELECT state FROM delete_blobs_tracking WHERE owner=$1 ORDER BY blob_id",
        )
        .bind(OWNER)
        .fetch_all(legacy.pool())
        .await
        .unwrap();
        assert_eq!(states, vec![BLOB_DELETED, BLOB_DELETABLE]);
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[derive(sqlx::FromRow)]
    struct MemberProbe {
        batch_id: Uuid,
        blob_id: String,
        object_id: Option<String>,
        outcome: String,
        resolved_at: Option<DateTime<Utc>>,
    }

    async fn members(pool: &PgPool) -> Vec<MemberProbe> {
        sqlx::query_as(
            "SELECT batch_id, blob_id, object_id, outcome, resolved_at
             FROM deletion_batch_members ORDER BY claimed_at, blob_id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_lineage_claim_finalize_preserves_members() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a", "b"]).await;
        let batch = Uuid::new_v4();
        create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            batch,
            &["a".into(), "b".into()],
            16,
        )
        .await
        .unwrap();
        // Members appear atomically with the claim, outcome 'claimed'.
        let claimed = members(legacy.pool()).await;
        assert_eq!(claimed.len(), 2);
        assert!(claimed.iter().all(|m| m.batch_id == batch
            && m.outcome == MEMBER_CLAIMED
            && m.resolved_at.is_none()));

        // Late object-id resolution propagates to the member row too.
        assert_eq!(
            set_claimed_object_ids(legacy.pool(), OWNER, batch, &[("a".into(), "0xaa".into())])
                .await
                .unwrap(),
            1
        );

        assert!(cas_batch_state(
            legacy.pool(),
            batch,
            BATCH_AWAITING_SIGNATURE,
            BATCH_EXECUTING
        )
        .await
        .unwrap());
        assert_eq!(
            finalize_batch_deleted(legacy.pool(), batch, BATCH_EXECUTING)
                .await
                .unwrap(),
            Some(2)
        );

        // Tracking rows lost their current-claim pointer; member history did not.
        let tracking_batches: Vec<Option<Uuid>> =
            sqlx::query_scalar("SELECT batch_id FROM delete_blobs_tracking ORDER BY blob_id")
                .fetch_all(legacy.pool())
                .await
                .unwrap();
        assert_eq!(tracking_batches, vec![None, None]);
        let finalized = members(legacy.pool()).await;
        assert_eq!(finalized.len(), 2);
        assert!(finalized
            .iter()
            .all(|m| m.batch_id == batch && m.outcome == BLOB_DELETED && m.resolved_at.is_some()));
        let member_a = finalized.iter().find(|m| m.blob_id == "a").unwrap();
        assert_eq!(member_a.object_id.as_deref(), Some("0xaa"));

        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_lineage_eviction_advances_one_member() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a", "b"]).await;
        let batch = Uuid::new_v4();
        create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            batch,
            &["a".into(), "b".into()],
            16,
        )
        .await
        .unwrap();
        assert!(
            evict_claimed_blob(legacy.pool(), OWNER, "a", batch, BLOB_DELETED_EXTERNAL)
                .await
                .unwrap()
        );
        let rows = members(legacy.pool()).await;
        let outcome_of = |blob: &str| {
            rows.iter()
                .find(|m| m.blob_id == blob)
                .map(|m| m.outcome.clone())
                .unwrap()
        };
        assert_eq!(outcome_of("a"), BLOB_DELETED_EXTERNAL);
        assert_eq!(outcome_of("b"), MEMBER_CLAIMED);
        // Eviction against a stale batch id must not touch the new claim's
        // member row (ABA guard extends to lineage).
        assert!(
            !evict_claimed_blob(legacy.pool(), OWNER, "b", Uuid::new_v4(), BLOB_EXPIRED)
                .await
                .unwrap()
        );
        assert_eq!(outcome_of("b"), MEMBER_CLAIMED);
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_lineage_rollback_releases_then_reclaim_appends() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a"]).await;
        let first = Uuid::new_v4();
        create_batch_and_claim_selection(legacy.pool(), OWNER, first, &["a".into()], 16)
            .await
            .unwrap();
        assert!(rollback_batch(
            legacy.pool(),
            first,
            BATCH_AWAITING_SIGNATURE,
            BATCH_ROLLED_BACK
        )
        .await
        .unwrap());
        let released = members(legacy.pool()).await;
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].outcome, MEMBER_RELEASED);
        assert!(released[0].resolved_at.is_some());

        // Re-claim after rollback appends a SECOND member row (new batch);
        // the released row is history and is never rewritten.
        let second = Uuid::new_v4();
        create_batch_and_claim_selection(legacy.pool(), OWNER, second, &["a".into()], 16)
            .await
            .unwrap();
        assert!(cas_batch_state(
            legacy.pool(),
            second,
            BATCH_AWAITING_SIGNATURE,
            BATCH_EXECUTING
        )
        .await
        .unwrap());
        finalize_batch_deleted(legacy.pool(), second, BATCH_EXECUTING)
            .await
            .unwrap();
        let history = members(legacy.pool()).await;
        assert_eq!(history.len(), 2);
        let outcome_of_batch = |batch: Uuid| {
            history
                .iter()
                .find(|m| m.batch_id == batch)
                .map(|m| m.outcome.clone())
                .unwrap()
        };
        assert_eq!(outcome_of_batch(first), MEMBER_RELEASED);
        assert_eq!(outcome_of_batch(second), BLOB_DELETED);
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_lineage_concurrent_claim_single_winner() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a"]).await;
        let contested: Vec<String> = vec!["a".into()];
        let (left, right) = tokio::join!(
            create_batch_and_claim_selection(legacy.pool(), OWNER, Uuid::new_v4(), &contested, 16),
            create_batch_and_claim_selection(legacy.pool(), OWNER, Uuid::new_v4(), &contested, 16),
        );
        assert_eq!(
            [&left, &right].iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one concurrent claim must win"
        );
        assert!([&left, &right]
            .iter()
            .any(|r| matches!(r, Err(ClaimError::Conflict(_)))));
        // Exactly one 'claimed' member exists -- the loser's transaction
        // rolled back its batch AND its (never-visible) member insert.
        let rows = members(legacy.pool()).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, MEMBER_CLAIMED);
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_concurrent_claim_all_is_disjoint() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(
            legacy.pool(),
            &["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
        )
        .await;
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let (left, right) = tokio::join!(
            create_batch_and_claim_all(legacy.pool(), OWNER, a, 6, 16),
            create_batch_and_claim_all(legacy.pool(), OWNER, b, 6, 16),
        );
        let left: HashSet<String> = left
            .unwrap()
            .rows
            .into_iter()
            .map(|row| row.blob_id)
            .collect();
        let right: HashSet<String> = right
            .unwrap()
            .rows
            .into_iter()
            .map(|row| row.blob_id)
            .collect();
        assert!(left.is_disjoint(&right));
        assert_eq!(left.len() + right.len(), 10);
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_store_concurrent_active_cap_is_exact() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), &["a", "b", "c", "d"]).await;
        let ids = [
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        ];
        let pool = legacy.pool().clone();
        let futures = ids
            .iter()
            .copied()
            .zip(["a", "b", "c", "d"])
            .map(|(batch, blob)| {
                let pool = pool.clone();
                async move {
                    let blobs = vec![blob.to_owned()];
                    create_batch_and_claim_selection(&pool, OWNER, batch, &blobs, 2).await
                }
            });
        let results = futures::future::join_all(futures).await;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ClaimError::ActiveBatchLimit(_))))
                .count(),
            2
        );
        assert_eq!(
            active_batch_ids(legacy.pool(), OWNER).await.unwrap().len(),
            2
        );
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }
}
