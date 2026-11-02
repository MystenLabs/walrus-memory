//! Idempotent security-delete background jobs.

use crate::security_delete_auth::same_owner;
use crate::storage::security_delete_store as store;
use crate::sui::input_freshness::{self, StaleInputReason};
use crate::sui::{ObjectInfo, SuiApi, SuiEpoch, SuiErr, WalrusEpoch, WalrusEpochSchedule};
use crate::types::{AppError, AppState, SecurityDeleteExecutionGate};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

const SWEEP_CURSOR_KEY: &str = "reconciler_sweep_cursor:v2";
const MAX_EXEC_RETRY_BACKOFF_SHIFT: u32 = 2;

#[derive(Clone, Debug)]
pub struct ReconcilerCfg {
    pub claim_ttl: Duration,
    pub exec_grace: Duration,
    pub sweep_page: i64,
    pub expiry_margin_epochs: u64,
    pub sponsor_address: Option<String>,
    pub sponsor_min_balance: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    pub rolled_back: u64,
    pub finalized: u64,
    pub failed: u64,
    pub retried: u64,
    pub swept: u64,
    pub low_balance: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolverReport {
    pub resolved: u64,
    pub marked_not_owner: u64,
    pub owners_completed: u64,
    pub owners_deferred: u64,
}

fn execution_retry_delay(
    base: Duration,
    submit_attempts: i32,
) -> Result<chrono::Duration, AppError> {
    let base = chrono::Duration::from_std(base)
        .map_err(|_| AppError::BadRequest("execution grace is too large".into()))?;
    let shift = submit_attempts
        .saturating_sub(1)
        .clamp(0, MAX_EXEC_RETRY_BACKOFF_SHIFT as i32) as u32;
    base.checked_mul(1_i32 << shift)
        .ok_or_else(|| AppError::BadRequest("execution retry delay is too large".into()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SweepCheckpoint {
    v: u8,
    updated_at: DateTime<Utc>,
    owner: String,
    blob_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolverCheckpoint {
    v: u8,
    scan_fence: i64,
    cursor: Option<String>,
    completed_fence: Option<i64>,
}

pub async fn run_reconciler_tick(
    pool: &PgPool,
    sui: &dyn SuiApi,
    execution_gate: &SecurityDeleteExecutionGate,
    cfg: &ReconcilerCfg,
) -> Result<TickReport, AppError> {
    if cfg.sweep_page <= 0 {
        return Err(AppError::BadRequest(
            "reconciler sweep_page must be positive".into(),
        ));
    }
    let mut report = TickReport::default();
    let batches = store::stuck_batches(
        pool,
        chrono::Duration::from_std(cfg.claim_ttl)
            .map_err(|_| AppError::BadRequest("claim TTL is too large".into()))?,
        chrono::Duration::from_std(cfg.exec_grace)
            .map_err(|_| AppError::BadRequest("execution grace is too large".into()))?,
    )
    .await?;

    for batch in batches {
        match batch.state.as_str() {
            store::BATCH_AWAITING_SIGNATURE => {
                if store::rollback_batch(
                    pool,
                    batch.id,
                    store::BATCH_AWAITING_SIGNATURE,
                    store::BATCH_ROLLED_BACK,
                )
                .await?
                {
                    report.rolled_back += 1;
                }
            }
            store::BATCH_EXECUTING => {
                let Some(digest) = batch.digest.as_deref() else {
                    if store::rollback_batch(
                        pool,
                        batch.id,
                        store::BATCH_EXECUTING,
                        store::BATCH_FAILED,
                    )
                    .await?
                    {
                        report.failed += 1;
                    }
                    continue;
                };
                match sui.get_tx_status(digest).await.map_err(sui_error)? {
                    Some(result) if result.success() => {
                        if store::finalize_batch_deleted(pool, batch.id, store::BATCH_EXECUTING)
                            .await?
                            .is_some()
                        {
                            report.finalized += 1;
                        }
                    }
                    Some(result) => {
                        resolve_failed_batch(pool, sui, &batch, &result.status, cfg).await?;
                        if store::rollback_batch(
                            pool,
                            batch.id,
                            store::BATCH_EXECUTING,
                            store::BATCH_FAILED,
                        )
                        .await?
                        {
                            report.failed += 1;
                        }
                    }
                    None => {
                        if sui.current_epoch().await.map_err(sui_error)?.get()
                            > batch.expire_epoch as u64
                        {
                            if store::rollback_batch(
                                pool,
                                batch.id,
                                store::BATCH_EXECUTING,
                                store::BATCH_FAILED,
                            )
                            .await?
                            {
                                report.failed += 1;
                            }
                            continue;
                        }

                        let (Some(tx_bytes), Some(signatures)) =
                            (batch.tx_bytes.as_deref(), batch.signatures.clone())
                        else {
                            // Rows created before durable submissions were
                            // introduced can only use the epoch safety path.
                            continue;
                        };
                        let execution_permit = execution_gate.acquire().await;
                        if !store::claim_batch_retry(
                            pool,
                            batch.id,
                            execution_retry_delay(cfg.exec_grace, batch.submit_attempts)?,
                        )
                        .await?
                        {
                            continue;
                        }
                        report.retried += 1;
                        if resolve_stale_retry_inputs(pool, sui, &batch, tx_bytes).await? {
                            report.failed += 1;
                            continue;
                        }
                        let execution = sui.execute_tx(tx_bytes, signatures).await;
                        drop(execution_permit);
                        match execution {
                            Ok(result) if result.digest != digest => {
                                tracing::error!(
                                    batch_id = %batch.id,
                                    expected_digest = %digest,
                                    returned_digest = %result.digest,
                                    "security-delete retry returned a different digest"
                                );
                            }
                            Ok(result) if result.success() => {
                                if store::finalize_batch_deleted(
                                    pool,
                                    batch.id,
                                    store::BATCH_EXECUTING,
                                )
                                .await?
                                .is_some()
                                {
                                    report.finalized += 1;
                                }
                            }
                            Ok(result) => {
                                resolve_failed_batch(pool, sui, &batch, &result.status, cfg)
                                    .await?;
                                if store::rollback_batch(
                                    pool,
                                    batch.id,
                                    store::BATCH_EXECUTING,
                                    store::BATCH_FAILED,
                                )
                                .await?
                                {
                                    report.failed += 1;
                                }
                            }
                            Err(error) => {
                                tracing::warn!(
                                    batch_id = %batch.id,
                                    %error,
                                    "security-delete retry remains outcome-unknown"
                                );
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    report.swept = run_sweep_page(pool, sui, cfg).await?;
    check_sponsor_balance(sui, cfg, &mut report).await?;
    Ok(report)
}

async fn resolve_stale_retry_inputs(
    pool: &PgPool,
    sui: &dyn SuiApi,
    batch: &store::BatchRow,
    tx_bytes: &[u8],
) -> Result<bool, AppError> {
    // A batch prepared before a Walrus package upgrade has the SUPERSEDED package baked into
    // its persisted tx_bytes. Re-executing it aborts `EWrongVersion` every time, so retrying
    // only burns sponsor gas on a transaction that can never land. Fail it now and release
    // the rows — the client's RE_PREPARE rebuilds against the current package.
    if let Some(tx_package) =
        input_freshness::transaction_package(tx_bytes).map_err(AppError::Internal)?
    {
        // This guard is an OPTIMISATION — it saves sponsor gas on a transaction that cannot
        // land. It must degrade gracefully: this is the recovery path, and aborting the tick
        // on a transient system-object read would break the very thing that recovers from
        // transient failures. If the read fails we simply proceed; a genuinely superseded
        // package still aborts on chain and `FailureClass::WholeTransaction` releases every
        // row without evicting any.
        let current = match sui.walrus_system_object().await {
            Ok(system) => system
                .package_id
                .as_deref()
                // Parsed addresses, never strings: the chain returns canonical 32-byte form
                // while config may be short-hand, and a string compare would differ on
                // formatting alone.
                .and_then(|id| id.parse::<sui_sdk_types::Address>().ok()),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    batch_id = %batch.id,
                    "could not read the Walrus system object; skipping the stale-package check"
                );
                None
            }
        };
        if let Some(current) = current {
            if tx_package != current {
                tracing::warn!(
                    batch_id = %batch.id,
                    tx_package = %tx_package,
                    current_package = %current,
                    "prepared batch targets a superseded Walrus package; failing without retry"
                );
                let _ = store::rollback_batch(
                    pool,
                    batch.id,
                    store::BATCH_EXECUTING,
                    store::BATCH_FAILED,
                )
                .await?;
                return Ok(true);
            }
        }
    }
    let Some(input_blob_ids) = batch.input_blob_ids.as_ref() else {
        return Ok(false);
    };
    let expected =
        input_freshness::expected_inputs(tx_bytes, input_blob_ids).map_err(AppError::Internal)?;
    let objects = input_freshness::fetch_current(sui, &expected)
        .await
        .map_err(sui_error)?;
    let stale = input_freshness::stale_inputs(&batch.owner, &expected, &objects)
        .map_err(AppError::Internal)?;
    if stale.is_empty() {
        return Ok(false);
    }
    for input in stale {
        let terminal = match input.reason {
            StaleInputReason::DeletedExternal => Some(store::BLOB_DELETED_EXTERNAL),
            StaleInputReason::NotOwner => Some(store::BLOB_NOT_OWNER),
            StaleInputReason::ChangedReference => None,
        };
        if let Some(terminal) = terminal {
            let _ =
                store::evict_claimed_blob(pool, &batch.owner, &input.blob_id, batch.id, terminal)
                    .await?;
        }
    }
    let _ =
        store::rollback_batch(pool, batch.id, store::BATCH_EXECUTING, store::BATCH_FAILED).await?;
    Ok(true)
}

async fn check_sponsor_balance(
    sui: &dyn SuiApi,
    cfg: &ReconcilerCfg,
    report: &mut TickReport,
) -> Result<(), AppError> {
    let Some(address) = cfg.sponsor_address.as_deref() else {
        return Ok(());
    };
    let balance = sui.address_balance(address).await.map_err(sui_error)?;
    report.low_balance = balance < cfg.sponsor_min_balance;
    if report.low_balance {
        tracing::warn!(
            sponsor = %address,
            balance_mist = balance,
            threshold_mist = cfg.sponsor_min_balance,
            "security-delete sponsor balance below configured threshold"
        );
    }
    Ok(())
}

async fn resolve_failed_batch(
    pool: &PgPool,
    sui: &dyn SuiApi,
    batch: &store::BatchRow,
    status: &sui_sdk_types::ExecutionStatus,
    cfg: &ReconcilerCfg,
) -> Result<(), AppError> {
    use crate::sui::classify::{classify_execution_failure, FailureClass};
    let rows = store::batch_blobs(pool, batch.id, &batch.owner).await?;
    let candidates = match classify_execution_failure(status) {
        FailureClass::CulpritInput { input_index } if input_index > 0 => {
            let Some(blob_id) = batch
                .input_blob_ids
                .as_ref()
                .and_then(|ids| ids.get(input_index - 1))
            else {
                return resolve_ambiguous_rows(pool, sui, batch, &rows, cfg).await;
            };
            rows.iter()
                .filter(|row| &row.blob_id == blob_id)
                .cloned()
                .collect()
        }
        FailureClass::SharedObjectCongestion => Vec::new(),
        // The transaction is unexecutable as a whole (e.g. Walrus upgraded its package and
        // the persisted tx_bytes call the superseded one). No blob is at fault, so evict
        // NOTHING: every row is released by the caller's rollback and re-offered. Running
        // these blobs through the eviction path would terminalize live ones `expired` —
        // permanently — for a reason that has nothing to do with them.
        FailureClass::WholeTransaction { reason } => {
            tracing::warn!(
                batch_id = %batch.id,
                reason,
                "security-delete batch failed wholesale; releasing all rows, evicting none"
            );
            Vec::new()
        }
        _ => rows,
    };
    resolve_ambiguous_rows(pool, sui, batch, &candidates, cfg).await
}

async fn resolve_ambiguous_rows(
    pool: &PgPool,
    sui: &dyn SuiApi,
    batch: &store::BatchRow,
    rows: &[store::BlobRow],
    cfg: &ReconcilerCfg,
) -> Result<(), AppError> {
    let with_ids = rows
        .iter()
        .filter_map(|row| row.object_id.as_ref().map(|id| (row, id.clone())))
        .collect::<Vec<_>>();
    if with_ids.is_empty() {
        return Ok(());
    }
    let objects = sui
        .batch_get_objects(
            &with_ids
                .iter()
                .map(|(_, id)| id.clone())
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(sui_error)?;
    // Walrus epoch: `end_epoch` is a Walrus epoch, not a Sui one.
    let epoch = sui.walrus_epoch().await.map_err(sui_error)?;
    for ((row, _), object) in with_ids.into_iter().zip(objects) {
        if let Some(state) = terminal_state(
            object.as_ref(),
            &row.blob_id,
            &batch.owner,
            epoch,
            cfg.expiry_margin_epochs,
        ) {
            let _ = store::evict_claimed_blob(pool, &batch.owner, &row.blob_id, batch.id, state)
                .await?;
        }
    }
    Ok(())
}

async fn run_sweep_page(
    pool: &PgPool,
    sui: &dyn SuiApi,
    cfg: &ReconcilerCfg,
) -> Result<u64, AppError> {
    let cursor = store::job_state_get(pool, SWEEP_CURSOR_KEY)
        .await?
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            serde_json::from_str::<SweepCheckpoint>(&raw)
                .map_err(|error| AppError::Internal(format!("decode sweep cursor: {error}")))
        })
        .transpose()?;
    let candidates = store::sweep_candidates(
        pool,
        cursor.map(|cursor| store::SweepCursor {
            updated_at: cursor.updated_at,
            owner: cursor.owner,
            blob_id: cursor.blob_id,
        }),
        cfg.sweep_page,
    )
    .await?;
    if candidates.is_empty() {
        store::job_state_set(pool, SWEEP_CURSOR_KEY, "").await?;
        return Ok(0);
    }
    let objects = sui
        .batch_get_objects(
            &candidates
                .iter()
                .filter_map(|row| row.object_id.clone())
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(sui_error)?;
    // Walrus epoch: `end_epoch` is a Walrus epoch, not a Sui one.
    let epoch = sui.walrus_epoch().await.map_err(sui_error)?;
    let mut swept = 0;
    for (row, object) in candidates.iter().zip(objects) {
        if let Some(state) = terminal_state(
            object.as_ref(),
            &row.blob_id,
            &row.owner,
            epoch,
            cfg.expiry_margin_epochs,
        ) {
            if store::sweep_mark_external(pool, &row.owner, &row.blob_id, state).await? {
                swept += 1;
            }
        }
    }
    let last = candidates.last().expect("non-empty candidates");
    store::job_state_set(
        pool,
        SWEEP_CURSOR_KEY,
        &serde_json::to_string(&SweepCheckpoint {
            v: 2,
            updated_at: last.updated_at,
            owner: last.owner.clone(),
            blob_id: last.blob_id.clone(),
        })
        .map_err(|error| AppError::Internal(format!("encode sweep cursor: {error}")))?,
    )
    .await?;
    Ok(swept)
}

/// Every state this returns is TERMINAL: the blob is never re-offered for deletion, so a
/// wrong answer here leaves the user's exposed data readable on Walrus for good. Prefer
/// returning `None` (leave the row alone, re-examine next tick) over a guess.
fn terminal_state(
    object: Option<&ObjectInfo>,
    expected_blob_id: &str,
    expected_owner: &str,
    epoch: WalrusEpoch,
    expiry_margin: u64,
) -> Option<&'static str> {
    let Some(object) = object else {
        return Some(store::BLOB_DELETED_EXTERNAL);
    };
    // Callers zip rows against `batch_get_objects` results positionally. That alignment holds
    // today, but a misalignment here would terminalize rows against another blob's object, so
    // confirm the object is the one we asked about rather than relying on the ordering.
    if object.blob_id.as_deref() != Some(expected_blob_id) {
        return None;
    }
    if !same_owner(object.owner.as_deref(), expected_owner) {
        return Some(store::BLOB_NOT_OWNER);
    }
    if object
        .end_epoch
        .is_some_and(|end| end.is_at_or_before(epoch, expiry_margin))
    {
        return Some(store::BLOB_EXPIRED);
    }
    None
}

pub async fn run_resolver_tick(
    pool: &PgPool,
    sui: &dyn SuiApi,
    owners_per_tick: i64,
) -> Result<ResolverReport, AppError> {
    if owners_per_tick <= 0 {
        return Err(AppError::BadRequest(
            "owners_per_tick must be positive".into(),
        ));
    }
    let owners = store::owners_needing_resolution(pool, owners_per_tick).await?;
    let mut report = ResolverReport::default();
    for owner in owners {
        let key = format!("resolver_checkpoint:{owner}");
        let checkpoint = store::job_state_get(pool, &key).await?;
        let mut checkpoint = match checkpoint.as_deref().filter(|raw| !raw.is_empty()) {
            Some(raw) => serde_json::from_str::<ResolverCheckpoint>(raw).map_err(|error| {
                AppError::Internal(format!("decode resolver checkpoint: {error}"))
            })?,
            None => {
                let Some(scan_fence) = store::try_reserve_resolver_scan_fence(pool, &owner).await?
                else {
                    report.owners_deferred += 1;
                    continue;
                };
                ResolverCheckpoint {
                    v: 1,
                    scan_fence,
                    cursor: None,
                    completed_fence: None,
                }
            }
        };
        if checkpoint.cursor.is_none() && checkpoint.completed_fence.is_some() {
            let Some(scan_fence) = store::try_reserve_resolver_scan_fence(pool, &owner).await?
            else {
                report.owners_deferred += 1;
                continue;
            };
            checkpoint.scan_fence = scan_fence;
        }
        persist_resolver_checkpoint(pool, &key, &checkpoint).await?;
        loop {
            let requested_cursor = checkpoint.cursor.clone();
            let (blobs, next) = sui
                .list_owned_blobs(&owner, requested_cursor.clone())
                .await
                .map_err(sui_error)?;
            report.resolved += store::set_object_ids(
                pool,
                &owner,
                &blobs
                    .into_iter()
                    .map(|blob| (blob.blob_id, blob.object_id))
                    .collect::<Vec<_>>(),
            )
            .await?;
            if next.is_some() && next == requested_cursor {
                return Err(AppError::Internal(
                    "resolver RPC returned a non-advancing cursor".into(),
                ));
            }
            checkpoint.cursor = next;
            persist_resolver_checkpoint(pool, &key, &checkpoint).await?;
            if checkpoint.cursor.is_none() {
                break;
            }
        }
        report.marked_not_owner +=
            store::complete_resolver_scan(pool, &owner, checkpoint.scan_fence).await?;
        report.owners_completed += 1;
        checkpoint.completed_fence = Some(checkpoint.scan_fence);
        persist_resolver_checkpoint(pool, &key, &checkpoint).await?;
    }
    Ok(report)
}

async fn persist_resolver_checkpoint(
    pool: &PgPool,
    key: &str,
    checkpoint: &ResolverCheckpoint,
) -> Result<(), AppError> {
    let value = serde_json::to_string(checkpoint)
        .map_err(|error| AppError::Internal(format!("encode resolver checkpoint: {error}")))?;
    store::job_state_set(pool, key, &value).await
}

fn sui_error(error: SuiErr) -> AppError {
    AppError::UpstreamUnavailable(format!("security-delete Sui RPC: {error}"))
}

fn background_deletion_pools(state: &AppState) -> Vec<(&'static str, &PgPool)> {
    let mut pools = Vec::with_capacity(2);
    if let Some(legacy_db) = state.legacy_db.as_deref() {
        pools.push(("legacy", legacy_db.pool()));
    }
    if state.config.legacy_db_url.as_deref() != Some(state.config.database_url.as_str()) {
        pools.push(("current", state.db.pool()));
    }
    pools
}

pub fn spawn_reconciler(state: Arc<AppState>) {
    if !state.config.deletion_reconciler_enabled {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if !state.config.deletion_reconciler_enabled {
                continue;
            }
            let Some(sui) = &state.security_delete_background_sui else {
                tracing::error!("security-delete reconciler dependencies unavailable");
                continue;
            };
            let pools = background_deletion_pools(&state);
            if pools.is_empty() {
                tracing::error!("security-delete reconciler has no configured database pools");
                continue;
            }
            let sponsor_address = state.config.sponsor_private_key.as_deref().and_then(|key| {
                crate::sui::tx_build::sponsor_address(key)
                    .map_err(|error| tracing::error!(%error, "invalid security-delete sponsor key"))
                    .ok()
            });
            let cfg = ReconcilerCfg {
                claim_ttl: Duration::from_secs(state.config.claim_ttl_secs),
                exec_grace: Duration::from_secs(state.config.exec_grace_secs),
                sweep_page: 500,
                expiry_margin_epochs: state.config.expiry_margin_epochs,
                sponsor_address,
                sponsor_min_balance: state.config.sponsor_min_balance_alert,
            };
            for (scope, pool) in pools {
                match run_reconciler_tick(
                    pool,
                    sui.as_ref(),
                    state.security_delete_execution_gate.as_ref(),
                    &cfg,
                )
                .await
                {
                    Ok(report) => {
                        tracing::info!(scope, ?report, "security-delete reconciler tick completed")
                    }
                    Err(error) => {
                        tracing::error!(scope, %error, "security-delete reconciler tick failed")
                    }
                }
            }
        }
    });
}

pub fn spawn_object_resolver(state: Arc<AppState>) {
    if !state.config.deletion_object_resolver_enabled {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if !state.config.deletion_object_resolver_enabled {
                continue;
            }
            let Some(sui) = &state.security_delete_background_sui else {
                tracing::error!("security-delete resolver dependencies unavailable");
                continue;
            };
            let pools = background_deletion_pools(&state);
            if pools.is_empty() {
                tracing::error!("security-delete resolver has no configured database pools");
                continue;
            }
            for (scope, pool) in pools {
                match run_resolver_tick(pool, sui.as_ref(), 25).await {
                    Ok(report) => {
                        tracing::info!(scope, ?report, "security-delete resolver tick completed")
                    }
                    Err(error) => {
                        tracing::error!(scope, %error, "security-delete resolver tick failed")
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::legacy_db::tests::fixture;
    use crate::sui::tx_build::{build_delete_tx, BuiltTx};
    use crate::sui::WalrusCallPackage;
    use crate::sui::{ExecResult, OwnedBlob, SharedObjectInfo};
    use async_trait::async_trait;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use sui_sdk_types::{Digest, ExecutionError, ExecutionStatus};
    use tokio::sync::Notify;
    use uuid::Uuid;

    const OWNER: &str = "0x000000000000000000000000000000000000000000000000000000000000000a";

    type OwnedBlobPage = Result<(Vec<OwnedBlob>, Option<String>), SuiErr>;

    fn execution_gate() -> SecurityDeleteExecutionGate {
        SecurityDeleteExecutionGate::new(1)
    }

    struct JobMockSui {
        objects: Mutex<HashMap<String, ObjectInfo>>,
        statuses: Mutex<HashMap<String, Option<ExecResult>>>,
        execution_results: Mutex<VecDeque<Result<ExecResult, SuiErr>>>,
        pages: Mutex<HashMap<Option<String>, VecDeque<OwnedBlobPage>>>,
        epoch: SuiEpoch,
        walrus_epoch: WalrusEpoch,
        walrus_epoch_schedule: WalrusEpochSchedule,
        balance: u64,
        execute_calls: AtomicUsize,
        list_calls: AtomicUsize,
        status_started: Option<Arc<Notify>>,
        status_continue: Option<Arc<Notify>>,
        list_started: Option<Arc<Notify>>,
        list_continue: Option<Arc<Notify>>,
    }

    /// Sui and Walrus clocks DIVERGE by default, as on any long-running network. Fixtures
    /// with numerically-compatible clocks are exactly what hid the epoch-conflation bug, so
    /// the default must make a mix-up visible rather than benign.
    impl Default for JobMockSui {
        fn default() -> Self {
            Self {
                objects: Default::default(),
                statuses: Default::default(),
                execution_results: Default::default(),
                pages: Default::default(),
                epoch: SuiEpoch(1159),
                walrus_epoch: WalrusEpoch(457),
                // Arbitrary but internally consistent 1-day-epoch schedule; no fixture in
                // this file asserts a specific `expires_at_from_epoch` result against it.
                walrus_epoch_schedule: WalrusEpochSchedule {
                    epoch_duration_ms: 86_400_000,
                    first_epoch_start_ms: 1_700_000_000_000,
                },
                balance: 0,
                execute_calls: Default::default(),
                list_calls: Default::default(),
                status_started: None,
                status_continue: None,
                list_started: None,
                list_continue: None,
            }
        }
    }

    #[async_trait]
    impl SuiApi for JobMockSui {
        async fn batch_get_objects(
            &self,
            ids: &[String],
        ) -> Result<Vec<Option<ObjectInfo>>, SuiErr> {
            let objects = self.objects.lock().unwrap();
            Ok(ids.iter().map(|id| objects.get(id).cloned()).collect())
        }
        async fn current_epoch(&self) -> Result<SuiEpoch, SuiErr> {
            Ok(self.epoch)
        }
        async fn walrus_epoch(&self) -> Result<WalrusEpoch, SuiErr> {
            Ok(self.walrus_epoch)
        }
        async fn walrus_epoch_schedule(&self) -> Result<WalrusEpochSchedule, SuiErr> {
            Ok(self.walrus_epoch_schedule)
        }
        async fn reference_gas_price(&self) -> Result<u64, SuiErr> {
            Ok(1)
        }
        async fn execute_tx(&self, _: &[u8], _: Vec<Vec<u8>>) -> Result<ExecResult, SuiErr> {
            self.execute_calls.fetch_add(1, Ordering::SeqCst);
            self.execution_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(SuiErr::Rejected("unused".into())))
        }
        async fn get_tx_status(&self, digest: &str) -> Result<Option<ExecResult>, SuiErr> {
            if let Some(started) = &self.status_started {
                started.notify_one();
            }
            if let Some(resume) = &self.status_continue {
                resume.notified().await;
            }
            Ok(self.statuses.lock().unwrap().get(digest).cloned().flatten())
        }
        async fn list_owned_blobs(
            &self,
            _: &str,
            cursor: Option<String>,
        ) -> Result<(Vec<OwnedBlob>, Option<String>), SuiErr> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = &self.list_started {
                started.notify_one();
            }
            if let Some(resume) = &self.list_continue {
                resume.notified().await;
            }
            self.pages
                .lock()
                .unwrap()
                .get_mut(&cursor)
                .and_then(VecDeque::pop_front)
                .unwrap_or_else(|| Ok((Vec::new(), None)))
        }
        async fn chain_id(&self) -> Result<[u8; 32], SuiErr> {
            Ok([0; 32])
        }
        async fn address_balance(&self, _: &str) -> Result<u64, SuiErr> {
            Ok(self.balance)
        }
        async fn walrus_system_object(&self) -> Result<SharedObjectInfo, SuiErr> {
            Err(SuiErr::Rejected("unused".into()))
        }
    }

    fn cfg() -> ReconcilerCfg {
        ReconcilerCfg {
            claim_ttl: Duration::from_secs(60),
            exec_grace: Duration::from_secs(60),
            sweep_page: 100,
            expiry_margin_epochs: 0,
            sponsor_address: Some(OWNER.into()),
            sponsor_min_balance: 10,
        }
    }

    async fn seed(pool: &PgPool, blob: &str, object: Option<&str>) {
        sqlx::query("INSERT INTO delete_blobs_tracking(owner,blob_id,object_id,created_at) VALUES($1,$2,$3,NOW())")
            .bind(OWNER).bind(blob).bind(object).execute(pool).await.unwrap();
    }

    /// A live blob, owned by `OWNER`, with storage well past the current Walrus epoch.
    fn healthy_object(blob_id: &str, owner: &str) -> ObjectInfo {
        ObjectInfo {
            object_id: "0xobj".into(),
            version: 1,
            digest: Digest::new([7; 32]).to_string(),
            owner: Some(owner.into()),
            blob_id: Some(blob_id.into()),
            end_epoch: Some(WalrusEpoch(9_000)),
            package_id: None,
        }
    }

    /// An RPC may return any valid text form of an address. Comparing it raw against the
    /// canonical owner we hold marks a healthy blob `not_owner` — which is TERMINAL, so the
    /// user's exposed blob would never be offered for deletion again.
    #[test]
    fn terminal_state_accepts_non_canonical_owner_forms() {
        // Same address as OWNER: short-hand, and mixed-case. Both are valid on the wire.
        for owner in ["0xA", "0xa", &OWNER.to_uppercase().replace("0X", "0x")] {
            let object = healthy_object("blob-1", owner);
            assert_eq!(
                terminal_state(Some(&object), "blob-1", OWNER, WalrusEpoch(457), 1),
                None,
                "owner form {owner} must not terminalize a healthy blob",
            );
        }
    }

    #[test]
    fn terminal_state_still_rejects_a_genuinely_different_owner() {
        let object = healthy_object(
            "blob-1",
            "0x00000000000000000000000000000000000000000000000000000000000000ff",
        );
        assert_eq!(
            terminal_state(Some(&object), "blob-1", OWNER, WalrusEpoch(457), 1),
            Some(store::BLOB_NOT_OWNER),
        );
    }

    /// Callers zip rows against `batch_get_objects` positionally. If that alignment ever slips,
    /// we must not terminalize our row against another blob's object. The decoy is one that
    /// WOULD be terminalized (expired, foreign owner) if we mistook it for ours — otherwise the
    /// assertion passes for the wrong reason and the check is untested.
    #[test]
    fn terminal_state_ignores_an_object_for_a_different_blob() {
        let mut decoy = healthy_object(
            "blob-OTHER",
            "0x00000000000000000000000000000000000000000000000000000000000000ff",
        );
        decoy.end_epoch = Some(WalrusEpoch(1));
        assert_eq!(
            terminal_state(Some(&decoy), "blob-1", OWNER, WalrusEpoch(457), 1),
            None,
            "an object for another blob must never terminalize this row",
        );
    }

    fn prepared_blob_tx(blob_id: &str, object_id: &str) -> (BuiltTx, ObjectInfo) {
        let object = ObjectInfo {
            object_id: object_id.into(),
            version: 1,
            digest: Digest::new([7; 32]).to_string(),
            owner: Some(OWNER.into()),
            blob_id: Some(blob_id.into()),
            end_epoch: Some(WalrusEpoch(500)),
            package_id: None,
        };
        let built = build_delete_tx(
            OWNER,
            "0xb",
            std::slice::from_ref(&object),
            WalrusCallPackage::from_chain("0xc"),
            &SharedObjectInfo {
                object_id: "0xd".into(),
                initial_shared_version: 1,
                mutable: true,
                package_id: None,
            },
            SuiEpoch(9),
            1,
            20_000_000,
            &[4; 32],
            3,
        )
        .unwrap();
        (built, object)
    }

    async fn cleanup(legacy: crate::storage::legacy_db::LegacyDb, admin: PgPool, schema: String) {
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[test]
    fn execution_retries_back_off_and_cap() {
        let base = Duration::from_secs(120);
        assert_eq!(execution_retry_delay(base, 1).unwrap().num_seconds(), 120);
        assert_eq!(execution_retry_delay(base, 2).unwrap().num_seconds(), 240);
        assert_eq!(execution_retry_delay(base, 3).unwrap().num_seconds(), 480);
        assert_eq!(execution_retry_delay(base, 20).unwrap().num_seconds(), 480);
    }

    #[tokio::test]
    async fn sponsor_balance_below_configured_threshold_sets_report() {
        let sui = JobMockSui {
            balance: 9,
            ..Default::default()
        };
        let cfg = cfg();
        let mut report = TickReport::default();
        check_sponsor_balance(&sui, &cfg, &mut report)
            .await
            .unwrap();
        assert!(report.low_balance);

        let sui = JobMockSui {
            balance: cfg.sponsor_min_balance,
            ..Default::default()
        };
        check_sponsor_balance(&sui, &cfg, &mut report)
            .await
            .unwrap();
        assert!(!report.low_balance);
    }

    #[tokio::test]
    #[ignore]
    async fn reconciler_rolls_back_expired_claim_and_is_idempotent() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "a", Some("0x1")).await;
        let batch = Uuid::new_v4();
        store::create_batch_and_claim_selection(legacy.pool(), OWNER, batch, &["a".into()], 16)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE deletion_batches SET claimed_at=NOW()-INTERVAL '2 minutes' WHERE id=$1",
        )
        .bind(batch)
        .execute(legacy.pool())
        .await
        .unwrap();
        let mock = JobMockSui {
            balance: 100,
            ..Default::default()
        };
        let first = run_reconciler_tick(legacy.pool(), &mock, &execution_gate(), &cfg())
            .await
            .unwrap();
        let second = run_reconciler_tick(legacy.pool(), &mock, &execution_gate(), &cfg())
            .await
            .unwrap();
        assert_eq!(first.rolled_back, 1);
        assert_eq!(second.rolled_back, 0);
        assert_eq!(
            store::get_batch(legacy.pool(), batch, OWNER)
                .await
                .unwrap()
                .unwrap()
                .state,
            store::BATCH_ROLLED_BACK
        );
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn reconciler_resolves_success_and_absent_expired_digest() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "ok", Some("0x1")).await;
        seed(legacy.pool(), "lost", Some("0x2")).await;
        let success = Uuid::new_v4();
        let absent = Uuid::new_v4();
        for (index, (id, blob, digest, expire)) in
            [(success, "ok", "success", 9), (absent, "lost", "absent", 9)]
                .into_iter()
                .enumerate()
        {
            store::create_batch_and_claim_selection(legacy.pool(), OWNER, id, &[blob.into()], 16)
                .await
                .unwrap();
            store::set_batch_prepared(
                legacy.pool(),
                id,
                digest,
                &[1],
                &bcs::to_bytes(&vec![blob.to_string()]).unwrap(),
                1,
                index as i64 + 1,
                expire,
            )
            .await
            .unwrap();
            store::cas_batch_state(
                legacy.pool(),
                id,
                store::BATCH_AWAITING_SIGNATURE,
                store::BATCH_EXECUTING,
            )
            .await
            .unwrap();
            sqlx::query(
                "UPDATE deletion_batches SET claimed_at=NOW()-INTERVAL '2 minutes' WHERE id=$1",
            )
            .bind(id)
            .execute(legacy.pool())
            .await
            .unwrap();
        }
        let mock = JobMockSui {
            epoch: SuiEpoch(10),
            balance: 100,
            ..Default::default()
        };
        mock.statuses.lock().unwrap().insert(
            "success".into(),
            Some(ExecResult {
                digest: "success".into(),
                status: ExecutionStatus::Success,
            }),
        );
        let report = run_reconciler_tick(legacy.pool(), &mock, &execution_gate(), &cfg())
            .await
            .unwrap();
        assert_eq!((report.finalized, report.failed), (1, 1));
        assert_eq!(
            store::get_batch(legacy.pool(), success, OWNER)
                .await
                .unwrap()
                .unwrap()
                .state,
            store::BATCH_COMPLETED
        );
        assert_eq!(
            store::get_batch(legacy.pool(), absent, OWNER)
                .await
                .unwrap()
                .unwrap()
                .state,
            store::BATCH_FAILED
        );
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn reconciler_replays_durable_submission_before_epoch_expiry() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "retry", Some("0x1")).await;
        let batch = Uuid::new_v4();
        store::create_batch_and_claim_selection(legacy.pool(), OWNER, batch, &["retry".into()], 16)
            .await
            .unwrap();
        let (built, object) = prepared_blob_tx("retry", "0x1");
        store::set_batch_prepared(
            legacy.pool(),
            batch,
            &built.digest,
            &built.tx_bytes,
            &bcs::to_bytes(&built.input_blob_ids).unwrap(),
            1,
            1,
            9,
        )
        .await
        .unwrap();
        assert!(
            store::begin_batch_execution(legacy.pool(), batch, &[vec![2], vec![3]],)
                .await
                .unwrap()
        );
        sqlx::query(
            "UPDATE deletion_batches
             SET executing_at=NOW()-INTERVAL '3 minutes',
                 last_submit_at=NOW()-INTERVAL '3 minutes'
             WHERE id=$1",
        )
        .bind(batch)
        .execute(legacy.pool())
        .await
        .unwrap();

        let mock = JobMockSui {
            epoch: SuiEpoch(9),
            balance: 100,
            ..Default::default()
        };
        mock.objects.lock().unwrap().insert(
            "0x1".parse::<sui_sdk_types::Address>().unwrap().to_string(),
            object,
        );
        mock.execution_results
            .lock()
            .unwrap()
            .push_back(Ok(ExecResult {
                digest: built.digest,
                status: ExecutionStatus::Success,
            }));

        let report = run_reconciler_tick(legacy.pool(), &mock, &execution_gate(), &cfg())
            .await
            .unwrap();
        assert_eq!((report.retried, report.finalized), (1, 1));
        assert_eq!(mock.execute_calls.load(Ordering::SeqCst), 1);
        let row = store::get_batch(legacy.pool(), batch, OWNER)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, store::BATCH_COMPLETED);
        assert_eq!(row.submit_attempts, 2);
        assert!(row.signatures.is_none());
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn reconciler_resolves_missing_retry_input_without_execute() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "missing", Some("0x1")).await;
        let batch = Uuid::new_v4();
        store::create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            batch,
            &["missing".into()],
            16,
        )
        .await
        .unwrap();
        let (built, _) = prepared_blob_tx("missing", "0x1");
        store::set_batch_prepared(
            legacy.pool(),
            batch,
            &built.digest,
            &built.tx_bytes,
            &bcs::to_bytes(&built.input_blob_ids).unwrap(),
            1,
            1,
            9,
        )
        .await
        .unwrap();
        assert!(
            store::begin_batch_execution(legacy.pool(), batch, &[vec![2], vec![3]])
                .await
                .unwrap()
        );
        sqlx::query(
            "UPDATE deletion_batches
             SET executing_at=NOW()-INTERVAL '3 minutes',
                 last_submit_at=NOW()-INTERVAL '3 minutes'
             WHERE id=$1",
        )
        .bind(batch)
        .execute(legacy.pool())
        .await
        .unwrap();

        let mock = JobMockSui {
            epoch: SuiEpoch(9),
            balance: 100,
            ..Default::default()
        };
        let gate = execution_gate();
        let report = run_reconciler_tick(legacy.pool(), &mock, &gate, &cfg())
            .await
            .unwrap();
        assert_eq!((report.retried, report.failed), (1, 1));
        assert_eq!(mock.execute_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            store::get_batch(legacy.pool(), batch, OWNER)
                .await
                .unwrap()
                .unwrap()
                .state,
            store::BATCH_FAILED
        );
        let state: String = sqlx::query_scalar(
            "SELECT state FROM delete_blobs_tracking WHERE owner=$1 AND blob_id='missing'",
        )
        .bind(OWNER)
        .fetch_one(legacy.pool())
        .await
        .unwrap();
        assert_eq!(state, store::BLOB_DELETED_EXTERNAL);
        let permit = tokio::time::timeout(Duration::from_millis(10), gate.acquire())
            .await
            .expect("stale retry must release execution permit");
        drop(permit);
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn reconciler_sweep_advances_cursor_and_reports_low_balance() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "gone", Some("0x1")).await;
        seed(legacy.pool(), "healthy", Some("0x2")).await;
        let mock = JobMockSui {
            epoch: SuiEpoch(5),
            balance: 1,
            ..Default::default()
        };
        mock.objects.lock().unwrap().insert(
            "0x2".into(),
            ObjectInfo {
                object_id: "0x2".into(),
                version: 1,
                digest: "d".into(),
                owner: Some(OWNER.into()),
                blob_id: Some("healthy".into()),
                end_epoch: Some(WalrusEpoch(460)),
                package_id: None,
            },
        );
        let report = run_reconciler_tick(legacy.pool(), &mock, &execution_gate(), &cfg())
            .await
            .unwrap();
        assert_eq!(report.swept, 1);
        assert!(report.low_balance);
        assert!(store::job_state_get(legacy.pool(), SWEEP_CURSOR_KEY)
            .await
            .unwrap()
            .unwrap()
            .contains("healthy"));
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn resolver_fills_only_tracked_nulls_and_marks_unmatched_once() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "matched", None).await;
        seed(legacy.pool(), "unmatched", None).await;
        seed(legacy.pool(), "existing", Some("0x9")).await;
        let mock = JobMockSui::default();
        mock.pages.lock().unwrap().insert(
            None,
            VecDeque::from([Ok((
                vec![
                    OwnedBlob {
                        object_id: "0x1".into(),
                        blob_id: "matched".into(),
                        end_epoch: WalrusEpoch(460),
                    },
                    OwnedBlob {
                        object_id: "0x8".into(),
                        blob_id: "untracked-v2".into(),
                        end_epoch: WalrusEpoch(460),
                    },
                    OwnedBlob {
                        object_id: "0x7".into(),
                        blob_id: "existing".into(),
                        end_epoch: WalrusEpoch(460),
                    },
                ],
                None,
            ))]),
        );
        let first = run_resolver_tick(legacy.pool(), &mock, 10).await.unwrap();
        let calls = mock.list_calls.load(Ordering::SeqCst);
        let second = run_resolver_tick(legacy.pool(), &mock, 10).await.unwrap();
        assert_eq!(
            (
                first.resolved,
                first.marked_not_owner,
                first.owners_completed
            ),
            (1, 1, 1)
        );
        assert_eq!(second, ResolverReport::default());
        assert_eq!(mock.list_calls.load(Ordering::SeqCst), calls);
        let existing: String = sqlx::query_scalar(
            "SELECT object_id FROM delete_blobs_tracking WHERE blob_id='existing'",
        )
        .fetch_one(legacy.pool())
        .await
        .unwrap();
        let untracked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM delete_blobs_tracking WHERE blob_id='untracked-v2'",
        )
        .fetch_one(legacy.pool())
        .await
        .unwrap();
        assert_eq!(existing, "0x9");
        assert_eq!(untracked, 0);
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn resolver_resumes_from_saved_page_cursor() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "a", None).await;
        seed(legacy.pool(), "b", None).await;
        let mock = JobMockSui::default();
        mock.pages.lock().unwrap().insert(
            None,
            VecDeque::from([Ok((
                vec![OwnedBlob {
                    object_id: "0x1".into(),
                    blob_id: "a".into(),
                    end_epoch: WalrusEpoch(460),
                }],
                Some("p2".into()),
            ))]),
        );
        mock.pages.lock().unwrap().insert(
            Some("p2".into()),
            VecDeque::from([
                Err(SuiErr::Transport("injected".into())),
                Ok((
                    vec![OwnedBlob {
                        object_id: "0x2".into(),
                        blob_id: "b".into(),
                        end_epoch: WalrusEpoch(460),
                    }],
                    None,
                )),
            ]),
        );
        assert!(run_resolver_tick(legacy.pool(), &mock, 10).await.is_err());
        let report = run_resolver_tick(legacy.pool(), &mock, 10).await.unwrap();
        assert_eq!((report.resolved, report.owners_completed), (1, 1));
        assert_eq!(mock.list_calls.load(Ordering::SeqCst), 3);
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn reconciler_late_failure_cannot_touch_new_batch_generation() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "a", Some("0x1")).await;
        let old = Uuid::new_v4();
        store::create_batch_and_claim_selection(legacy.pool(), OWNER, old, &["a".into()], 16)
            .await
            .unwrap();
        store::set_batch_prepared(
            legacy.pool(),
            old,
            "old",
            &[1],
            &bcs::to_bytes(&vec!["a".to_string()]).unwrap(),
            1,
            1,
            9,
        )
        .await
        .unwrap();
        store::cas_batch_state(
            legacy.pool(),
            old,
            store::BATCH_AWAITING_SIGNATURE,
            store::BATCH_EXECUTING,
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE deletion_batches SET claimed_at=NOW()-INTERVAL '2 minutes' WHERE id=$1",
        )
        .bind(old)
        .execute(legacy.pool())
        .await
        .unwrap();
        let started = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let mock = Arc::new(JobMockSui {
            epoch: SuiEpoch(10),
            balance: 100,
            status_started: Some(started.clone()),
            status_continue: Some(resume.clone()),
            ..Default::default()
        });
        mock.statuses.lock().unwrap().insert(
            "old".into(),
            Some(ExecResult {
                digest: "old".into(),
                status: ExecutionStatus::Failure {
                    error: ExecutionError::InputObjectDeleted,
                    command: Some(0),
                },
            }),
        );
        let pool = legacy.pool().clone();
        let mock_for_tick = mock.clone();
        let gate = execution_gate();
        let task = tokio::spawn(async move {
            run_reconciler_tick(&pool, mock_for_tick.as_ref(), &gate, &cfg())
                .await
                .unwrap()
        });
        started.notified().await;
        assert!(store::rollback_batch(
            legacy.pool(),
            old,
            store::BATCH_EXECUTING,
            store::BATCH_FAILED
        )
        .await
        .unwrap());
        let new = Uuid::new_v4();
        store::create_batch_and_claim_selection(legacy.pool(), OWNER, new, &["a".into()], 16)
            .await
            .unwrap();
        resume.notify_one();
        let report = task.await.unwrap();
        assert_eq!(report.failed, 0, "old batch CAS must lose");
        let row = store::batch_blobs(legacy.pool(), new, OWNER)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(row.batch_id, Some(new));
        assert_eq!(row.state, store::BLOB_DELETING);
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn resolver_skips_owner_with_uncommitted_trigger_insert() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "old", None).await;

        // The trigger takes the owner's shared transaction lock before it
        // allocates tracked_seq. Keep that transaction open so the resolver's
        // exclusive try-lock must fail without starting a Sui scan.
        let mut pending_insert = legacy.pool().begin().await.unwrap();
        sqlx::query("INSERT INTO vector_entries(id,owner,blob_id) VALUES('pending','0xa','new')")
            .execute(&mut *pending_insert)
            .await
            .unwrap();

        let mock = JobMockSui::default();
        let deferred = run_resolver_tick(legacy.pool(), &mock, 10).await.unwrap();
        assert_eq!(deferred.owners_deferred, 1);
        assert_eq!(deferred.owners_completed, 0);
        assert_eq!(mock.list_calls.load(Ordering::SeqCst), 0);
        assert!(
            store::job_state_get(legacy.pool(), &format!("resolver_checkpoint:{OWNER}"))
                .await
                .unwrap()
                .is_none()
        );

        pending_insert.commit().await.unwrap();
        let report = run_resolver_tick(legacy.pool(), &mock, 10).await.unwrap();
        assert_eq!(report.owners_completed, 1);
        assert_eq!(report.marked_not_owner, 2);
        cleanup(legacy, admin, schema).await;
    }

    #[tokio::test]
    #[ignore]
    async fn resolver_defers_rows_inserted_after_scan_watermark() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        seed(legacy.pool(), "old", None).await;
        let started = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let mock = Arc::new(JobMockSui {
            list_started: Some(started.clone()),
            list_continue: Some(resume.clone()),
            ..Default::default()
        });
        mock.pages.lock().unwrap().insert(
            None,
            VecDeque::from([Ok((Vec::new(), None)), Ok((Vec::new(), None))]),
        );
        let pool = legacy.pool().clone();
        let mock_tick = mock.clone();
        let first = tokio::spawn(async move {
            run_resolver_tick(&pool, mock_tick.as_ref(), 10)
                .await
                .unwrap()
        });
        started.notified().await;
        let checkpoint =
            store::job_state_get(legacy.pool(), &format!("resolver_checkpoint:{OWNER}"))
                .await
                .unwrap()
                .and_then(|raw| serde_json::from_str::<ResolverCheckpoint>(&raw).ok())
                .unwrap();
        seed(legacy.pool(), "new", None).await;
        let tracked_seq: i64 =
            sqlx::query_scalar("SELECT tracked_seq FROM delete_blobs_tracking WHERE blob_id='new'")
                .fetch_one(legacy.pool())
                .await
                .unwrap();
        assert!(tracked_seq > checkpoint.scan_fence);
        resume.notify_one();
        first.await.unwrap();
        let state: String =
            sqlx::query_scalar("SELECT state FROM delete_blobs_tracking WHERE blob_id='new'")
                .fetch_one(legacy.pool())
                .await
                .unwrap();
        assert_eq!(state, store::BLOB_DELETABLE);
        // Disable the pause for the delta pass by using a fresh mock.
        let delta = JobMockSui::default();
        let report = run_resolver_tick(legacy.pool(), &delta, 10).await.unwrap();
        assert_eq!(report.owners_completed, 1);
        let state: String =
            sqlx::query_scalar("SELECT state FROM delete_blobs_tracking WHERE blob_id='new'")
                .fetch_one(legacy.pool())
                .await
                .unwrap();
        assert_eq!(state, store::BLOB_NOT_OWNER);
        let calls = delta.list_calls.load(Ordering::SeqCst);
        assert_eq!(
            run_resolver_tick(legacy.pool(), &delta, 10).await.unwrap(),
            ResolverReport::default()
        );
        assert_eq!(delta.list_calls.load(Ordering::SeqCst), calls);
        cleanup(legacy, admin, schema).await;
    }
}
