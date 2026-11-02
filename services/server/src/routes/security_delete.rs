use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sui_sdk_types::ExecutionStatus;
use uuid::Uuid;

use crate::security_delete_auth::{same_owner, SdOwner};
use crate::security_delete_error::{SdBatchId, SdCode, SdError, SdJson, SdQuery};
use crate::storage::security_delete_store as store;
use crate::sui::classify::{classify_execution_failure, FailureClass};
use crate::sui::input_freshness::{self, StaleInputReason};
use crate::sui::tx_build::{
    build_delete_tx, derive_nonce, sponsor_signature, MAX_DELETE_BLOBS_PER_TX,
};
use crate::sui::{SuiApi, SuiErr};
use crate::types::{AppError, AppState};

const LIST_MAX: i64 = 200;
const GAS_BASE: u64 = 10_000_000;
const GAS_PER_BLOB: u64 = 2_000_000;
const RPC_OBJECT_BATCH: usize = 100;
// Wall-clock deadline for the whole prepare (claim -> epochs -> 9x BatchGetObjects -> PTB build).
// 8s is too tight on a real network: a 900-blob prepare measures ~5.8s against Sui testnet, so a
// single slow RPC round-trip tips it over and surfaces as RPC_UNAVAILABLE.
const PREPARE_RPC_BUDGET: Duration = Duration::from_secs(30);
const CRASH_TEST_HEADER: &str = "x-security-delete-crash-test";
const CRASH_TEST_PAUSE: Duration = Duration::from_secs(300);

fn crash_test_requested(state: &AppState, headers: &HeaderMap) -> bool {
    crash_test_credentials_match(
        &state.config.sui_network,
        state.config.security_delete_crash_test_secret.as_deref(),
        headers
            .get(CRASH_TEST_HEADER)
            .and_then(|value| value.to_str().ok()),
    )
}

fn crash_test_credentials_match(
    network: &str,
    expected: Option<&str>,
    provided: Option<&str>,
) -> bool {
    network == "localnet"
        && expected
            .zip(provided)
            .is_some_and(|(expected, provided)| expected == provided)
}

async fn with_prepare_rpc_budget<T>(
    budget: Duration,
    future: impl Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    tokio::time::timeout(budget, future).await
}

pub async fn security_delete_feature_gate(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, SdError> {
    if !crate::types::security_delete_routes_enabled(&state.config) {
        return Err(SdError::new(SdCode::FeatureDisabled, "Feature disabled"));
    }
    Ok(next.run(request).await)
}

/// Closed-envelope Redis limiter used by auth routes. It intentionally runs
/// inside the feature gate so a disabled deployment never reveals the API.
pub async fn security_delete_auth_rate_limit(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, SdError> {
    let identity = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    rate_limit(
        &state,
        "auth",
        &identity,
        state.config.security_delete_auth_requests_per_minute,
        60,
    )
    .await?;
    Ok(next.run(request).await)
}

async fn rate_limit(
    state: &AppState,
    scope: &str,
    identity: &str,
    limit: u64,
    window_secs: u64,
) -> Result<(), SdError> {
    let bucket = Utc::now().timestamp() / window_secs as i64;
    let key = format!("sd_rate:{scope}:{identity}:{bucket}");
    let mut connection = state.redis.clone();
    let count: i64 = redis::cmd("INCR")
        .arg(&key)
        .query_async(&mut connection)
        .await
        .map_err(|error| SdError::internal(AppError::Internal(format!("rate limit: {error}"))))?;
    if count == 1 {
        let _: bool = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(window_secs)
            .query_async(&mut connection)
            .await
            .map_err(|error| {
                SdError::internal(AppError::Internal(format!("rate expiry: {error}")))
            })?;
    }
    if count as u64 > limit {
        return Err(SdError::with_details(
            SdCode::RateLimited,
            "Too many requests",
            json!({"retryAfterSecs": window_secs}),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionScope {
    Legacy,
    Current,
}

impl DeletionScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Current => "current",
        }
    }

    fn parse(raw: Option<&str>) -> Result<Self, SdError> {
        match raw {
            None | Some("legacy") => Ok(Self::Legacy),
            Some("current") => Ok(Self::Current),
            Some(_) => Err(invalid_request()),
        }
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub state: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
    pub scope: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobItemJson {
    blob_id: String,
    object_id: Option<String>,
    created_at: String,
    state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CountsJson {
    total: i64,
    deletable: i64,
    deleting: i64,
    deleted: i64,
    deleted_external: i64,
    not_owner: i64,
    expired: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitsJson {
    delete_batch_max: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    items: Vec<BlobItemJson>,
    counts: CountsJson,
    limits: LimitsJson,
    next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListCursor {
    v: u8,
    created_at_micros: i64,
    blob_id: String,
}

fn decode_cursor(raw: Option<&str>) -> Result<Option<(DateTime<Utc>, String)>, SdError> {
    let Some(raw) = raw else { return Ok(None) };
    let cursor: ListCursor =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid_request())?)
            .map_err(|_| invalid_request())?;
    if cursor.v != 1 || cursor.blob_id.is_empty() {
        return Err(invalid_request());
    }
    let created_at =
        DateTime::from_timestamp_micros(cursor.created_at_micros).ok_or_else(invalid_request)?;
    Ok(Some((created_at, cursor.blob_id)))
}

fn encode_cursor(created_at: DateTime<Utc>, blob_id: String) -> String {
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&ListCursor {
            v: 1,
            created_at_micros: created_at.timestamp_micros(),
            blob_id,
        })
        .expect("cursor serialization is infallible"),
    )
}

fn parse_states(raw: Option<&str>) -> Result<Vec<&str>, SdError> {
    let states: Vec<&str> = raw.unwrap_or(store::BLOB_DELETABLE).split(',').collect();
    if states.is_empty()
        || states.iter().any(|state| {
            state.is_empty()
                || !matches!(
                    *state,
                    store::BLOB_DELETABLE
                        | store::BLOB_DELETING
                        | store::BLOB_DELETED
                        | store::BLOB_DELETED_EXTERNAL
                        | store::BLOB_NOT_OWNER
                        | store::BLOB_EXPIRED
                )
        })
    {
        return Err(invalid_request());
    }
    Ok(states)
}

fn empty_list_response(delete_batch_max: usize) -> ListResponse {
    ListResponse {
        items: Vec::new(),
        counts: CountsJson {
            total: 0,
            deletable: 0,
            deleting: 0,
            deleted: 0,
            deleted_external: 0,
            not_owner: 0,
            expired: 0,
        },
        limits: LimitsJson { delete_batch_max },
        next_cursor: None,
    }
}

pub async fn list_deletable_blobs(
    State(state): State<Arc<AppState>>,
    SdOwner(owner): SdOwner,
    SdQuery(query): SdQuery<ListQuery>,
) -> Result<Json<ListResponse>, SdError> {
    let scope = DeletionScope::parse(query.scope.as_deref())?;
    let states = parse_states(query.state.as_deref())?;
    let limit = query.limit.unwrap_or(100);
    if !(1..=LIST_MAX).contains(&limit) {
        return Err(invalid_request());
    }
    let cursor = decode_cursor(query.cursor.as_deref())?;
    let Some(pool) = scope_pool(&state, scope, &owner).await? else {
        return Ok(Json(empty_list_response(state.config.delete_batch_max)));
    };
    let mut rows = store::list_blobs(pool, &owner, scope.as_str(), &states, cursor, limit + 1)
        .await
        .map_err(SdError::internal)?;
    let next_cursor = if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        rows.last()
            .map(|row| encode_cursor(row.created_at, row.blob_id.clone()))
    } else {
        None
    };
    let counts = store::counts(pool, &owner, scope.as_str())
        .await
        .map_err(SdError::internal)?;
    Ok(Json(ListResponse {
        items: rows
            .into_iter()
            .map(|row| BlobItemJson {
                blob_id: row.blob_id,
                object_id: row.object_id,
                created_at: row.created_at.to_rfc3339(),
                state: row.state,
            })
            .collect(),
        counts: CountsJson {
            total: counts.total,
            deletable: counts.deletable,
            deleting: counts.deleting,
            deleted: counts.deleted,
            deleted_external: counts.deleted_external,
            not_owner: counts.not_owner,
            expired: counts.expired,
        },
        limits: LimitsJson {
            delete_batch_max: state.config.delete_batch_max,
        },
        next_cursor,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareRequest {
    mode: String,
    blob_ids: Option<Vec<String>>,
    scope: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExcludedJson {
    blob_id: String,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareResponse {
    batch_id: Option<String>,
    tx_bytes: Option<String>,
    included: usize,
    excluded: Vec<ExcludedJson>,
    expires_at: Option<String>,
}

fn nothing(excluded: Vec<ExcludedJson>) -> Json<PrepareResponse> {
    Json(PrepareResponse {
        batch_id: None,
        tx_bytes: None,
        included: 0,
        excluded,
        expires_at: None,
    })
}

pub async fn prepare_deletion(
    State(state): State<Arc<AppState>>,
    SdOwner(owner): SdOwner,
    SdJson(request): SdJson<PrepareRequest>,
) -> Result<Json<PrepareResponse>, SdError> {
    let scope = DeletionScope::parse(request.scope.as_deref())?;
    let selection = match request.mode.as_str() {
        "all" if request.blob_ids.is_none() => None,
        "selection" => {
            let ids = request.blob_ids.ok_or_else(invalid_request)?;
            let unique: HashSet<&str> = ids.iter().map(String::as_str).collect();
            if ids.is_empty()
                || ids.len() > state.config.delete_batch_max.min(MAX_DELETE_BLOBS_PER_TX)
                || unique.len() != ids.len()
                || ids.iter().any(|id| id.trim().is_empty())
            {
                return Err(invalid_request());
            }
            Some(ids)
        }
        _ => return Err(invalid_request()),
    };
    let Some(pool) = scope_pool(&state, scope, &owner).await? else {
        return Ok(nothing(Vec::new()));
    };
    if store::counts(pool, &owner, scope.as_str())
        .await
        .map_err(SdError::internal)?
        .deletable
        == 0
    {
        return Ok(nothing(Vec::new()));
    }
    rate_limit(
        &state,
        "prepare",
        &owner,
        state.config.security_delete_prepare_requests_per_minute,
        60,
    )
    .await?;
    let batch_id = Uuid::new_v4();
    let claim = match selection {
        Some(ref ids) => {
            store::create_batch_and_claim_selection(
                pool,
                &owner,
                scope.as_str(),
                batch_id,
                ids,
                state.config.max_active_batches_per_owner as i64,
            )
            .await
        }
        None => {
            store::create_batch_and_claim_all(
                pool,
                &owner,
                scope.as_str(),
                batch_id,
                state.config.delete_batch_max as i64,
                state.config.max_active_batches_per_owner as i64,
            )
            .await
        }
    }
    .map_err(claim_error)?;
    if claim.rows.is_empty() {
        return Ok(nothing(Vec::new()));
    }

    let prepare_result = with_prepare_rpc_budget(PREPARE_RPC_BUDGET, async {
        let sui = security_delete_sui(&state)?;
        let mut excluded = Vec::new();
        if claim.rows.iter().any(|row| row.object_id.is_none()) {
            if let Err(error) =
                resolve_claimed_object_ids(pool, sui, &owner, batch_id, &mut excluded).await
            {
                rollback_after_prepare_failure(pool, batch_id).await;
                return Err(error);
            }
        }
        let claimed = store::batch_blobs(pool, batch_id, &owner)
            .await
            .map_err(SdError::internal)?;
        let ids: Vec<String> = claimed
            .iter()
            .filter_map(|row| row.object_id.clone())
            .collect();
        // TWO DIFFERENT CLOCKS — do not merge these.
        // `walrus_epoch` classifies blob expiry (`Blob.storage.end_epoch` is a Walrus epoch).
        // `sui_epoch` bounds the transaction (`ValidDuring.max_epoch` is a Sui epoch).
        // On testnet they differ by ~700; using either one for the other's job breaks the flow.
        let walrus_epoch = match sui.walrus_epoch().await {
            Ok(epoch) => epoch,
            Err(error) => return Err(prepare_rpc_failure(pool, batch_id, error).await),
        };
        let sui_epoch = match sui.current_epoch().await {
            Ok(epoch) => epoch,
            Err(error) => return Err(prepare_rpc_failure(pool, batch_id, error).await),
        };
        let objects = match batch_get_all(sui, &ids).await {
            Ok(objects) => objects,
            Err(error) => return Err(prepare_rpc_failure(pool, batch_id, error).await),
        };
        let mut healthy = Vec::new();
        for (row, object) in claimed
            .iter()
            .filter(|row| row.object_id.is_some())
            .zip(objects)
        {
            let (terminal, reason) = match object.as_ref() {
                None => (Some(store::BLOB_DELETED_EXTERNAL), "already_deleted"),
                Some(object)
                    if object.blob_id.as_deref() != Some(row.blob_id.as_str())
                        || !same_owner(object.owner.as_deref(), &owner) =>
                {
                    (Some(store::BLOB_NOT_OWNER), "not_owner")
                }
                Some(object)
                    if object.end_epoch.is_some_and(|end| {
                        end.is_at_or_before(walrus_epoch, state.config.expiry_margin_epochs)
                    }) =>
                {
                    (Some(store::BLOB_EXPIRED), "expired")
                }
                Some(_) => (None, ""),
            };
            if let Some(terminal) = terminal {
                if store::evict_claimed_blob(pool, &owner, &row.blob_id, batch_id, terminal)
                    .await
                    .map_err(SdError::internal)?
                {
                    excluded.push(ExcludedJson {
                        blob_id: row.blob_id.clone(),
                        reason: reason.into(),
                    });
                }
            } else if let Some(object) = object {
                healthy.push(object);
            }
        }
        if healthy.is_empty() {
            let _ = store::rollback_batch(
                pool,
                batch_id,
                store::BATCH_AWAITING_SIGNATURE,
                store::BATCH_ROLLED_BACK,
            )
            .await;
            return Ok(nothing(excluded));
        }

        let system = match sui.walrus_system_object().await {
            Ok(system) => system,
            Err(error) => return Err(prepare_rpc_failure(pool, batch_id, error).await),
        };
        // Walrus upgrades its package; the system object names the package its code
        // currently lives in. Calling a superseded package aborts in `system::inner`
        // (abort code 1), so the chain's value wins and the configured id is only a
        // fallback for networks whose system object does not expose one.
        let walrus_package = walrus_package_id(&state.config.walrus_package_id, &system);
        let gas_price = match sui.reference_gas_price().await {
            Ok(price) => price,
            Err(error) => return Err(prepare_rpc_failure(pool, batch_id, error).await),
        };
        let chain = match sui.chain_id().await {
            Ok(chain) => chain,
            Err(error) => return Err(prepare_rpc_failure(pool, batch_id, error).await),
        };
        let sponsor_key = state
            .config
            .sponsor_private_key
            .as_deref()
            .ok_or_else(|| SdError::new(SdCode::FeatureDisabled, "Feature disabled"))?;
        let sponsor = match sponsor_address(sponsor_key) {
            Ok(sponsor) => sponsor,
            Err(error) => {
                rollback_after_prepare_failure(pool, batch_id).await;
                return Err(error);
            }
        };
        let base_nonce = derive_nonce(&batch_id);
        let mut built_tx = None;
        for offset in 0..16u32 {
            let built = match build_delete_tx(
                &owner,
                &sponsor,
                &healthy,
                walrus_package,
                &system,
                // ValidDuring.max_epoch — the SUI clock. The `SuiEpoch` type makes passing
                // `walrus_epoch` here a compile error.
                sui_epoch,
                gas_price,
                GAS_BASE.saturating_add(GAS_PER_BLOB.saturating_mul(healthy.len() as u64)),
                &chain,
                base_nonce.wrapping_add(offset),
            ) {
                Ok(built) => built,
                Err(error) => {
                    rollback_after_prepare_failure(pool, batch_id).await;
                    return Err(SdError::internal(AppError::Internal(error.to_string())));
                }
            };
            let mapping = match bcs::to_bytes(&built.input_blob_ids) {
                Ok(mapping) => mapping,
                Err(error) => {
                    rollback_after_prepare_failure(pool, batch_id).await;
                    return Err(SdError::internal(AppError::Internal(error.to_string())));
                }
            };
            match store::set_batch_prepared(
                pool,
                batch_id,
                &built.digest,
                &built.tx_bytes,
                &mapping,
                healthy.len() as i32,
                built.nonce as i64,
                built.expire_epoch as i64,
            )
            .await
            {
                Ok(true) => {
                    built_tx = Some(built);
                    break;
                }
                Ok(false) => {
                    return Err(SdError::new(SdCode::BatchExpired, "Deletion batch expired"));
                }
                Err(error) if nonce_collision(&error) => continue,
                Err(error) => {
                    rollback_after_prepare_failure(pool, batch_id).await;
                    return Err(SdError::internal(error));
                }
            }
        }
        let Some(built) = built_tx else {
            rollback_after_prepare_failure(pool, batch_id).await;
            return Err(SdError::internal(AppError::Internal(
                "unable to allocate a unique deletion nonce".into(),
            )));
        };
        Ok(Json(PrepareResponse {
            batch_id: Some(batch_id.to_string()),
            tx_bytes: Some(STANDARD.encode(built.tx_bytes)),
            included: healthy.len(),
            excluded,
            expires_at: Some(format!("epoch:{}", built.expire_epoch)),
        }))
    })
    .await;
    match prepare_result {
        Ok(result) => result,
        Err(_) => Err(prepare_rpc_failure(
            pool,
            batch_id,
            SuiErr::Transport("prepare RPC budget exhausted".into()),
        )
        .await),
    }
}

async fn resolve_claimed_object_ids(
    pool: &sqlx::PgPool,
    sui: &dyn SuiApi,
    owner: &str,
    batch_id: Uuid,
    excluded: &mut Vec<ExcludedJson>,
) -> Result<(), SdError> {
    let mut cursor = None;
    let mut owned = HashMap::new();
    loop {
        let requested_cursor = cursor.clone();
        let (page, next) = sui
            .list_owned_blobs(owner, requested_cursor.clone())
            .await
            .map_err(rpc_error)?;
        for blob in page {
            owned.insert(blob.blob_id, blob.object_id);
        }
        let Some(next) = next else { break };
        if Some(&next) == requested_cursor.as_ref() {
            return Err(rpc_error(SuiErr::Transport(
                "owned-object scan returned a non-advancing cursor".into(),
            )));
        }
        cursor = Some(next);
    }
    let rows = store::batch_blobs(pool, batch_id, owner)
        .await
        .map_err(SdError::internal)?;
    let pairs: Vec<(String, String)> = rows
        .iter()
        .filter(|row| row.object_id.is_none())
        .filter_map(|row| {
            owned
                .get(&row.blob_id)
                .map(|id| (row.blob_id.clone(), id.clone()))
        })
        .collect();
    store::set_claimed_object_ids(pool, owner, batch_id, &pairs)
        .await
        .map_err(SdError::internal)?;
    for row in rows
        .iter()
        .filter(|row| row.object_id.is_none() && !owned.contains_key(&row.blob_id))
    {
        if store::evict_claimed_blob(pool, owner, &row.blob_id, batch_id, store::BLOB_NOT_OWNER)
            .await
            .map_err(SdError::internal)?
        {
            excluded.push(ExcludedJson {
                blob_id: row.blob_id.clone(),
                reason: "not_owner".into(),
            });
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct SubmitRequest {
    signature: String,
}

#[derive(Serialize)]
pub struct SubmitResponse {
    state: String,
    deleted: u64,
    digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    state: String,
    blob_count: i32,
    digest: Option<String>,
    resolved_at: Option<String>,
}

pub async fn submit_deletion(
    State(state): State<Arc<AppState>>,
    SdOwner(owner): SdOwner,
    SdBatchId(batch_id): SdBatchId,
    headers: HeaderMap,
    SdJson(request): SdJson<SubmitRequest>,
) -> Result<Json<SubmitResponse>, SdError> {
    let (pool, batch) = resolve_batch_pool(&state, batch_id, &owner).await?;
    match batch.state.as_str() {
        store::BATCH_ROLLED_BACK => {
            return Err(SdError::new(SdCode::BatchExpired, "Deletion batch expired"))
        }
        store::BATCH_COMPLETED | store::BATCH_FAILED => return Err(resolved(&batch.state)),
        store::BATCH_EXECUTING => return Err(resolved(&batch.state)),
        store::BATCH_AWAITING_SIGNATURE => {}
        _ => return Err(resolved(&batch.state)),
    }
    let tx_bytes = batch.tx_bytes.as_deref().ok_or_else(|| {
        SdError::internal(AppError::Internal(
            "prepared batch missing transaction".into(),
        ))
    })?;
    let user_signature = state
        .security_delete_wallet_verifier
        .verify_transaction(&owner, tx_bytes, &request.signature)
        .await?;
    let sponsor = sponsor_signature(
        state
            .config
            .sponsor_private_key
            .as_deref()
            .ok_or_else(|| SdError::new(SdCode::FeatureDisabled, "Feature disabled"))?,
        tx_bytes,
    )
    .map_err(|error| SdError::internal(AppError::Internal(error.to_string())))?;
    let signatures = vec![user_signature, sponsor];
    // Every deletion PTB mutates the Walrus System shared object. Queue
    // before the durable execution CAS so time spent waiting cannot make an
    // otherwise healthy batch look like a stale in-flight execution to the
    // reconciler.
    let execution_permit = state.security_delete_execution_gate.acquire().await;
    if !store::begin_batch_execution(pool, batch_id, &signatures)
        .await
        .map_err(SdError::internal)?
    {
        let current = require_batch(pool, batch_id, &owner).await?;
        return Err(resolved(&current.state));
    }
    let sui = security_delete_sui(&state)?;
    match revalidate_before_execute(pool, sui, batch_id, &owner, &batch, tx_bytes).await {
        Ok(Some(evicted)) => {
            drop(execution_permit);
            return Err(SdError::with_details(
                SdCode::TxExecutionFailed,
                "Transaction inputs changed after preparation",
                json!({"evicted": evicted}),
            ));
        }
        Ok(None) => {}
        Err(error) => {
            // No execute request has been sent, so releasing the claims is
            // safe even when the freshness read itself had a transport error.
            let _ =
                store::rollback_batch(pool, batch_id, store::BATCH_EXECUTING, store::BATCH_FAILED)
                    .await;
            drop(execution_permit);
            return Err(error);
        }
    }
    if crash_test_requested(&state, &headers) {
        tracing::warn!(%batch_id, "security-delete local crash test paused after execution CAS");
        tokio::time::sleep(CRASH_TEST_PAUSE).await;
    }
    let execution = sui.execute_tx(tx_bytes, signatures).await;
    drop(execution_permit);
    match execution {
        Ok(result) if batch.digest.as_deref() != Some(result.digest.as_str()) => {
            tracing::error!(
                batch_id = %batch_id,
                expected_digest = ?batch.digest,
                returned_digest = %result.digest,
                "security-delete execution returned a different digest"
            );
            Err(SdError::new(
                SdCode::RpcUnavailable,
                "Sui RPC is temporarily unavailable",
            ))
        }
        Ok(result) if result.success() => complete_submit(pool, batch_id, result.digest).await,
        Ok(result) => {
            let shared_object_congestion = matches!(
                classify_execution_failure(&result.status),
                FailureClass::SharedObjectCongestion
            );
            let evicted =
                resolve_committed_failure(pool, sui, batch_id, &owner, &batch, &result.status)
                    .await?;
            Err(SdError::with_details(
                SdCode::TxExecutionFailed,
                "Transaction execution failed",
                if shared_object_congestion {
                    json!({"reason": "shared_object_congestion", "evicted": evicted})
                } else {
                    json!({"evicted": evicted})
                },
            ))
        }
        Err(SuiErr::Transport(_) | SuiErr::RateLimited) => Err(SdError::new(
            SdCode::RpcUnavailable,
            "Sui RPC is temporarily unavailable",
        )),
        Err(SuiErr::SponsorFundsUnavailable(_)) => {
            resolve_rejected_execution(
                pool,
                sui,
                batch_id,
                &owner,
                &batch,
                SdCode::SponsorFundsUnavailable,
            )
            .await
        }
        // `NotFound` from an execute is a rejection (some referenced object is unknown to the
        // node), not the benign "not on chain yet" it means for a transaction lookup. Like any
        // rejection it is not proof the transaction failed to commit, so it takes the same
        // digest-resolving path rather than releasing the claims outright.
        Err(SuiErr::Rejected(_) | SuiErr::NotFound(_)) => {
            // A node may reject a replay as "already executed" even though
            // the transaction committed. Resolve the persisted digest before
            // releasing the claims; a failed lookup is an unknown outcome and
            // must stay executing for the reconciler.
            resolve_rejected_execution(
                pool,
                sui,
                batch_id,
                &owner,
                &batch,
                SdCode::TxExecutionFailed,
            )
            .await
        }
    }
}

async fn revalidate_before_execute(
    pool: &sqlx::PgPool,
    sui: &dyn SuiApi,
    batch_id: Uuid,
    owner: &str,
    batch: &store::BatchRow,
    tx_bytes: &[u8],
) -> Result<Option<Vec<String>>, SdError> {
    // Walrus may have upgraded its package between prepare and submit (the user has up to
    // CLAIM_TTL to sign). The package is baked into the prepared tx_bytes, so executing them
    // would abort `EWrongVersion` and waste sponsor gas. Catch it here: fail the batch with a
    // global reason, release every row, and tell the client to RE_PREPARE — the rebuild picks
    // up the current package. No blob is evicted, because none is at fault.
    if let Some(tx_package) = input_freshness::transaction_package(tx_bytes)
        .map_err(|error| SdError::internal(AppError::Internal(error)))?
    {
        // An OPTIMISATION, not a correctness dependency: it saves sponsor gas on a tx that
        // cannot land. Degrade gracefully — a failed system-object read must not block a
        // submit that would otherwise succeed. A genuinely superseded package still aborts on
        // chain, and `FailureClass::WholeTransaction` releases every row without evicting any.
        let current = match sui.walrus_system_object().await {
            Ok(system) => system
                .package_id
                .as_deref()
                // Parsed addresses, never strings — see `walrus_package_changed`.
                .and_then(|id| id.parse::<sui_sdk_types::Address>().ok()),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    %batch_id,
                    "could not read the Walrus system object; skipping the stale-package check"
                );
                None
            }
        };
        if let Some(current) = current {
            if tx_package != current {
                tracing::warn!(
                    %batch_id,
                    tx_package = %tx_package,
                    current_package = %current,
                    "prepared batch targets a superseded Walrus package; failing before execute"
                );
                // Returning Err here takes the caller's rollback path (EXECUTING -> FAILED),
                // which releases every row. Nothing is evicted, because no blob is at fault.
                return Err(SdError::with_details(
                    SdCode::TxExecutionFailed,
                    "Walrus upgraded its package after this batch was prepared",
                    json!({
                        "reason": crate::sui::classify::REASON_PACKAGE_UPGRADED,
                        "evicted": [],
                    }),
                ));
            }
        }
    }
    let input_blob_ids = batch.input_blob_ids.as_ref().ok_or_else(|| {
        SdError::internal(AppError::Internal(
            "prepared batch missing input blob ordering".into(),
        ))
    })?;
    let expected = input_freshness::expected_inputs(tx_bytes, input_blob_ids)
        .map_err(|error| SdError::internal(AppError::Internal(error)))?;
    let objects = input_freshness::fetch_current(sui, &expected)
        .await
        .map_err(rpc_error)?;
    let stale = input_freshness::stale_inputs(owner, &expected, &objects)
        .map_err(|error| SdError::internal(AppError::Internal(error)))?;
    if stale.is_empty() {
        return Ok(None);
    }
    let mut evicted = Vec::new();
    for input in stale {
        let terminal = match input.reason {
            StaleInputReason::DeletedExternal => Some(store::BLOB_DELETED_EXTERNAL),
            StaleInputReason::NotOwner => Some(store::BLOB_NOT_OWNER),
            StaleInputReason::ChangedReference => None,
        };
        let Some(terminal) = terminal else {
            continue;
        };
        if store::evict_claimed_blob(pool, owner, &input.blob_id, batch_id, terminal)
            .await
            .map_err(SdError::internal)?
        {
            evicted.push(input.blob_id);
        }
    }
    store::rollback_batch(pool, batch_id, store::BATCH_EXECUTING, store::BATCH_FAILED)
        .await
        .map_err(SdError::internal)?;
    Ok(Some(evicted))
}

async fn resolve_rejected_execution(
    pool: &sqlx::PgPool,
    sui: &dyn SuiApi,
    batch_id: Uuid,
    owner: &str,
    batch: &store::BatchRow,
    rejection_code: SdCode,
) -> Result<Json<SubmitResponse>, SdError> {
    let digest = batch.digest.as_deref().ok_or_else(|| {
        SdError::internal(AppError::Internal(
            "executing batch missing transaction digest".into(),
        ))
    })?;
    match sui.get_tx_status(digest).await {
        Ok(Some(result)) if result.digest != digest => Err(SdError::new(
            SdCode::RpcUnavailable,
            "Sui RPC is temporarily unavailable",
        )),
        Ok(Some(result)) if result.success() => {
            complete_submit(pool, batch_id, result.digest).await
        }
        Ok(Some(result)) => {
            let shared_object_congestion = matches!(
                classify_execution_failure(&result.status),
                FailureClass::SharedObjectCongestion
            );
            let evicted =
                resolve_committed_failure(pool, sui, batch_id, owner, batch, &result.status)
                    .await?;
            Err(SdError::with_details(
                SdCode::TxExecutionFailed,
                "Transaction execution failed",
                if shared_object_congestion {
                    json!({"reason": "shared_object_congestion", "evicted": evicted})
                } else {
                    json!({"evicted": evicted})
                },
            ))
        }
        Ok(None) => {
            let _ =
                store::rollback_batch(pool, batch_id, store::BATCH_EXECUTING, store::BATCH_FAILED)
                    .await;
            if rejection_code == SdCode::SponsorFundsUnavailable {
                tracing::warn!(
                    batch_id = %batch_id,
                    "security-delete sponsor address balance cannot fund transaction gas"
                );
                Err(SdError::with_details(
                    rejection_code,
                    "Deletion sponsorship is temporarily unavailable",
                    json!({"retryAfterSecs": 30}),
                ))
            } else {
                Err(SdError::new(rejection_code, "Transaction execution failed"))
            }
        }
        Err(_) => Err(SdError::new(
            SdCode::RpcUnavailable,
            "Sui RPC is temporarily unavailable",
        )),
    }
}

async fn complete_submit(
    pool: &sqlx::PgPool,
    batch_id: Uuid,
    digest: String,
) -> Result<Json<SubmitResponse>, SdError> {
    let deleted = store::finalize_batch_deleted(pool, batch_id, store::BATCH_EXECUTING)
        .await
        .map_err(SdError::internal)?
        .ok_or_else(|| SdError::new(SdCode::BatchAlreadyResolved, "Batch already resolved"))?;
    Ok(Json(SubmitResponse {
        state: store::BATCH_COMPLETED.into(),
        deleted,
        digest,
    }))
}

async fn resolve_committed_failure(
    pool: &sqlx::PgPool,
    sui: &dyn SuiApi,
    batch_id: Uuid,
    owner: &str,
    batch: &store::BatchRow,
    status: &ExecutionStatus,
) -> Result<Vec<String>, SdError> {
    let rows = store::batch_blobs(pool, batch_id, owner)
        .await
        .map_err(SdError::internal)?;
    let targets: Vec<String> = match classify_execution_failure(status) {
        FailureClass::CulpritInput { input_index } => batch
            .input_blob_ids
            .as_ref()
            .and_then(|ids| input_index.checked_sub(1).and_then(|index| ids.get(index)))
            .cloned()
            .into_iter()
            .collect(),
        FailureClass::SharedObjectCongestion => Vec::new(),
        // Unexecutable as a whole (e.g. Walrus upgraded its package under a prepared tx).
        // No blob is at fault — evict none. The rows are released by the rollback and the
        // client's RE_PREPARE rebuilds against the current package.
        FailureClass::WholeTransaction { reason } => {
            tracing::warn!(
                %batch_id,
                reason,
                "security-delete batch failed wholesale; releasing all rows, evicting none"
            );
            Vec::new()
        }
        _ => rows.iter().map(|row| row.blob_id.clone()).collect(),
    };
    let object_ids: Vec<String> = rows
        .iter()
        .filter(|row| targets.contains(&row.blob_id))
        .filter_map(|row| row.object_id.clone())
        .collect();
    let mut evicted = Vec::new();
    if let Ok(objects) = batch_get_all(sui, &object_ids).await {
        for (row, object) in rows
            .iter()
            .filter(|row| targets.contains(&row.blob_id) && row.object_id.is_some())
            .zip(objects)
        {
            let terminal = match object {
                None => Some(store::BLOB_DELETED_EXTERNAL),
                // The rows and the fetched objects are paired positionally, off two separately
                // written filters that must agree. They do today — but every state below is
                // terminal, so confirm the object is this row's before acting on it rather than
                // trusting the two filters to stay in step.
                Some(object) if object.blob_id.as_deref() != Some(row.blob_id.as_str()) => None,
                Some(object) if !same_owner(object.owner.as_deref(), owner) => {
                    Some(store::BLOB_NOT_OWNER)
                }
                _ => None,
            };
            if let Some(terminal) = terminal {
                if store::evict_claimed_blob(pool, owner, &row.blob_id, batch_id, terminal)
                    .await
                    .map_err(SdError::internal)?
                {
                    evicted.push(row.blob_id.clone());
                }
            }
        }
    }
    store::rollback_batch(pool, batch_id, store::BATCH_EXECUTING, store::BATCH_FAILED)
        .await
        .map_err(SdError::internal)?;
    Ok(evicted)
}

pub async fn cancel_deletion(
    State(state): State<Arc<AppState>>,
    SdOwner(owner): SdOwner,
    SdBatchId(batch_id): SdBatchId,
) -> Result<Json<StatusResponse>, SdError> {
    let (pool, batch) = resolve_batch_pool(&state, batch_id, &owner).await?;
    if batch.state != store::BATCH_AWAITING_SIGNATURE {
        return Err(resolved(&batch.state));
    }
    if !store::rollback_batch(
        pool,
        batch_id,
        store::BATCH_AWAITING_SIGNATURE,
        store::BATCH_ROLLED_BACK,
    )
    .await
    .map_err(SdError::internal)?
    {
        let current = require_batch(pool, batch_id, &owner).await?;
        return Err(resolved(&current.state));
    }
    let current = require_batch(pool, batch_id, &owner).await?;
    Ok(Json(status_response(current)))
}

pub async fn deletion_status(
    State(state): State<Arc<AppState>>,
    SdOwner(owner): SdOwner,
    SdBatchId(batch_id): SdBatchId,
) -> Result<Json<StatusResponse>, SdError> {
    let (_, batch) = resolve_batch_pool(&state, batch_id, &owner).await?;
    Ok(Json(status_response(batch)))
}

fn status_response(batch: store::BatchRow) -> StatusResponse {
    StatusResponse {
        state: batch.state,
        blob_count: batch.blob_count,
        digest: batch.digest,
        resolved_at: batch.resolved_at.map(|value| value.to_rfc3339()),
    }
}

async fn require_batch(
    pool: &sqlx::PgPool,
    batch_id: Uuid,
    owner: &str,
) -> Result<store::BatchRow, SdError> {
    store::get_batch(pool, batch_id, owner)
        .await
        .map_err(SdError::internal)?
        .ok_or_else(|| SdError::new(SdCode::BatchNotFound, "Deletion batch not found"))
}

fn resolved(state: &str) -> SdError {
    SdError::with_details(
        SdCode::BatchAlreadyResolved,
        "Deletion batch already resolved",
        json!({"state": state}),
    )
}

async fn scope_pool<'a>(
    state: &'a AppState,
    scope: DeletionScope,
    owner: &str,
) -> Result<Option<&'a sqlx::PgPool>, SdError> {
    if !crate::types::security_delete_routes_enabled(&state.config) {
        return Err(SdError::new(SdCode::FeatureDisabled, "Feature disabled"));
    }
    match scope {
        DeletionScope::Legacy => Ok(state.legacy_db.as_deref().map(|db| db.pool())),
        DeletionScope::Current => {
            let pool = state.db.pool();
            store::sync_owner_post_migration_blobs(pool, owner)
                .await
                .map_err(SdError::internal)?;
            Ok(Some(pool))
        }
    }
}

fn candidate_batch_pools(state: &AppState) -> Result<Vec<&sqlx::PgPool>, SdError> {
    if !crate::types::security_delete_routes_enabled(&state.config) {
        return Err(SdError::new(SdCode::FeatureDisabled, "Feature disabled"));
    }
    let mut pools = Vec::with_capacity(2);
    if let Some(legacy_db) = state.legacy_db.as_deref() {
        pools.push(legacy_db.pool());
    }
    if state.config.legacy_db_url.as_deref() != Some(state.config.database_url.as_str()) {
        pools.push(state.db.pool());
    }
    Ok(pools)
}

async fn find_batch_in_pools<'a>(
    pools: &[&'a sqlx::PgPool],
    batch_id: Uuid,
    owner: &str,
) -> Result<(&'a sqlx::PgPool, store::BatchRow), SdError> {
    let mut last_error = None;
    for &pool in pools {
        match store::get_batch(pool, batch_id, owner).await {
            Ok(Some(batch)) => return Ok((pool, batch)),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%batch_id, %owner, %error, "candidate pool query failed for deletion batch");
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        return Err(SdError::internal(error));
    }
    Err(SdError::new(
        SdCode::BatchNotFound,
        "Deletion batch not found",
    ))
}

async fn resolve_batch_pool<'a>(
    state: &'a AppState,
    batch_id: Uuid,
    owner: &str,
) -> Result<(&'a sqlx::PgPool, store::BatchRow), SdError> {
    let pools = candidate_batch_pools(state)?;
    find_batch_in_pools(&pools, batch_id, owner).await
}

fn security_delete_sui(state: &AppState) -> Result<&dyn SuiApi, SdError> {
    state
        .security_delete_sui
        .as_deref()
        .ok_or_else(|| SdError::new(SdCode::FeatureDisabled, "Feature disabled"))
}

fn invalid_request() -> SdError {
    SdError::new(SdCode::InvalidRequest, "Invalid request")
}

fn claim_error(error: store::ClaimError) -> SdError {
    match error {
        store::ClaimError::ActiveBatchLimit(ids) => SdError::with_details(
            SdCode::ActiveBatchLimit,
            "Active deletion batch limit reached",
            json!({"activeBatchIds": ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>() }),
        ),
        store::ClaimError::Conflict(ids) => SdError::with_details(
            SdCode::BatchConflict,
            "Deletion selection conflicts with current state",
            json!({"conflictingBlobIds": ids}),
        ),
        store::ClaimError::Storage(error) => SdError::internal(error),
    }
}

/// The Walrus package to build `delete_blob` calls against.
///
/// Chain is authoritative: the `System` object carries the id of the package its code
/// currently lives in, and that changes when Walrus upgrades. The object's Move *type*
/// keeps naming the original package forever (Move types are immutable), so the type is
/// not a usable source. Calling a superseded package aborts in `system::inner` with abort
/// code 1 and every deletion fails on chain.
///
/// `configured` (`WALRUS_PACKAGE_ID`) is a fallback for networks whose system object does
/// not expose `package_id`, and an incident pin. A disagreement is logged, not silently
/// resolved, so an upgrade is never invisible.
fn walrus_package_id<'a>(
    configured: &'a str,
    system: &'a crate::sui::SharedObjectInfo,
) -> crate::sui::WalrusCallPackage<'a> {
    match system.package_id.as_deref() {
        Some(on_chain) => {
            if walrus_package_changed(configured, on_chain) {
                tracing::warn!(
                    configured,
                    on_chain,
                    "Walrus upgraded its package; calling the on-chain id (do NOT repoint \
                     WALRUS_PACKAGE_ID — it is the Blob type's immutable origin package)"
                );
            }
            crate::sui::WalrusCallPackage::from_chain(on_chain)
        }
        // The chain exposed no package id: fall back to config rather than fail every delete.
        None => crate::sui::WalrusCallPackage::from_chain(configured),
    }
}

/// Whether the chain's package differs from the configured one.
///
/// Compares parsed addresses, never strings: config may be short-hand (`0x3`) while the chain
/// returns canonical 32-byte form (`0x00…03`). A string compare would report drift between two
/// identical addresses and page ops forever over nothing.
fn walrus_package_changed(configured: &str, on_chain: &str) -> bool {
    if configured.is_empty() {
        return false;
    }
    match (
        configured.parse::<sui_sdk_types::Address>(),
        on_chain.parse::<sui_sdk_types::Address>(),
    ) {
        (Ok(configured), Ok(on_chain)) => configured != on_chain,
        _ => configured != on_chain,
    }
}

fn rpc_error(error: SuiErr) -> SdError {
    // The client-facing contract stays a sanitized RPC_UNAVAILABLE, but the cause
    // must be observable server-side or every RPC failure is undiagnosable.
    tracing::warn!(?error, "security-delete Sui RPC failure");
    SdError::new(SdCode::RpcUnavailable, "Sui RPC is temporarily unavailable")
}

async fn batch_get_all(
    sui: &dyn SuiApi,
    object_ids: &[String],
) -> Result<Vec<Option<crate::sui::ObjectInfo>>, SuiErr> {
    let mut objects = Vec::with_capacity(object_ids.len());
    for chunk in object_ids.chunks(RPC_OBJECT_BATCH) {
        objects.extend(sui.batch_get_objects(chunk).await?);
    }
    Ok(objects)
}

#[cfg(test)]
fn is_unknown_execution_outcome(error: &SuiErr) -> bool {
    matches!(error, SuiErr::Transport(_) | SuiErr::RateLimited)
}

async fn prepare_rpc_failure(pool: &sqlx::PgPool, batch_id: Uuid, error: SuiErr) -> SdError {
    rollback_after_prepare_failure(pool, batch_id).await;
    rpc_error(error)
}

async fn rollback_after_prepare_failure(pool: &sqlx::PgPool, batch_id: Uuid) {
    let _ = store::rollback_batch(
        pool,
        batch_id,
        store::BATCH_AWAITING_SIGNATURE,
        store::BATCH_ROLLED_BACK,
    )
    .await;
}

fn sponsor_address(key_b64: &str) -> Result<String, SdError> {
    let bytes = STANDARD
        .decode(key_b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(key_b64))
        .map_err(|_| SdError::new(SdCode::FeatureDisabled, "Feature disabled"))?;
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SdError::new(SdCode::FeatureDisabled, "Feature disabled"))?;
    Ok(sui_crypto::ed25519::Ed25519PrivateKey::new(secret)
        .public_key()
        .derive_address()
        .to_string())
}

fn nonce_collision(error: &AppError) -> bool {
    matches!(error, AppError::Internal(message) if message.contains("idx_deletion_nonce_epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::legacy_db::tests::fixture;
    use crate::sui::mock::MockSuiApi;
    use crate::sui::SuiEpoch;
    use crate::sui::WalrusCallPackage;
    use crate::sui::WalrusEpoch;
    use crate::sui::{ObjectInfo, SharedObjectInfo};

    fn system_object(package_id: Option<&str>) -> SharedObjectInfo {
        SharedObjectInfo {
            object_id: "0x6c2547cb".into(),
            initial_shared_version: 1,
            mutable: true,
            package_id: package_id.map(str::to_owned),
        }
    }

    /// Walrus upgrades its package; the configured id goes stale on its own, with no
    /// deploy and no config change. Building `delete_blob` against the superseded package
    /// aborts on chain (`system::inner`, abort code 1) and EVERY deletion fails — so the
    /// system object's `package_id` must win over configuration.
    ///
    /// Observed on testnet 2026-07-13: config `0xd84704c1…` (the original package, still
    /// named by the object's immutable Move type) vs on-chain `0x849e95d2…` (where the
    /// code actually lives after the upgrade).
    #[test]
    /// End-to-end guard for BUG 2, at the seam `prepare_deletion` actually uses.
    ///
    /// `walrus_package_id()` being correct is not enough — `prepare` must FEED its result to
    /// `build_delete_tx`. Reverting that one argument to `state.config.walrus_package_id`
    /// reintroduces bug 2 in its literal production form: every `delete_blob` aborts with
    /// `EWrongVersion` and no deletion can ever succeed. Both types are `&str`, so the
    /// compiler cannot catch it — only this assertion can.
    ///
    /// Builds the PTB exactly as prepare does, then reads the package back out of the bytes
    /// and asserts it is the CHAIN's, not the stale configured one.
    #[test]
    fn the_built_ptb_calls_the_chains_package_not_the_stale_config() {
        const CONFIGURED_BUT_STALE: &str = "0xd847";
        const CURRENT_ON_CHAIN: &str = "0x849e";

        let system = system_object(Some(CURRENT_ON_CHAIN));
        // The exact selection prepare makes.
        let walrus_package = walrus_package_id(CONFIGURED_BUT_STALE, &system);

        let blob = ObjectInfo {
            object_id: "0x01".into(),
            version: 1,
            digest: Digest::new([1; 32]).to_string(),
            owner: Some(OWNER.into()),
            blob_id: Some("blob-0001".into()),
            end_epoch: Some(WalrusEpoch(500)),
            package_id: None,
        };
        let built = crate::sui::tx_build::build_delete_tx(
            OWNER,
            OWNER,
            std::slice::from_ref(&blob),
            walrus_package,
            &system,
            SuiEpoch(1159),
            1000,
            10_000_000,
            &[9; 32],
            7,
        )
        .expect("prepare builds this PTB");

        let called = input_freshness::transaction_package(&built.tx_bytes)
            .expect("the PTB decodes")
            .expect("a delete PTB always has a MoveCall");
        assert_eq!(
            called,
            CURRENT_ON_CHAIN.parse().unwrap(),
            "the PTB must call the chain's package; calling the stale configured one aborts \
             EWrongVersion and no deletion can ever succeed"
        );
        assert_ne!(
            called,
            CONFIGURED_BUT_STALE.parse().unwrap(),
            "regression guard for bug 2"
        );

        // And the transaction is bounded by the SUI clock, not the Walrus one. A Walrus epoch
        // here (457 vs Sui 1159) builds a tx born ~700 epochs expired, which validators reject
        // outright. The `SuiEpoch` newtype makes that a compile error; this pins the value.
        assert_eq!(
            built.expire_epoch, 1159,
            "ValidDuring must carry the Sui epoch"
        );
    }

    fn walrus_package_prefers_the_chain_over_stale_config() {
        const CONFIGURED_BUT_STALE: &str = "0xd84704c1";
        const CURRENT_ON_CHAIN: &str = "0x849e95d2";

        assert_eq!(
            walrus_package_id(CONFIGURED_BUT_STALE, &system_object(Some(CURRENT_ON_CHAIN))),
            WalrusCallPackage::from_chain(CURRENT_ON_CHAIN),
            "the chain is authoritative: a stale configured package aborts every delete"
        );

        // Agreement is the ordinary case and must be preserved.
        assert_eq!(
            walrus_package_id(CURRENT_ON_CHAIN, &system_object(Some(CURRENT_ON_CHAIN))),
            WalrusCallPackage::from_chain(CURRENT_ON_CHAIN),
        );

        // Fallback: a system object that exposes no package id leaves config in charge,
        // so networks without the field keep working.
        assert_eq!(
            walrus_package_id(CONFIGURED_BUT_STALE, &system_object(None)),
            WalrusCallPackage::from_chain(CONFIGURED_BUT_STALE),
        );
    }
    use sui_sdk_types::{Digest, ExecutionError, ExecutionStatus};

    const OWNER: &str = "0x000000000000000000000000000000000000000000000000000000000000000a";

    #[test]
    fn crash_test_requires_localnet_and_matching_secret() {
        assert!(crash_test_credentials_match(
            "localnet",
            Some("secret"),
            Some("secret")
        ));
        assert!(!crash_test_credentials_match(
            "mainnet",
            Some("secret"),
            Some("secret")
        ));
        assert!(!crash_test_credentials_match(
            "localnet",
            Some("secret"),
            Some("wrong")
        ));
        assert!(!crash_test_credentials_match("localnet", None, None));
    }

    #[tokio::test]
    async fn prepare_rpc_budget_bounds_a_stalled_operation() {
        let result =
            with_prepare_rpc_budget(Duration::from_millis(5), std::future::pending::<()>()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn prepare_rpc_timeout_rolls_back_claim() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        sqlx::query(
            "INSERT INTO delete_blobs_tracking(owner,blob_id,object_id,created_at)
             VALUES($1,'timeout-blob','0x1',NOW())",
        )
        .bind(OWNER)
        .execute(legacy.pool())
        .await
        .unwrap();
        let batch_id = Uuid::new_v4();
        store::create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            "legacy",
            batch_id,
            &["timeout-blob".into()],
            16,
        )
        .await
        .unwrap();

        let error = prepare_rpc_failure(
            legacy.pool(),
            batch_id,
            SuiErr::Transport("prepare RPC budget exhausted".into()),
        )
        .await;
        assert_eq!(error.code, SdCode::RpcUnavailable);
        let batch = store::get_batch(legacy.pool(), batch_id, OWNER)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(batch.state, store::BATCH_ROLLED_BACK);
        let tracking_state: String = sqlx::query_scalar(
            "SELECT state FROM delete_blobs_tracking WHERE owner=$1 AND blob_id='timeout-blob'",
        )
        .bind(OWNER)
        .fetch_one(legacy.pool())
        .await
        .unwrap();
        assert_eq!(tracking_state, store::BLOB_DELETABLE);

        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[test]
    fn list_cursor_roundtrip_and_rejects_invalid() {
        let time = DateTime::from_timestamp_micros(1_700_000_000_123_456).unwrap();
        let encoded = encode_cursor(time, "blob".into());
        assert_eq!(
            decode_cursor(Some(&encoded)).unwrap(),
            Some((time, "blob".into()))
        );
        assert_eq!(
            decode_cursor(Some("garbage")).unwrap_err().code,
            SdCode::InvalidRequest
        );
    }

    #[test]
    fn list_state_and_prepare_validation_are_closed() {
        assert!(parse_states(Some("deleting,deleted")).is_ok());
        assert_eq!(
            parse_states(Some("unknown")).unwrap_err().code,
            SdCode::InvalidRequest
        );
    }

    #[test]
    fn submit_unknown_outcome_is_left_for_reconciliation() {
        assert!(is_unknown_execution_outcome(&SuiErr::Transport(
            "timeout".into()
        )));
        assert!(is_unknown_execution_outcome(&SuiErr::RateLimited));
        assert!(!is_unknown_execution_outcome(&SuiErr::Rejected(
            "definitive".into()
        )));
        assert!(!is_unknown_execution_outcome(
            &SuiErr::SponsorFundsUnavailable("definitive".into())
        ));
        // A NotFound from an execute is a rejection, not an in-flight submission: it must not
        // be retried as if the outcome were unknown.
        assert!(!is_unknown_execution_outcome(&SuiErr::NotFound(
            "definitive".into()
        )));
    }

    #[tokio::test]
    #[ignore]
    async fn submit_revalidation_resolves_missing_input_before_execute() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        let blobs = [("a", "0x1", 1_u8), ("b", "0x2", 2_u8)]
            .into_iter()
            .map(|(blob_id, object_id, marker)| ObjectInfo {
                object_id: object_id.into(),
                version: 1,
                digest: Digest::new([marker; 32]).to_string(),
                owner: Some(OWNER.into()),
                blob_id: Some(blob_id.into()),
                end_epoch: Some(WalrusEpoch(500)),
                package_id: None,
            })
            .collect::<Vec<_>>();
        for blob in &blobs {
            sqlx::query(
                "INSERT INTO delete_blobs_tracking(owner,blob_id,object_id,created_at)
                 VALUES($1,$2,$3,NOW())",
            )
            .bind(OWNER)
            .bind(blob.blob_id.as_deref().unwrap())
            .bind(&blob.object_id)
            .execute(legacy.pool())
            .await
            .unwrap();
        }
        let batch_id = Uuid::new_v4();
        store::create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            "legacy",
            batch_id,
            &["a".into(), "b".into()],
            16,
        )
        .await
        .unwrap();
        let built = build_delete_tx(
            OWNER,
            "0xb",
            &blobs,
            WalrusCallPackage::from_chain("0xc"),
            &SharedObjectInfo {
                object_id: "0xd".into(),
                initial_shared_version: 1,
                mutable: true,
                package_id: None,
            },
            SuiEpoch(1),
            1,
            20_000_000,
            &[8; 32],
            4,
        )
        .unwrap();
        store::set_batch_prepared(
            legacy.pool(),
            batch_id,
            &built.digest,
            &built.tx_bytes,
            &bcs::to_bytes(&built.input_blob_ids).unwrap(),
            2,
            4,
            1,
        )
        .await
        .unwrap();
        assert!(
            store::begin_batch_execution(legacy.pool(), batch_id, &[vec![1], vec![2]])
                .await
                .unwrap()
        );
        let batch = store::get_batch(legacy.pool(), batch_id, OWNER)
            .await
            .unwrap()
            .unwrap();
        let mock = MockSuiApi::default();
        mock.objects.lock().unwrap().insert(
            "0x2".parse::<sui_sdk_types::Address>().unwrap().to_string(),
            blobs[1].clone(),
        );

        let evicted = revalidate_before_execute(
            legacy.pool(),
            &mock,
            batch_id,
            OWNER,
            &batch,
            &built.tx_bytes,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(evicted, vec!["a"]);
        assert_eq!(
            store::get_batch(legacy.pool(), batch_id, OWNER)
                .await
                .unwrap()
                .unwrap()
                .state,
            store::BATCH_FAILED
        );
        let states: Vec<(String, String)> = sqlx::query_as(
            "SELECT blob_id,state FROM delete_blobs_tracking WHERE owner=$1 ORDER BY blob_id",
        )
        .bind(OWNER)
        .fetch_all(legacy.pool())
        .await
        .unwrap();
        assert_eq!(
            states,
            vec![
                ("a".into(), store::BLOB_DELETED_EXTERNAL.into()),
                ("b".into(), store::BLOB_DELETABLE.into()),
            ]
        );
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn submit_culprit_resolution_evicts_only_confirmed_missing_input() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        for (blob, object) in [("a", "0x1"), ("b", "0x2")] {
            sqlx::query(
                "INSERT INTO delete_blobs_tracking(owner,blob_id,object_id,created_at)
                 VALUES($1,$2,$3,NOW())",
            )
            .bind(OWNER)
            .bind(blob)
            .bind(object)
            .execute(legacy.pool())
            .await
            .unwrap();
        }
        let batch_id = Uuid::new_v4();
        store::create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            "legacy",
            batch_id,
            &["a".into(), "b".into()],
            16,
        )
        .await
        .unwrap();
        store::set_batch_prepared(
            legacy.pool(),
            batch_id,
            "digest",
            &[1],
            &bcs::to_bytes(&vec!["a".to_string(), "b".to_string()]).unwrap(),
            2,
            1,
            10,
        )
        .await
        .unwrap();
        store::cas_batch_state(
            legacy.pool(),
            batch_id,
            store::BATCH_AWAITING_SIGNATURE,
            store::BATCH_EXECUTING,
        )
        .await
        .unwrap();
        let batch = store::get_batch(legacy.pool(), batch_id, OWNER)
            .await
            .unwrap()
            .unwrap();
        let mock = MockSuiApi::default(); // object 0x2 absent => confirmed external delete
        let evicted = resolve_committed_failure(
            legacy.pool(),
            &mock,
            batch_id,
            OWNER,
            &batch,
            &ExecutionStatus::Failure {
                error: ExecutionError::InputObjectDeleted,
                command: Some(1),
            },
        )
        .await
        .unwrap();
        assert_eq!(evicted, vec!["b"]);
        let states: Vec<(String, String)> = sqlx::query_as(
            "SELECT blob_id,state FROM delete_blobs_tracking WHERE owner=$1 ORDER BY blob_id",
        )
        .bind(OWNER)
        .fetch_all(legacy.pool())
        .await
        .unwrap();
        assert_eq!(
            states,
            vec![
                ("a".into(), store::BLOB_DELETABLE.into()),
                ("b".into(), store::BLOB_DELETED_EXTERNAL.into()),
            ]
        );
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    /// The eviction path pairs rows with fetched objects positionally, off two separately
    /// written filters. If those ever fall out of step a row is judged against ANOTHER blob's
    /// object — and `not_owner` is terminal, so a healthy blob would be hidden from its owner
    /// for good. Feed it a mismatched object directly: the row must be left alone.
    #[tokio::test]
    #[ignore]
    async fn submit_resolution_ignores_an_object_belonging_to_a_different_blob() {
        let Some((legacy, admin, schema)) = fixture().await else {
            return;
        };
        for (blob, object) in [("a", "0x1"), ("b", "0x2")] {
            sqlx::query(
                "INSERT INTO delete_blobs_tracking(owner,blob_id,object_id,created_at)
                 VALUES($1,$2,$3,NOW())",
            )
            .bind(OWNER)
            .bind(blob)
            .bind(object)
            .execute(legacy.pool())
            .await
            .unwrap();
        }
        let batch_id = Uuid::new_v4();
        store::create_batch_and_claim_selection(
            legacy.pool(),
            OWNER,
            "legacy",
            batch_id,
            &["a".into(), "b".into()],
            16,
        )
        .await
        .unwrap();
        store::set_batch_prepared(
            legacy.pool(),
            batch_id,
            "digest",
            &[1],
            &bcs::to_bytes(&vec!["a".to_string(), "b".to_string()]).unwrap(),
            2,
            1,
            10,
        )
        .await
        .unwrap();
        store::cas_batch_state(
            legacy.pool(),
            batch_id,
            store::BATCH_AWAITING_SIGNATURE,
            store::BATCH_EXECUTING,
        )
        .await
        .unwrap();
        let batch = store::get_batch(legacy.pool(), batch_id, OWNER)
            .await
            .unwrap()
            .unwrap();

        // Both objects exist, but each answers for the OTHER row's blob and is owned by someone
        // else. Judged against the wrong row, each looks like a foreign object => `not_owner`.
        let mock = MockSuiApi::default();
        let stranger = "0x00000000000000000000000000000000000000000000000000000000000000ff";
        for (object_id, wrong_blob) in [("0x1", "b"), ("0x2", "a")] {
            mock.objects.lock().unwrap().insert(
                object_id.into(),
                ObjectInfo {
                    object_id: object_id.into(),
                    version: 1,
                    digest: Digest::new([7; 32]).to_string(),
                    owner: Some(stranger.into()),
                    blob_id: Some(wrong_blob.into()),
                    end_epoch: Some(WalrusEpoch(9_000)),
                    package_id: None,
                },
            );
        }
        let evicted = resolve_committed_failure(
            legacy.pool(),
            &mock,
            batch_id,
            OWNER,
            &batch,
            &ExecutionStatus::Failure {
                error: ExecutionError::InsufficientGas,
                command: None,
            },
        )
        .await
        .unwrap();

        assert!(
            evicted.is_empty(),
            "a mismatched object must never evict a row, got {evicted:?}"
        );
        let states: Vec<(String, String)> = sqlx::query_as(
            "SELECT blob_id,state FROM delete_blobs_tracking WHERE owner=$1 ORDER BY blob_id",
        )
        .bind(OWNER)
        .fetch_all(legacy.pool())
        .await
        .unwrap();
        assert_eq!(
            states,
            vec![
                ("a".into(), store::BLOB_DELETABLE.into()),
                ("b".into(), store::BLOB_DELETABLE.into()),
            ],
            "both rows must stay deletable, not be terminalized not_owner"
        );
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[test]
    fn deletion_scope_parses_legacy_default_current_and_rejects_unknown() {
        assert_eq!(DeletionScope::parse(None).unwrap(), DeletionScope::Legacy);
        assert_eq!(
            DeletionScope::parse(Some("legacy")).unwrap(),
            DeletionScope::Legacy
        );
        assert_eq!(
            DeletionScope::parse(Some("current")).unwrap(),
            DeletionScope::Current
        );
        assert_eq!(
            DeletionScope::parse(Some("all")).unwrap_err().code,
            SdCode::InvalidRequest
        );
        assert_eq!(
            DeletionScope::parse(Some("")).unwrap_err().code,
            SdCode::InvalidRequest
        );
    }

    #[tokio::test]
    async fn post_migration_scope_isolates_pools_syncs_object_ids_and_clears_idempotency() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Some(url) = std::env::var("TEST_LEGACY_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()
        else {
            return;
        };
        let Ok(admin) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let legacy_schema = format!("sd_legacy_{}", Uuid::new_v4().simple());
        let primary_schema = format!("sd_primary_{}", Uuid::new_v4().simple());
        for schema in [&legacy_schema, &primary_schema] {
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
        }

        let legacy_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::from_str(&url)
                    .unwrap()
                    .options([("search_path", legacy_schema.as_str())]),
            )
            .await
            .unwrap();
        let primary_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::from_str(&url)
                    .unwrap()
                    .options([("search_path", primary_schema.as_str())]),
            )
            .await
            .unwrap();

        for pool in [&legacy_pool, &primary_pool] {
            sqlx::raw_sql(
                "CREATE TABLE vector_entries (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    namespace TEXT NOT NULL DEFAULT 'default',
                    blob_id TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE TABLE memory_tombstones (
                    memory_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    blob_id TEXT NOT NULL,
                    deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );",
            )
            .execute(pool)
            .await
            .unwrap();
            store::ensure_post_migration_schema(pool).await.unwrap();
        }
        // Calling ensure_post_migration_schema a second time must be idempotent.
        store::ensure_post_migration_schema(&primary_pool)
            .await
            .unwrap();

        sqlx::raw_sql(
            "CREATE TABLE remember_jobs (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'default',
                status TEXT NOT NULL DEFAULT 'done',
                blob_id TEXT,
                blob_object_id TEXT,
                idempotency_key TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&primary_pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO delete_blobs_tracking (owner, blob_id, object_id, created_at)
             VALUES ($1, 'legacy-blob', '0x11', NOW())",
        )
        .bind(OWNER)
        .execute(&legacy_pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id)
             VALUES ('mem-post-1', $1, 'agent', 'post-blob-1')",
        )
        .bind(OWNER)
        .execute(&primary_pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, blob_id, blob_object_id, idempotency_key)
             VALUES ('job-post-1', $1, 'agent', 'done', 'post-blob-1', '0xABC', 'idem-post-1')",
        )
        .bind(OWNER)
        .execute(&primary_pool)
        .await
        .unwrap();

        store::sync_owner_post_migration_blobs(&primary_pool, OWNER)
            .await
            .unwrap();

        let primary_rows =
            store::list_blobs(&primary_pool, OWNER, "current", &[store::BLOB_DELETABLE], None, 10)
                .await
                .unwrap();
        assert_eq!(primary_rows.len(), 1);
        assert_eq!(primary_rows[0].blob_id, "post-blob-1");
        assert_eq!(
            primary_rows[0].object_id.as_deref(),
            Some("0x0000000000000000000000000000000000000000000000000000000000000abc")
        );

        let legacy_rows =
            store::list_blobs(&legacy_pool, OWNER, "legacy", &[store::BLOB_DELETABLE], None, 10)
                .await
                .unwrap();
        assert_eq!(legacy_rows.len(), 1);
        assert_eq!(legacy_rows[0].blob_id, "legacy-blob");

        let legacy_batch_id = Uuid::new_v4();
        let current_batch_id = Uuid::new_v4();
        store::create_batch_and_claim_selection(
            &legacy_pool,
            OWNER,
            "legacy",
            legacy_batch_id,
            &["legacy-blob".into()],
            16,
        )
        .await
        .unwrap();
        store::create_batch_and_claim_selection(
            &primary_pool,
            OWNER,
            "current",
            current_batch_id,
            &["post-blob-1".into()],
            16,
        )
        .await
        .unwrap();

        let pools = [&legacy_pool, &primary_pool];
        let (_, found_legacy) = find_batch_in_pools(&pools, legacy_batch_id, OWNER)
            .await
            .unwrap();
        assert_eq!(found_legacy.id, legacy_batch_id);
        let (_, found_current) = find_batch_in_pools(&pools, current_batch_id, OWNER)
            .await
            .unwrap();
        assert_eq!(found_current.id, current_batch_id);
        assert_eq!(
            find_batch_in_pools(&pools, Uuid::new_v4(), OWNER)
                .await
                .unwrap_err()
                .code,
            SdCode::BatchNotFound
        );

        store::set_batch_prepared(
            &primary_pool,
            current_batch_id,
            "digest-post-1",
            &[1, 2, 3],
            &bcs::to_bytes(&vec!["post-blob-1".to_string()]).unwrap(),
            1,
            7,
            100,
        )
        .await
        .unwrap();
        assert!(
            store::begin_batch_execution(&primary_pool, current_batch_id, &[vec![1], vec![2]])
                .await
                .unwrap()
        );
        let deleted = store::finalize_batch_deleted(
            &primary_pool,
            current_batch_id,
            store::BATCH_EXECUTING,
        )
        .await
        .unwrap();
        assert_eq!(deleted, Some(1));

        let remaining_vectors: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vector_entries WHERE owner = $1")
                .bind(OWNER)
                .fetch_one(&primary_pool)
                .await
                .unwrap();
        assert_eq!(remaining_vectors, 0);

        let tombstone_ns: Option<String> = sqlx::query_scalar(
            "SELECT namespace FROM memory_tombstones WHERE memory_id = 'mem-post-1'",
        )
        .fetch_optional(&primary_pool)
        .await
        .unwrap();
        assert_eq!(tombstone_ns.as_deref(), Some("agent"));

        let idempotency_after: Option<String> = sqlx::query_scalar(
            "SELECT idempotency_key FROM remember_jobs WHERE id = 'job-post-1'",
        )
        .fetch_one(&primary_pool)
        .await
        .unwrap();
        assert_eq!(
            idempotency_after, None,
            "finalizing post-migration deletion must release remember_jobs.idempotency_key"
        );

        // Re-syncing after deletion must preserve the terminal `deleted` state.
        store::sync_owner_post_migration_blobs(&primary_pool, OWNER)
            .await
            .unwrap();
        let counts = store::counts(&primary_pool, OWNER, "current").await.unwrap();
        assert_eq!(counts.deletable, 0);
        assert_eq!(counts.deleted, 1);

        drop(legacy_pool);
        drop(primary_pool);
        for schema in [&legacy_schema, &primary_schema] {
            sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                .execute(&admin)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn single_database_shared_db_preserves_scope_isolation_and_does_not_cross_claim() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Some(url) = std::env::var("TEST_LEGACY_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()
        else {
            return;
        };
        let Ok(admin) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let shared_schema = format!("sd_shared_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {shared_schema}"))
            .execute(&admin)
            .await
            .unwrap();

        let shared_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::from_str(&url)
                    .unwrap()
                    .options([("search_path", shared_schema.as_str())]),
            )
            .await
            .unwrap();

        sqlx::raw_sql(
            "CREATE TABLE vector_entries (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT 'default',
                blob_id TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE memory_tombstones (
                memory_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                namespace TEXT NOT NULL,
                blob_id TEXT NOT NULL,
                deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );",
        )
        .execute(&shared_pool)
        .await
        .unwrap();

        // Seed a pre-migration row into vector_entries BEFORE running the
        // legacy migrations, matching the real shared-DB (LEGACY_DB_URL == DATABASE_URL)
        // startup path where migration 002 backfills existing rows as scope=legacy
        // and migration 001/003 installs trg_track_deletable on vector_entries.
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, created_at)
             VALUES ('mem-legacy-1', $1, 'default', 'legacy-row', NOW() - INTERVAL '1 day')",
        )
        .bind(OWNER)
        .execute(&shared_pool)
        .await
        .unwrap();

        let legacy_on_shared = crate::storage::legacy_db::LegacyDb::new_with_search_path(
            &url,
            Some(&shared_schema),
        )
        .await
        .unwrap();
        store::ensure_post_migration_schema(&shared_pool).await.unwrap();

        let trigger_installed: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM pg_trigger t
                JOIN pg_class c ON c.oid = t.tgrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = current_schema()
                  AND c.relname = 'vector_entries'
                  AND t.tgname = 'trg_track_deletable'
                  AND NOT t.tgisinternal
            )",
        )
        .fetch_one(&shared_pool)
        .await
        .unwrap();
        assert!(trigger_installed, "trg_track_deletable must be active on vector_entries");

        // Resolve the pre-migration row's object_id so it is claimable by legacy delete-all.
        store::set_object_ids(&shared_pool, OWNER, &[("legacy-row".into(), "0xaaa".into())])
            .await
            .unwrap();

        // 1. Insert a post-migration memory while remember_jobs does not exist yet
        //    (covers the no-remember-jobs sync branch with trg_track_deletable installed).
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, created_at)
             VALUES ('mem-post-no-job', $1, 'agent', 'current-no-job', NOW())",
        )
        .bind(OWNER)
        .execute(&shared_pool)
        .await
        .unwrap();

        store::sync_owner_post_migration_blobs(&shared_pool, OWNER)
            .await
            .unwrap();

        // 2. Add remember_jobs with blob_object_id and insert a second post-migration
        //    memory through trg_track_deletable, then verify sync backfills object_id
        //    without reverting scope to legacy.
        sqlx::raw_sql(
            "CREATE TABLE remember_jobs (
                id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                blob_id TEXT,
                blob_object_id TEXT
            );",
        )
        .execute(&shared_pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, created_at)
             VALUES ('mem-post-1', $1, 'agent', 'current-row', NOW() + INTERVAL '1 second')",
        )
        .bind(OWNER)
        .execute(&shared_pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, blob_id, blob_object_id)
             VALUES ('job-post-1', $1, 'current-row', '0xbbb')",
        )
        .bind(OWNER)
        .execute(&shared_pool)
        .await
        .unwrap();

        store::sync_owner_post_migration_blobs(&shared_pool, OWNER)
            .await
            .unwrap();

        // Also assign an object_id to current-no-job so both current rows are claimable.
        store::set_object_ids(&shared_pool, OWNER, &[("current-no-job".into(), "0xccc".into())])
            .await
            .unwrap();

        // 3. list_blobs with scope=legacy must only see the legacy row.
        let legacy_list = store::list_blobs(&shared_pool, OWNER, "legacy", &[store::BLOB_DELETABLE], None, 10)
            .await
            .unwrap();
        assert_eq!(legacy_list.len(), 1);
        assert_eq!(legacy_list[0].blob_id, "legacy-row");
        assert_eq!(legacy_list[0].scope, "legacy");

        // 4. list_blobs with scope=current must see both trigger-captured post-migration rows.
        let current_list = store::list_blobs(&shared_pool, OWNER, "current", &[store::BLOB_DELETABLE], None, 10)
            .await
            .unwrap();
        assert_eq!(current_list.len(), 2);
        assert_eq!(current_list[0].blob_id, "current-no-job");
        assert_eq!(current_list[0].scope, "current");
        assert_eq!(current_list[0].object_id.as_deref(), Some("0xccc"));
        assert_eq!(current_list[1].blob_id, "current-row");
        assert_eq!(current_list[1].scope, "current");
        let expected_obj = format!("0x{:0>64}", "bbb");
        assert_eq!(current_list[1].object_id.as_deref(), Some(expected_obj.as_str()));

        // 5. counts per scope must be isolated.
        let legacy_counts = store::counts(&shared_pool, OWNER, "legacy").await.unwrap();
        assert_eq!(legacy_counts.total, 1);
        assert_eq!(legacy_counts.deletable, 1);

        let current_counts = store::counts(&shared_pool, OWNER, "current").await.unwrap();
        assert_eq!(current_counts.total, 2);
        assert_eq!(current_counts.deletable, 2);

        // 6. Pre-migration delete-all must NOT claim post-migration memories.
        let legacy_batch_id = Uuid::new_v4();
        let claim_legacy = store::create_batch_and_claim_all(&shared_pool, OWNER, "legacy", legacy_batch_id, 10, 5)
            .await
            .unwrap();
        assert_eq!(claim_legacy.rows.len(), 1);
        assert_eq!(claim_legacy.rows[0].blob_id, "legacy-row");

        // Both post-migration rows must still be deletable and untouched in scope=current.
        let current_after_legacy_claim = store::list_blobs(&shared_pool, OWNER, "current", &[store::BLOB_DELETABLE], None, 10)
            .await
            .unwrap();
        assert_eq!(current_after_legacy_claim.len(), 2);
        assert_eq!(current_after_legacy_claim[0].blob_id, "current-no-job");
        assert_eq!(current_after_legacy_claim[1].blob_id, "current-row");

        // 7. Post-migration claim claims the current rows.
        let current_batch_id = Uuid::new_v4();
        let claim_current = store::create_batch_and_claim_all(&shared_pool, OWNER, "current", current_batch_id, 10, 5)
            .await
            .unwrap();
        let mut claimed_current_ids: Vec<&str> =
            claim_current.rows.iter().map(|r| r.blob_id.as_str()).collect();
        claimed_current_ids.sort_unstable();
        assert_eq!(claimed_current_ids, vec!["current-no-job", "current-row"]);

        drop(legacy_on_shared);
        drop(shared_pool);
        sqlx::query(&format!("DROP SCHEMA {shared_schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn find_batch_in_pools_survives_failed_legacy_pool() {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::str::FromStr;

        let Some(url) = std::env::var("TEST_LEGACY_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()
        else {
            return;
        };
        let Ok(admin) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let bad_schema = format!("sd_bad_{}", Uuid::new_v4().simple());
        let good_schema = format!("sd_good_{}", Uuid::new_v4().simple());
        for schema in [&bad_schema, &good_schema] {
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
        }

        // bad_pool has no tables created, so get_batch will error with undefined table.
        let bad_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::from_str(&url)
                    .unwrap()
                    .options([("search_path", bad_schema.as_str())]),
            )
            .await
            .unwrap();

        // good_pool has schema and a batch.
        let good_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::from_str(&url)
                    .unwrap()
                    .options([("search_path", good_schema.as_str())]),
            )
            .await
            .unwrap();

        store::ensure_post_migration_schema(&good_pool).await.unwrap();
        let batch_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO deletion_batches (id, owner, state, scope)
             VALUES ($1, $2, 'awaiting_signature', 'current')",
        )
        .bind(batch_id)
        .bind(OWNER)
        .execute(&good_pool)
        .await
        .unwrap();

        // bad_pool is first in pools slice; find_batch_in_pools must not abort,
        // it must proceed to good_pool and successfully find the batch.
        let pools = [&bad_pool, &good_pool];
        let (_, found) = find_batch_in_pools(&pools, batch_id, OWNER)
            .await
            .expect("must find batch in healthy pool even when first pool errors");
        assert_eq!(found.id, batch_id);
        assert_eq!(found.scope, "current");

        drop(bad_pool);
        drop(good_pool);
        for schema in [&bad_schema, &good_schema] {
            sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                .execute(&admin)
                .await
                .unwrap();
        }
    }
}
