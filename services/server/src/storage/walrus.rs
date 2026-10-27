use crate::types::{AppError, SidecarError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures::stream::{FuturesUnordered, StreamExt};
use std::time::Duration;

const SIDECAR_WALRUS_TIMEOUT: Duration = Duration::from_secs(300);

/// `Display` for `reqwest::Error` stops at "error sending request for url".
/// Append the source chain so a dropped upload says reset, refused, or timed out.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(next) = source {
        let text = next.to_string();
        if parts.last().is_some_and(|prev| prev == &text) {
            break;
        }
        parts.push(text);
        if parts.len() == 4 {
            break;
        }
        source = next.source();
    }
    parts.join(": ")
}

const WALRUS_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15);
const DURABLE_UPLOAD_PROTOCOL_VERSION: u32 = 3;

/// Result of a Walrus blob upload
pub struct UploadResult {
    /// Walrus content-addressed blob ID (base64url)
    pub blob_id: String,
    /// Sui object ID of the Blob object (hex, e.g. "0x...")
    #[allow(dead_code)]
    pub object_id: Option<String>,
    /// Walrus epoch at which the blob's storage expires
    pub end_epoch: Option<i32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedRegisterTransaction {
    pub transaction_bytes: String,
    pub signature: String,
    pub digest: String,
    /// Enoki sponsorship handle. Absent for legacy/direct-signed journals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor_digest: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadExecutionIdentity {
    pub chain_identifier: String,
    pub walrus_package_id: String,
}

#[derive(Debug, Clone)]
pub struct UploadJournal {
    pub wallet_index: usize,
    pub wallet_address: Option<String>,
    pub execution_identity: Option<UploadExecutionIdentity>,
    pub resume_step: Option<serde_json::Value>,
    pub register_transaction: Option<PreparedRegisterTransaction>,
}

pub enum DurableUploadAdvance {
    /// Exact signed bytes are ready to checkpoint before execution.
    Prepared(UploadJournal),
    /// A proven-safe reset needs another prepare/execute cycle. Preserve its
    /// cause so a bounded rebuild failure reports the underlying sidecar error.
    Reset {
        journal: UploadJournal,
        reason: String,
    },
    Step {
        journal: UploadJournal,
        step: serde_json::Value,
    },
}

#[derive(Debug)]
pub enum UploadBlobError {
    App(AppError),
    MetadataTransferFailed {
        blob_id: String,
        object_id: String,
        message: String,
        /// Walrus epoch the storage lease ends at — carried from
        /// whichever response surfaced the failure (the sidecar includes it
        /// on both the success shape and the metadata-transfer failure
        /// shape) so the eventual recovery/finalize path doesn't have to
        /// insert with `end_epoch = None` for a value that was actually
        /// known at upload time.
        end_epoch: Option<i32>,
    },
}

impl std::fmt::Display for UploadBlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadBlobError::App(err) => write!(f, "{}", err),
            UploadBlobError::MetadataTransferFailed { message, .. } => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for UploadBlobError {}

impl From<AppError> for UploadBlobError {
    fn from(err: AppError) -> Self {
        UploadBlobError::App(err)
    }
}

impl From<UploadBlobError> for AppError {
    fn from(err: UploadBlobError) -> Self {
        match err {
            UploadBlobError::App(err) => err,
            UploadBlobError::MetadataTransferFailed { message, .. } => AppError::Internal(message),
        }
    }
}

/// A blob discovered from on-chain query
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct OnChainBlob {
    /// Walrus blob ID
    #[serde(rename = "blobId")]
    pub blob_id: String,
    /// Sui object ID
    #[serde(rename = "objectId")]
    pub object_id: String,
    /// Namespace from on-chain metadata
    pub namespace: String,
    /// Walrus Memory package ID from on-chain metadata
    #[serde(rename = "packageId", default)]
    pub package_id: String,
    /// Delegate/agent public key from on-chain metadata (memwal_agent_id)
    #[serde(rename = "agentId", default)]
    pub agent_id: Option<String>,
}

/// Response from sidecar query-blobs endpoint
#[derive(Debug, serde::Deserialize)]
struct QueryBlobsResponse {
    blobs: Vec<OnChainBlob>,
    total: usize,
    /// True when the sidecar's raw on-chain candidate fetch hit its own
    /// cap before namespace/package filtering -- `blobs` may be
    /// an incomplete view of what's actually on chain even though this
    /// response itself isn't further truncated by `limit`. Defaulted so an
    /// older sidecar (mid rolling-deploy) that doesn't send this field yet
    /// still parses.
    #[serde(rename = "sourceCapped", default)]
    source_capped: bool,
}

/// A blob's on-chain storage lease, as returned by the sidecar's
/// `/walrus/query-blobs` endpoint when called with `includeStorageLease:
/// true` (the periodic expiry sweep). This is a genuinely different response
/// shape from `OnChainBlob`/`query_blobs_by_owner` — no `namespace`,
/// `packageId`, or `agentId` — so it gets its own struct rather than
/// extending `OnChainBlob`.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
pub struct BlobStorageLease {
    /// Walrus blob ID
    #[serde(rename = "blobId")]
    pub blob_id: String,
    /// Sui object ID of the Blob object
    #[serde(rename = "objectId")]
    pub object_id: String,
    /// Walrus epoch at which this blob's storage lease ends
    #[serde(rename = "storageEndEpoch")]
    pub storage_end_epoch: i32,
}

/// Response from sidecar query-blobs endpoint when `includeStorageLease:
/// true` is requested.
#[derive(Debug, serde::Deserialize)]
struct QueryBlobStorageLeasesResponse {
    blobs: Vec<BlobStorageLease>,
    #[allow(dead_code)]
    total: usize,
    #[serde(rename = "currentEpoch")]
    current_epoch: i32,
    #[allow(dead_code)]
    #[serde(rename = "nonexistentBlobIds", default)]
    nonexistent_blob_ids: Vec<String>,
}

/// Result of a batch storage-lease lookup: each blob's on-chain storage
/// lease, plus the Walrus epoch the sidecar observed while looking them up
/// (`QueryBlobStorageLeasesResponse.current_epoch`). The expiry sweep
/// (`main.rs`) needs both — `current_epoch` anchors its
/// `expires_at_from_epoch` formula, scoped to the exact same lease-lookup
/// response `storage_end_epoch` came from.
pub struct BlobStorageLeases {
    pub blobs: Vec<BlobStorageLease>,
    pub current_epoch: i32,
}

/// Request/response types for sidecar HTTP API
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WalrusUploadRequest {
    data: String,
    key_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    owner: String,
    namespace: String,
    package_id: String,
    seal_abi: SealAbi,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_package_id: Option<String>,
    epochs: u64,
    defer_transfer: bool,
    #[serde(rename = "agentId", skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalrusUploadResponse {
    blob_id: String,
    object_id: Option<String>,
    #[serde(default)]
    transfer_status: Option<String>,
    #[serde(default)]
    end_epoch: Option<i32>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalrusUploadErrorResponse {
    error: String,
    blob_id: Option<String>,
    object_id: Option<String>,
    #[serde(default)]
    transfer_status: Option<String>,
    /// The sidecar includes this on the metadata-transfer failure response
    /// too (not just the success shape) — see `walrus-upload.ts`'s 500
    /// response for the "failed" transfer_status case. Previously absent
    /// here, so serde silently dropped it despite the sidecar sending it.
    #[serde(default)]
    end_epoch: Option<i32>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableUploadRequest<'a> {
    data: String,
    key_index: usize,
    job_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_address: Option<&'a str>,
    owner: &'a str,
    namespace: &'a str,
    package_id: &'a str,
    upload_protocol_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_execution_identity: Option<&'a UploadExecutionIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_step: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_transaction: Option<&'a PreparedRegisterTransaction>,
    epochs: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DurableUploadResponse {
    #[serde(default)]
    register_transaction: Option<PreparedRegisterTransaction>,
    #[serde(default)]
    resume_step: Option<serde_json::Value>,
    #[serde(default)]
    wallet_address: Option<String>,
    #[serde(default)]
    upload_execution_identity: Option<UploadExecutionIdentity>,
    #[serde(default)]
    step: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DurableUploadErrorResponse {
    #[serde(default)]
    code: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetMetadataBatchEntry {
    pub blob_object_id: String,
    pub namespace: String,
    #[serde(rename = "encryptedData", skip_serializing_if = "Option::is_none")]
    pub encrypted_data: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SetMetadataBatchRequest {
    blobs: Vec<SetMetadataBatchEntry>,
    owner: String,
    package_id: String,
    seal_abi: SealAbi,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_package_id: Option<String>,
    #[serde(rename = "agentId", skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    key_index: usize,
}

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum SealAbi {
    V1New,
}

pub enum SealPersistence<'a> {
    V1New {
        account_id: &'a str,
        registry_id: &'a str,
        policy_package_id: &'a str,
    },
}

fn seal_persistence_fields(
    persistence: SealPersistence<'_>,
) -> (SealAbi, Option<String>, Option<String>, Option<String>) {
    match persistence {
        SealPersistence::V1New {
            account_id,
            registry_id,
            policy_package_id,
        } => (
            SealAbi::V1New,
            Some(account_id.to_string()),
            Some(registry_id.to_string()),
            Some(policy_package_id.to_string()),
        ),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetMetadataBatchResponse {
    transferred: usize,
}

/// Upload an encrypted blob to Walrus via the HTTP sidecar.
///
/// Calls the long-lived sidecar server at `POST /walrus/upload` which uses
/// `@mysten/walrus` SDK with the multi-step writeBlobFlow.
///
/// The server wallet pays for gas + storage. After certify, the blob object
/// is transferred to `owner_address`. Namespace + owner are stored as
/// on-chain metadata attributes for discoverability.
#[allow(clippy::too_many_arguments)]
pub async fn upload_blob(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    data: &[u8],
    epochs: u64,
    owner_address: &str,
    key_index: usize,
    namespace: &str,
    package_id: &str,
    agent_id: Option<&str>,
    job_id: Option<&str>,
    seal_persistence: SealPersistence<'_>,
) -> Result<UploadResult, UploadBlobError> {
    upload_blob_inner(
        client,
        sidecar_url,
        sidecar_secret,
        data,
        epochs,
        owner_address,
        key_index,
        namespace,
        package_id,
        agent_id,
        job_id,
        false,
        seal_persistence,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn upload_blob_inner(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    data: &[u8],
    epochs: u64,
    owner_address: &str,
    key_index: usize,
    namespace: &str,
    package_id: &str,
    agent_id: Option<&str>,
    job_id: Option<&str>,
    defer_transfer: bool,
    seal_persistence: SealPersistence<'_>,
) -> Result<UploadResult, UploadBlobError> {
    let url = format!("{}/walrus/upload", sidecar_url);
    let data_b64 = BASE64.encode(data);

    let (seal_abi, account_id, registry_id, policy_package_id) =
        seal_persistence_fields(seal_persistence);
    let mut req = client.post(&url).json(&WalrusUploadRequest {
        data: data_b64,
        key_index,
        job_id: job_id.map(|s| s.to_string()),
        owner: owner_address.to_string(),
        namespace: namespace.to_string(),
        package_id: package_id.to_string(),
        seal_abi,
        account_id,
        registry_id,
        policy_package_id,
        epochs,
        defer_transfer,
        agent_id: agent_id.map(|s| s.to_string()),
    });
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);
    let started = std::time::Instant::now();
    let resp = req
        .timeout(SIDECAR_WALRUS_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            crate::observability::observe_external(
                "sidecar",
                "walrus_upload",
                "transport_error",
                started.elapsed(),
            );
            crate::observability::record_sidecar_failure("walrus_upload", "transport_error");
            UploadBlobError::App(AppError::Internal(format!(
                "Sidecar walrus/upload request failed: {}",
                e
            )))
        })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "walrus_upload",
        &status_label,
        started.elapsed(),
    );

    if !resp.status().is_success() {
        crate::observability::record_sidecar_failure("walrus_upload", "http_error");
        let body = resp.text().await.unwrap_or_default();
        if let Ok(err) = serde_json::from_str::<WalrusUploadErrorResponse>(&body) {
            if err.transfer_status.as_deref() == Some("failed") {
                if let (Some(blob_id), Some(object_id)) = (err.blob_id, err.object_id) {
                    return Err(UploadBlobError::MetadataTransferFailed {
                        blob_id,
                        object_id,
                        message: err.error,
                        end_epoch: err.end_epoch,
                    });
                }
            }
            return Err(UploadBlobError::App(AppError::Internal(format!(
                "walrus upload failed: {}",
                err.error
            ))));
        }
        if let Ok(err) = serde_json::from_str::<SidecarError>(&body) {
            return Err(UploadBlobError::App(AppError::Internal(format!(
                "walrus upload failed: {}",
                err.error
            ))));
        }
        return Err(UploadBlobError::App(AppError::Internal(format!(
            "walrus upload failed: {}",
            body
        ))));
    }

    let result: WalrusUploadResponse = resp.json().await.map_err(|e| {
        UploadBlobError::App(AppError::Internal(format!(
            "Failed to parse walrus/upload response: {}",
            e
        )))
    })?;
    if result.transfer_status.as_deref() == Some("failed") {
        if let Some(object_id) = result.object_id.clone() {
            return Err(UploadBlobError::MetadataTransferFailed {
                blob_id: result.blob_id.clone(),
                object_id,
                message: "walrus upload completed but metadata/transfer failed".into(),
                end_epoch: result.end_epoch,
            });
        }
        return Err(UploadBlobError::App(AppError::Internal(
            "walrus upload completed but metadata/transfer failed".into(),
        )));
    }
    if defer_transfer && result.object_id.is_none() {
        return Err(UploadBlobError::App(AppError::Internal(
            "walrus deferred upload returned no object_id".into(),
        )));
    }

    tracing::info!(
        "walrus upload via sidecar ok: blob_id={}, object_id={:?}, transfer_status={:?}, owner={}, ns={}",
        result.blob_id,
        result.object_id,
        result.transfer_status,
        owner_address,
        namespace
    );

    Ok(UploadResult {
        blob_id: result.blob_id,
        object_id: result.object_id,
        end_epoch: result.end_epoch,
    })
}

fn register_transaction_for_resume<'a>(
    resume_step: Option<&serde_json::Value>,
    register_transaction: Option<&'a PreparedRegisterTransaction>,
) -> Option<&'a PreparedRegisterTransaction> {
    // The prepared transaction is consumed by the encoded → registered
    // transition. Keeping it in the journal after that step makes the next
    // request internally inconsistent (`registerTransaction` with a registered,
    // uploaded, or certified resume step), which the sidecar correctly rejects.
    let is_encoded = resume_step
        .and_then(|step| step.get("step"))
        .and_then(serde_json::Value::as_str)
        == Some("encoded");
    is_encoded.then_some(register_transaction).flatten()
}

fn should_reset_prepared_register(
    error_code: Option<&str>,
    prepared: Option<&PreparedRegisterTransaction>,
) -> bool {
    // NO_SIDE_EFFECT: sidecar proved the digest absent. INVALID_PREPARED:
    // this replica refused the journaled bytes before execute (mixed-version
    // or incompatible sponsorship). CONGESTION_CANCELLED_TRANSACTION: the
    // digest finalized as cancelled by shared-object congestion and can never
    // land. All three are safe to rebuild. Only the last one gets a new
    // nonce; the other two re-prepare byte-identical so a register that did
    // land is still found by its digest.
    matches!(
        error_code,
        Some("NO_SIDE_EFFECT")
            | Some("INVALID_PREPARED_REGISTER_TRANSACTION")
            | Some("CONGESTION_CANCELLED_TRANSACTION")
    ) && prepared.is_some()
}

/// Drop a prepared register that must not be executed again, and name its
/// digest on the encoded checkpoint. The sidecar mixes that digest into the
/// direct-signed nonce, so the rebuild is not the cancelled bytes.
fn discard_cancelled_register(journal: &mut UploadJournal) {
    if let Some(digest) = journal
        .register_transaction
        .as_ref()
        .map(|prepared| prepared.digest.clone())
        .filter(|digest| !digest.is_empty())
    {
        if let Some(step) = journal
            .resume_step
            .as_mut()
            .and_then(|step| step.as_object_mut())
        {
            step.insert(
                "registerRebuild".to_string(),
                serde_json::Value::String(digest),
            );
        }
    }
    journal.register_transaction = None;
}

/// An `encoded` checkpoint is a local hash of the bytes from that attempt.
/// Re-encrypting the fact produces a new blob id. Walrus then refuses the
/// resume and reports `NO_SIDE_EFFECT`, so nothing was submitted. Dropping
/// the checkpoint lets the same bytes be encoded again. A later step owns a
/// blob object and must not be discarded here.
fn should_drop_stale_encoded_resume(
    body: &str,
    error_code: Option<&str>,
    resume_step: Option<&serde_json::Value>,
) -> bool {
    let encoded = resume_step
        .and_then(|step| step.get("step"))
        .and_then(serde_json::Value::as_str)
        == Some("encoded");
    encoded
        && error_code == Some("NO_SIDE_EFFECT")
        && body.to_ascii_lowercase().contains("resume blobid mismatch")
}

#[allow(clippy::too_many_arguments)]
pub async fn advance_durable_upload(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    data: &[u8],
    epochs: u64,
    owner: &str,
    namespace: &str,
    package_id: &str,
    job_id: &str,
    mut journal: UploadJournal,
) -> Result<DurableUploadAdvance, AppError> {
    let url = format!("{}/walrus/upload-step-v3", sidecar_url);
    let mut req = client.post(&url).json(&DurableUploadRequest {
        data: BASE64.encode(data),
        key_index: journal.wallet_index,
        job_id,
        wallet_address: journal.wallet_address.as_deref(),
        owner,
        namespace,
        package_id,
        upload_protocol_version: DURABLE_UPLOAD_PROTOCOL_VERSION,
        upload_execution_identity: journal.execution_identity.as_ref(),
        resume_step: journal.resume_step.as_ref(),
        register_transaction: register_transaction_for_resume(
            journal.resume_step.as_ref(),
            journal.register_transaction.as_ref(),
        ),
        epochs,
    });
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let response = crate::observability::apply_request_id_header(req)
        .timeout(SIDECAR_WALRUS_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            // reqwest's Display is only "error sending request for url (...)".
            // The reset, refusal, or timeout is on the source chain, and that
            // is what an exhausted-retry alert has to show.
            AppError::Internal(format!(
                "durable Walrus upload request failed: {}",
                error_chain(&e)
            ))
        })?;
    let status = response.status();
    let body = response.text().await.map_err(|e| {
        AppError::Internal(format!(
            "durable Walrus upload response failed for {url}: {}",
            error_chain(&e)
        ))
    })?;
    if !status.is_success() {
        let error_code = serde_json::from_str::<DurableUploadErrorResponse>(&body)
            .ok()
            .and_then(|error| error.code);
        if should_drop_stale_encoded_resume(
            &body,
            error_code.as_deref(),
            journal.resume_step.as_ref(),
        ) {
            // The encoded checkpoint names a blob id the current bytes do not
            // hash to. The sidecar submitted nothing, so the next loop pass
            // encodes these bytes from scratch. The prepared register, if any,
            // belongs to the old blob id.
            journal.resume_step = None;
            journal.register_transaction = None;
            return Ok(DurableUploadAdvance::Reset {
                journal,
                reason: format!("durable Walrus upload reset ({}): {}", status, body),
            });
        }
        let reset_safe = should_reset_prepared_register(
            error_code.as_deref(),
            journal.register_transaction.as_ref(),
        );
        if reset_safe {
            // Reset-safe codes mean this replica must not execute the journaled
            // bytes. NO_SIDE_EFFECT proved the digest absent. INVALID_PREPARED
            // means this replica refused the bytes before execute (mixed-version
            // or incompatible sponsorship) and can rebuild compatible ones.
            // A congestion cancel is the only code that proves the digest dead;
            // naming it on the checkpoint makes the rebuild a new transaction.
            // The other two re-prepare byte-identical so a register that did
            // land is still found by its digest lookup.
            if matches!(
                error_code.as_deref(),
                Some("CONGESTION_CANCELLED_TRANSACTION")
            ) {
                discard_cancelled_register(&mut journal);
            } else {
                journal.register_transaction = None;
            }
            return Ok(DurableUploadAdvance::Reset {
                journal,
                reason: format!("durable Walrus upload reset ({}): {}", status, body),
            });
        }
        return Err(AppError::Internal(format!(
            "durable Walrus upload failed ({}): {}",
            status, body
        )));
    }
    let parsed: DurableUploadResponse = serde_json::from_str(&body).map_err(|e| {
        AppError::Internal(format!("invalid durable Walrus upload response: {}", e))
    })?;
    let returned_step = parsed.step.as_ref();
    let next_resume_step = parsed.resume_step.or(journal.resume_step);
    let next_register_transaction = if returned_step.is_some() {
        // A returned checkpoint consumed any prepared transaction. The only
        // returned step before preparation is `encoded`, when none exists yet.
        parsed.register_transaction
    } else {
        parsed.register_transaction.or(journal.register_transaction)
    };
    let next = UploadJournal {
        wallet_index: journal.wallet_index,
        wallet_address: parsed.wallet_address.or(journal.wallet_address),
        execution_identity: parsed
            .upload_execution_identity
            .or(journal.execution_identity),
        resume_step: next_resume_step,
        register_transaction: next_register_transaction,
    };
    if let Some(step) = parsed.step {
        Ok(DurableUploadAdvance::Step {
            journal: next,
            step,
        })
    } else if next.register_transaction.is_some() {
        Ok(DurableUploadAdvance::Prepared(next))
    } else {
        Err(AppError::Internal(
            "durable Walrus upload response contained neither step nor prepared transaction".into(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn set_metadata_batch(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    key_index: usize,
    owner_address: &str,
    package_id: &str,
    agent_id: Option<&str>,
    blobs: Vec<SetMetadataBatchEntry>,
    seal_persistence: SealPersistence<'_>,
) -> Result<usize, AppError> {
    let url = format!("{}/walrus/set-metadata-batch", sidecar_url);
    let (seal_abi, account_id, registry_id, policy_package_id) =
        seal_persistence_fields(seal_persistence);
    let mut req = client.post(&url).json(&SetMetadataBatchRequest {
        blobs,
        owner: owner_address.to_string(),
        package_id: package_id.to_string(),
        seal_abi,
        account_id,
        registry_id,
        policy_package_id,
        agent_id: agent_id.map(|s| s.to_string()),
        key_index,
    });
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);

    let started = std::time::Instant::now();
    let resp = req
        .timeout(SIDECAR_WALRUS_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            crate::observability::observe_external(
                "sidecar",
                "walrus_set_metadata_batch",
                "transport_error",
                started.elapsed(),
            );
            crate::observability::record_sidecar_failure(
                "walrus_set_metadata_batch",
                "transport_error",
            );
            AppError::Internal(format!(
                "Sidecar walrus/set-metadata-batch request failed: {}",
                e
            ))
        })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "walrus_set_metadata_batch",
        &status_label,
        started.elapsed(),
    );
    if !resp.status().is_success() {
        crate::observability::record_sidecar_failure("walrus_set_metadata_batch", "http_error");
        let body = resp.text().await.unwrap_or_default();
        if let Ok(err) = serde_json::from_str::<SidecarError>(&body) {
            return Err(AppError::Internal(format!(
                "walrus set-metadata-batch failed: {}",
                err.error
            )));
        }
        return Err(AppError::Internal(format!(
            "walrus set-metadata-batch failed: {}",
            body
        )));
    }

    let result: SetMetadataBatchResponse = resp.json().await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to parse walrus/set-metadata-batch response: {}",
            e
        ))
    })?;
    Ok(result.transferred)
}

/// Blob a prior write minted for a remember job, discovered on-chain by the
/// `memwal_job_id` tag (GH #477 crash-window reconciliation).
pub struct FoundBlobByJob {
    pub blob_id: String,
    pub object_id: Option<String>,
}

/// Ask the sidecar whether `owner` already has a blob tagged with `job_id`.
/// Used before re-uploading a `running` job that may have minted (and lost the
/// record) so the relayer can adopt the blob instead of re-minting. `Ok(None)`
/// means no such blob is visible yet (upload normally).
pub async fn find_blob_by_job(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    owner: &str,
    job_id: &str,
) -> Result<Option<FoundBlobByJob>, AppError> {
    let url = format!("{}/walrus/find-blob-by-job", sidecar_url);
    let mut req = client.post(&url).json(&serde_json::json!({
        "owner": owner,
        "jobId": job_id,
    }));
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);

    let started = std::time::Instant::now();
    // A read against the chain — bounded, not the long upload timeout.
    let resp = req
        .timeout(WALRUS_DOWNLOAD_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            crate::observability::observe_external(
                "sidecar",
                "walrus_find_blob_by_job",
                "transport_error",
                started.elapsed(),
            );
            crate::observability::record_sidecar_failure(
                "walrus_find_blob_by_job",
                "transport_error",
            );
            AppError::Internal(format!(
                "Sidecar walrus/find-blob-by-job request failed: {}",
                e
            ))
        })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "walrus_find_blob_by_job",
        &status_label,
        started.elapsed(),
    );
    if !resp.status().is_success() {
        crate::observability::record_sidecar_failure("walrus_find_blob_by_job", "http_error");
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "walrus find-blob-by-job failed: {}",
            body
        )));
    }

    #[derive(serde::Deserialize)]
    struct FindBlobResp {
        blob_id: Option<String>,
        object_id: Option<String>,
    }
    let parsed: FindBlobResp = resp.json().await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to parse walrus/find-blob-by-job response: {}",
            e
        ))
    })?;
    Ok(parsed.blob_id.map(|blob_id| FoundBlobByJob {
        blob_id,
        object_id: parsed.object_id,
    }))
}

/// Query user's Walrus Blob objects from the Sui chain via sidecar.
///
/// This enables restore-from-zero: even if the local DB is empty,
/// we can discover all blob_ids by querying the user's on-chain objects
/// and reading the `memwal_namespace` metadata attribute.
pub async fn query_blobs_by_owner(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    owner_address: &str,
    namespace: Option<&str>,
    package_id: Option<&str>,
    limit: Option<usize>,
) -> Result<(Vec<OnChainBlob>, bool), AppError> {
    let url = format!("{}/walrus/query-blobs", sidecar_url);

    let mut body = serde_json::json!({ "owner": owner_address });
    if let Some(ns) = namespace {
        body["namespace"] = serde_json::json!(ns);
    }
    if let Some(pkg) = package_id {
        body["packageId"] = serde_json::json!(pkg);
    }
    if let Some(limit) = limit {
        body["limit"] = serde_json::json!(limit);
    }

    let mut req = client.post(&url).json(&body);
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);
    let started = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sidecar",
            "walrus_query_blobs",
            "transport_error",
            started.elapsed(),
        );
        crate::observability::record_sidecar_failure("walrus_query_blobs", "transport_error");
        AppError::UpstreamUnavailable(format!("Sidecar walrus/query-blobs failed: {}", e))
    })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "walrus_query_blobs",
        &status_label,
        started.elapsed(),
    );

    if !resp.status().is_success() {
        crate::observability::record_sidecar_failure("walrus_query_blobs", "http_error");
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::UpstreamUnavailable(format!(
            "walrus query-blobs failed: {}",
            body
        )));
    }

    let result: QueryBlobsResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse query-blobs response: {}", e)))?;

    tracing::info!(
        "walrus query-blobs ok: {} blobs for owner={}, ns={:?}, source_capped={}",
        result.total,
        owner_address,
        namespace,
        result.source_capped
    );

    Ok((result.blobs, result.source_capped))
}

/// Query on-chain storage-lease end epochs for a specific set of blob IDs
/// owned by `owner_address`, via the sidecar's `/walrus/query-blobs`
/// endpoint's `includeStorageLease: true` mode (the periodic expiry
/// sweep). Unlike `query_blobs_by_owner`, this is scoped to exactly the
/// blob IDs passed in and returns each one's `storageEndEpoch` rather than
/// namespace/package/agent metadata.
pub async fn query_blob_storage_leases(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    owner_address: &str,
    blob_ids: &[String],
) -> Result<BlobStorageLeases, AppError> {
    let url = format!("{}/walrus/query-blobs", sidecar_url);

    // NOTE: `limit` does NOT currently bound this call's cost. The
    // sidecar's `cap` formula (walrus-query.ts) is
    // `useRecentTxPath && !requestedBlobIds ? ... : Infinity` — since this
    // call always sends `blobIds`, `requestedBlobIds` is truthy, so `cap`
    // is always `Infinity` regardless of `limit`, and the sidecar still
    // paginates the owner's entire on-chain blob collection. `limit` is
    // sent anyway (harmless, forward-compatible) in case the sidecar's cap
    // logic is later changed to respect it for this call shape too. The
    // real fix is sidecar-side (early-exit `listBlobObjectsGrpc` once all
    // `requestedBlobIds` are found) and is tracked as a follow-up, not
    // done here.
    let body = serde_json::json!({
        "owner": owner_address,
        "blobIds": blob_ids,
        "includeStorageLease": true,
        "limit": blob_ids.len(),
    });

    let mut req = client.post(&url).json(&body);
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);
    let started = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sidecar",
            "walrus_query_blob_storage_leases",
            "transport_error",
            started.elapsed(),
        );
        crate::observability::record_sidecar_failure(
            "walrus_query_blob_storage_leases",
            "transport_error",
        );
        AppError::Internal(format!(
            "Sidecar walrus/query-blobs (storage lease) failed: {}",
            e
        ))
    })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "walrus_query_blob_storage_leases",
        &status_label,
        started.elapsed(),
    );

    if !resp.status().is_success() {
        crate::observability::record_sidecar_failure(
            "walrus_query_blob_storage_leases",
            "http_error",
        );
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "walrus query-blobs (storage lease) failed: {}",
            body
        )));
    }

    let result: QueryBlobStorageLeasesResponse = resp.json().await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to parse query-blobs storage-lease response: {}",
            e
        ))
    })?;

    tracing::info!(
        "walrus query-blobs (storage lease) ok: {} leases for owner={}",
        result.blobs.len(),
        owner_address,
    );

    Ok(BlobStorageLeases {
        blobs: result.blobs,
        current_epoch: result.current_epoch,
    })
}

/// Download a blob from one or more Walrus aggregators.
///
/// The first URL is treated as primary. When more URLs are configured, cold
/// reads race the next candidate after `race_after`; the first successful 2xx
/// response wins. This supports low-latency proxy/CDN aggregators while keeping
/// the existing single-aggregator behavior when no extra URL is configured.
///
/// `skip_consistency_check` is intentionally caller-controlled because it
/// should only be enabled for trusted blobs written by Walrus Memory.
pub async fn download_blob_from_aggregators(
    client: &reqwest::Client,
    aggregator_urls: &[String],
    blob_id: &str,
    skip_consistency_check: bool,
    race_after: Duration,
) -> Result<Vec<u8>, AppError> {
    if !is_valid_blob_id(blob_id) {
        // Internal, NOT BlobNotFound: BlobNotFound triggers reactive index
        // cleanup in the engine, and a malformed id is a data/config problem,
        // not proof the blob is gone from Walrus.
        return Err(AppError::Internal(format!(
            "Invalid Walrus blob id (expected base64url charset): {:?}",
            blob_id
        )));
    }

    let aggregator_urls: Vec<String> = aggregator_urls
        .iter()
        .map(|url| url.trim())
        .filter(|url| !url.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    if aggregator_urls.is_empty() {
        return Err(AppError::Internal(
            "Walrus download failed: no aggregator URLs configured".into(),
        ));
    }

    if aggregator_urls.len() == 1 {
        return download_blob_from_aggregator(
            client,
            &aggregator_urls[0],
            blob_id,
            skip_consistency_check,
        )
        .await;
    }

    let mut tasks = FuturesUnordered::new();
    let mut errors: Vec<(String, AppError)> = Vec::new();
    let mut next_index = 0usize;

    tasks.push(download_blob_candidate(
        client.clone(),
        aggregator_urls[next_index].clone(),
        blob_id.to_string(),
        skip_consistency_check,
    ));
    next_index += 1;

    loop {
        if tasks.is_empty() {
            if next_index < aggregator_urls.len() {
                tasks.push(download_blob_candidate(
                    client.clone(),
                    aggregator_urls[next_index].clone(),
                    blob_id.to_string(),
                    skip_consistency_check,
                ));
                next_index += 1;
                continue;
            }
            break;
        }

        if next_index >= aggregator_urls.len() {
            match tasks.next().await {
                Some((_, Ok(bytes))) => return Ok(bytes),
                Some((url, Err(err))) => errors.push((url, err)),
                None => break,
            }
            continue;
        }

        if race_after.is_zero() {
            while next_index < aggregator_urls.len() {
                tasks.push(download_blob_candidate(
                    client.clone(),
                    aggregator_urls[next_index].clone(),
                    blob_id.to_string(),
                    skip_consistency_check,
                ));
                next_index += 1;
            }
            continue;
        }

        tokio::select! {
            result = tasks.next() => {
                match result {
                    Some((_, Ok(bytes))) => return Ok(bytes),
                    Some((url, Err(err))) => errors.push((url, err)),
                    None => {}
                }
            }
            _ = tokio::time::sleep(race_after) => {
                tasks.push(download_blob_candidate(
                    client.clone(),
                    aggregator_urls[next_index].clone(),
                    blob_id.to_string(),
                    skip_consistency_check,
                ));
                next_index += 1;
            }
        }
    }

    Err(aggregate_download_errors(blob_id, &errors))
}

async fn download_blob_candidate(
    client: reqwest::Client,
    aggregator_url: String,
    blob_id: String,
    skip_consistency_check: bool,
) -> (String, Result<Vec<u8>, AppError>) {
    let result =
        download_blob_from_aggregator(&client, &aggregator_url, &blob_id, skip_consistency_check)
            .await;
    (aggregator_url, result)
}

async fn download_blob_from_aggregator(
    client: &reqwest::Client,
    aggregator_url: &str,
    blob_id: &str,
    skip_consistency_check: bool,
) -> Result<Vec<u8>, AppError> {
    let started = std::time::Instant::now();
    let mut url = reqwest::Url::parse(aggregator_url)
        .and_then(|base| base.join(&format!("v1/blobs/{blob_id}")))
        .map_err(|e| AppError::Internal(format!("Invalid Walrus aggregator URL: {}", e)))?;
    if skip_consistency_check {
        url.query_pairs_mut()
            .append_pair("skip_consistency_check", "true");
    }

    let resp = client
        .get(url.clone())
        .timeout(WALRUS_DOWNLOAD_TIMEOUT)
        .send()
        .await
        .map_err(|e| {
            let status = if e.is_timeout() {
                "timeout"
            } else {
                "transport_error"
            };
            crate::observability::observe_external(
                "walrus",
                "download_blob",
                status,
                started.elapsed(),
            );
            AppError::Internal(format!(
                "Walrus download failed from {}: {}",
                aggregator_url, e
            ))
        })?;

    let status = resp.status();
    let status_label = status.as_u16().to_string();
    crate::observability::observe_external(
        "walrus",
        "download_blob",
        &status_label,
        started.elapsed(),
    );

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(AppError::BlobNotFound(format!(
            "Blob {} expired or not found at {}",
            blob_id, aggregator_url
        )));
    }

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "Walrus download failed from {} with status {}: {}",
            aggregator_url, status, body
        )));
    }

    let bytes = resp.bytes().await.map_err(|e| {
        crate::observability::observe_external(
            "walrus",
            "download_blob",
            "body_error",
            started.elapsed(),
        );
        AppError::Internal(format!(
            "Failed to read Walrus blob {} from {}: {}",
            blob_id, aggregator_url, e
        ))
    })?;

    tracing::info!(
        "walrus download ok: blob_id={}, {} bytes, aggregator={}, skip_consistency_check={}",
        blob_id,
        bytes.len(),
        aggregator_url,
        skip_consistency_check
    );
    Ok(bytes.to_vec())
}

/// Walrus blob IDs are unpadded URL-safe base64 (a u256, 43 chars in
/// practice). Validate the charset before the id is interpolated into an
/// aggregator URL path so a corrupted or hostile stored id (containing
/// `/`, `..`, `?`, `#`, …) cannot change the request target.
fn is_valid_blob_id(blob_id: &str) -> bool {
    !blob_id.is_empty()
        && blob_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn aggregate_download_errors(blob_id: &str, errors: &[(String, AppError)]) -> AppError {
    if !errors.is_empty()
        && errors
            .iter()
            .all(|(_, err)| matches!(err, AppError::BlobNotFound(_)))
    {
        return AppError::BlobNotFound(format!(
            "Blob {} expired or not found across {} Walrus aggregators",
            blob_id,
            errors.len()
        ));
    }

    let summary = errors
        .iter()
        .map(|(url, err)| format!("{}: {}", url, err))
        .collect::<Vec<_>>()
        .join("; ");
    AppError::Internal(format!(
        "Walrus download failed for blob {} across {} aggregators: {}",
        blob_id,
        errors.len(),
        summary
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_download_errors, discard_cancelled_register, error_chain, is_valid_blob_id,
        register_transaction_for_resume, should_drop_stale_encoded_resume,
        should_reset_prepared_register, PreparedRegisterTransaction, QueryBlobsResponse,
        UploadJournal, WalrusUploadErrorResponse,
    };
    use crate::types::AppError;

    // The sidecar's metadata-transfer failure response includes `endEpoch`
    // (see walrus-upload.ts's 500 response for the "failed"
    // transfer_status case), but `WalrusUploadErrorResponse` didn't
    // declare the field, so serde silently dropped it despite the
    // sidecar sending it. This pins the deserialize directly against the
    // sidecar's real response shape, without needing a live sidecar.
    #[test]
    fn error_chain_keeps_the_source_reqwest_hides() {
        #[derive(Debug)]
        struct Leaf;
        impl std::fmt::Display for Leaf {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("connection reset by peer")
            }
        }
        impl std::error::Error for Leaf {}

        #[derive(Debug)]
        struct Wrap(Leaf);
        impl std::fmt::Display for Wrap {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "error sending request for url (http://localhost:9000/walrus/upload-step-v3)",
                )
            }
        }
        impl std::error::Error for Wrap {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        assert_eq!(
            error_chain(&Wrap(Leaf)),
            "error sending request for url (http://localhost:9000/walrus/upload-step-v3): connection reset by peer"
        );
    }

    #[test]
    fn walrus_upload_error_response_captures_end_epoch() {
        let body = r#"{
            "error": "Blob uploaded but metadata/transfer to owner failed",
            "jobId": "job-123",
            "blobId": "blob-abc",
            "objectId": "0xobject",
            "transferStatus": "failed",
            "endEpoch": 500
        }"#;
        let parsed: WalrusUploadErrorResponse = serde_json::from_str(body).expect("deserializes");
        assert_eq!(parsed.end_epoch, Some(500));
    }

    #[test]
    fn walrus_upload_error_response_end_epoch_defaults_to_none_when_absent() {
        // Backward compat: a response shape without endEpoch (or an older
        // sidecar version) must still deserialize, not fail.
        let body = r#"{
            "error": "some other failure",
            "blobId": null,
            "objectId": null,
            "transferStatus": null
        }"#;
        let parsed: WalrusUploadErrorResponse =
            serde_json::from_str(body).expect("deserializes without end_epoch");
        assert_eq!(parsed.end_epoch, None);
    }

    #[test]
    fn prepared_register_transaction_is_sent_only_with_encoded_resume() {
        let prepared = PreparedRegisterTransaction {
            transaction_bytes: "bytes".into(),
            signature: "signature".into(),
            digest: "digest".into(),
            sponsor_digest: None,
        };
        let encoded = serde_json::json!({ "step": "encoded" });
        let registered = serde_json::json!({ "step": "registered" });

        assert!(register_transaction_for_resume(Some(&encoded), Some(&prepared)).is_some());
        assert!(register_transaction_for_resume(Some(&registered), Some(&prepared)).is_none());
        assert!(register_transaction_for_resume(None, Some(&prepared)).is_none());
    }

    #[test]
    fn prepared_register_resets_on_no_side_effect_or_invalid_prepared() {
        let direct = PreparedRegisterTransaction {
            transaction_bytes: "bytes".into(),
            signature: "signature".into(),
            digest: "digest".into(),
            sponsor_digest: None,
        };
        let sponsored = PreparedRegisterTransaction {
            sponsor_digest: Some("sponsor".into()),
            ..direct.clone()
        };

        assert!(should_reset_prepared_register(
            Some("NO_SIDE_EFFECT"),
            Some(&direct)
        ));
        assert!(should_reset_prepared_register(
            Some("INVALID_PREPARED_REGISTER_TRANSACTION"),
            Some(&sponsored),
        ));
        assert!(!should_reset_prepared_register(
            Some("DURABLE_SIDE_EFFECT_VERIFY_FAILED"),
            Some(&sponsored),
        ));
    }

    #[test]
    fn a_cancelled_register_rebuild_names_the_discarded_digest() {
        let mut journal = UploadJournal {
            wallet_index: 0,
            wallet_address: None,
            execution_identity: None,
            resume_step: Some(serde_json::json!({
                "step": "encoded",
                "blobId": "blob",
            })),
            register_transaction: Some(PreparedRegisterTransaction {
                transaction_bytes: "bytes".into(),
                signature: "signature".into(),
                digest: "cancelled-digest".into(),
                sponsor_digest: None,
            }),
        };
        discard_cancelled_register(&mut journal);
        assert!(journal.register_transaction.is_none());
        assert_eq!(
            journal.resume_step.as_ref().unwrap()["registerRebuild"],
            "cancelled-digest"
        );
        assert_eq!(journal.resume_step.as_ref().unwrap()["blobId"], "blob");
    }

    #[test]
    fn encoded_resume_drops_only_on_blob_id_mismatch() {
        let encoded = serde_json::json!({
            "step": "encoded",
            "blobId": "Y8n5tChPgigsw_ptMHoDxIqbVzYqJRdpNDcbs84s4Fc"
        });
        let mismatch = r#"{"error":"Resume blobId mismatch: expected Y8n5tChP, got IRQ1QmKp. The blob content may have changed.","code":"NO_SIDE_EFFECT"}"#;
        assert!(should_drop_stale_encoded_resume(
            mismatch,
            Some("NO_SIDE_EFFECT"),
            Some(&encoded),
        ));
        let registered = serde_json::json!({ "step": "registered" });
        assert!(!should_drop_stale_encoded_resume(
            mismatch,
            Some("NO_SIDE_EFFECT"),
            Some(&registered),
        ));
        assert!(!should_drop_stale_encoded_resume(
            r#"{"error":"fetch failed","code":"NO_SIDE_EFFECT"}"#,
            Some("NO_SIDE_EFFECT"),
            Some(&encoded),
        ));
        assert!(!should_drop_stale_encoded_resume(
            mismatch,
            Some("SHARED_SERVICE_UNAVAILABLE"),
            Some(&encoded),
        ));
    }

    // ── QueryBlobsResponse.source_capped (WALM-319) ──────────────────────

    #[test]
    fn query_blobs_response_reads_source_capped_when_present() {
        let parsed: QueryBlobsResponse =
            serde_json::from_str(r#"{"blobs":[],"total":0,"sourceCapped":true}"#).unwrap();
        assert!(parsed.source_capped);

        let parsed: QueryBlobsResponse =
            serde_json::from_str(r#"{"blobs":[],"total":0,"sourceCapped":false}"#).unwrap();
        assert!(!parsed.source_capped);
    }

    #[test]
    fn query_blobs_response_defaults_source_capped_when_absent() {
        // A sidecar older than this fix (mid-rolling-deploy) won't send
        // sourceCapped at all -- must still parse, not error.
        let parsed: QueryBlobsResponse = serde_json::from_str(r#"{"blobs":[],"total":0}"#).unwrap();
        assert!(!parsed.source_capped);
    }

    #[test]
    fn valid_blob_ids_pass_charset_check() {
        // Real Walrus blob ids are unpadded base64url of a u256 (43 chars).
        assert!(is_valid_blob_id(
            "M4hsZGQ1oCchKzYnnhDMV-ZKvhWsp2SS1G7xI6PzQxs"
        ));
        assert!(is_valid_blob_id("abc123_-XYZ"));
    }

    #[test]
    fn invalid_blob_ids_are_rejected() {
        for bad in [
            "",
            "../secrets",
            "id/with/slashes",
            "id?query=1",
            "id#fragment",
            "id with spaces",
            "id\nnewline",
            "id+plus=", // standard base64 charset is not base64url
        ] {
            assert!(!is_valid_blob_id(bad), "should reject blob id: {:?}", bad);
        }
    }

    #[tokio::test]
    async fn download_rejects_invalid_blob_id_before_any_request() {
        let client = reqwest::Client::new();
        let err = super::download_blob_from_aggregators(
            &client,
            &["https://aggregator.invalid".to_string()],
            "../../../etc/passwd",
            false,
            std::time::Duration::ZERO,
        )
        .await
        .unwrap_err();

        // Must be Internal, not BlobNotFound — BlobNotFound would trigger
        // reactive index cleanup in the engine.
        assert!(matches!(err, AppError::Internal(_)));
    }

    #[test]
    fn aggregate_download_errors_preserves_not_found_cleanup_signal() {
        let errors = vec![
            (
                "https://a.example".to_string(),
                AppError::BlobNotFound("404".into()),
            ),
            (
                "https://b.example".to_string(),
                AppError::BlobNotFound("404".into()),
            ),
        ];

        assert!(matches!(
            aggregate_download_errors("blob", &errors),
            AppError::BlobNotFound(_)
        ));
    }

    #[test]
    fn aggregate_download_errors_keeps_transient_errors_internal() {
        let errors = vec![
            (
                "https://a.example".to_string(),
                AppError::BlobNotFound("404".into()),
            ),
            (
                "https://b.example".to_string(),
                AppError::Internal("timeout".into()),
            ),
        ];

        assert!(matches!(
            aggregate_download_errors("blob", &errors),
            AppError::Internal(_)
        ));
    }

    #[test]
    fn walrus_upload_response_deserializes_end_epoch() {
        let json = serde_json::json!({
            "blobId": "abc123",
            "objectId": "0xdead",
            "transferStatus": "ok",
            "endEpoch": 457,
        });
        let parsed: super::WalrusUploadResponse = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.end_epoch, Some(457));
    }

    /// Locks the exact JSON shape the sidecar's `/walrus/query-blobs`
    /// (`includeStorageLease: true`) route returns — see
    /// `res.json({ blobs, total, currentEpoch, nonexistentBlobIds })` in
    /// `services/server/scripts/sidecar/routes/walrus-query.ts`, where each
    /// `blobs[]` entry is `{ blobId, objectId, storageEndEpoch }`.
    #[test]
    fn query_blob_storage_leases_response_matches_sidecar_shape() {
        let json = serde_json::json!({
            "blobs": [
                {
                    "blobId": "M4hsZGQ1oCchKzYnnhDMV-ZKvhWsp2SS1G7xI6PzQxs",
                    "objectId": "0xdead",
                    "storageEndEpoch": 457,
                }
            ],
            "total": 1,
            "currentEpoch": 450,
            "nonexistentBlobIds": []
        });
        let parsed: super::QueryBlobStorageLeasesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.current_epoch, 450);
        assert!(parsed.nonexistent_blob_ids.is_empty());
        assert_eq!(parsed.blobs.len(), 1);
        assert_eq!(
            parsed.blobs[0].blob_id,
            "M4hsZGQ1oCchKzYnnhDMV-ZKvhWsp2SS1G7xI6PzQxs"
        );
        assert_eq!(parsed.blobs[0].object_id, "0xdead");
        assert_eq!(parsed.blobs[0].storage_end_epoch, 457);
    }

    // GH #477 reconcile client. The fail-closed contract is funds-critical: a
    // sidecar error / 409-indeterminate must become Err (caller retries WITHOUT
    // uploading), never Ok(None) (which would re-mint). Drive it against a local
    // mock so each branch is pinned.
    async fn mock_find_blob_server(
        status: axum::http::StatusCode,
        body: serde_json::Value,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>>,
    ) {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let app = axum::Router::new().route(
            "/walrus/find-blob-by-job",
            axum::routing::post({
                let seen = std::sync::Arc::clone(&seen);
                move |axum::Json(req): axum::Json<serde_json::Value>| {
                    let seen = std::sync::Arc::clone(&seen);
                    let body = body.clone();
                    async move {
                        *seen.lock().unwrap() = Some(req);
                        (status, axum::Json(body))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{}", addr), handle, seen)
    }

    #[tokio::test]
    async fn durable_upload_resets_only_proven_rejections_and_keeps_the_cause() {
        for code in [
            "NO_SIDE_EFFECT",
            "INVALID_PREPARED_REGISTER_TRANSACTION",
            "CONGESTION_CANCELLED_TRANSACTION",
            "SHARED_SERVICE_UNAVAILABLE",
            "DURABLE_SIDE_EFFECT_VERIFY_FAILED",
        ] {
            let app = axum::Router::new().route(
                "/walrus/upload-step-v3",
                axum::routing::post(move || async move {
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "code": code,
                            "error": "Enoki 404: Sponsored transaction not found",
                        })),
                    )
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let encoded = serde_json::json!({ "step": "encoded", "blobId": "blob" });
            let journal = super::UploadJournal {
                wallet_index: 3,
                wallet_address: Some("0xsigner".into()),
                execution_identity: None,
                resume_step: Some(encoded.clone()),
                register_transaction: Some(PreparedRegisterTransaction {
                    transaction_bytes: "bytes".into(),
                    signature: "signature".into(),
                    digest: "digest".into(),
                    sponsor_digest: Some("sponsor".into()),
                }),
            };
            let result = super::advance_durable_upload(
                &reqwest::Client::new(),
                &url,
                None,
                b"ciphertext",
                1,
                "0xowner",
                "test",
                "0xpackage",
                "job",
                journal,
            )
            .await;
            server.abort();
            if matches!(
                code,
                "NO_SIDE_EFFECT"
                    | "INVALID_PREPARED_REGISTER_TRANSACTION"
                    | "CONGESTION_CANCELLED_TRANSACTION"
            ) {
                let super::DurableUploadAdvance::Reset { journal, reason } = result.unwrap() else {
                    panic!("a proven reset must report its own budget event");
                };
                assert!(journal.register_transaction.is_none());
                // Only a finalized congestion cancel names the discarded
                // digest, so only that rebuild is a different transaction.
                let mut expected = encoded.clone();
                if code == "CONGESTION_CANCELLED_TRANSACTION" {
                    expected["registerRebuild"] = serde_json::json!("digest");
                }
                assert_eq!(journal.resume_step, Some(expected));
                assert_eq!(journal.wallet_index, 3);
                assert!(reason.contains(code));
                assert!(reason.contains("Sponsored transaction not found"));
            } else {
                assert!(
                    result.is_err(),
                    "ambiguous effects must not clear the journal"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_congestion_reset_sends_the_cancelled_digest_on_the_rebuild_request() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = axum::Router::new().route(
            "/walrus/upload-step-v3",
            axum::routing::post({
                let seen = std::sync::Arc::clone(&seen);
                move |axum::Json(request): axum::Json<serde_json::Value>| {
                    let seen = std::sync::Arc::clone(&seen);
                    async move {
                        let first = {
                            let mut requests = seen.lock().unwrap();
                            requests.push(request);
                            requests.len() == 1
                        };
                        if first {
                            (
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                axum::Json(serde_json::json!({
                                    "code": "CONGESTION_CANCELLED_TRANSACTION",
                                    "error": "registration transaction was cancelled by shared-object congestion",
                                })),
                            )
                        } else {
                            (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({ "error": "stop" })),
                            )
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let journal = super::UploadJournal {
            wallet_index: 3,
            wallet_address: Some("0xsigner".into()),
            execution_identity: None,
            resume_step: Some(serde_json::json!({ "step": "encoded", "blobId": "blob" })),
            register_transaction: Some(PreparedRegisterTransaction {
                transaction_bytes: "bytes".into(),
                signature: "signature".into(),
                digest: "cancelled-digest".into(),
                sponsor_digest: None,
            }),
        };
        let reset = super::advance_durable_upload(
            &reqwest::Client::new(),
            &url,
            None,
            b"ciphertext",
            1,
            "0xowner",
            "test",
            "0xpackage",
            "job",
            journal,
        )
        .await
        .expect("a congestion cancel is reset-safe");
        let super::DurableUploadAdvance::Reset { journal, .. } = reset else {
            panic!("a congestion cancel must reset the journal");
        };
        // The stop response ends the loop; only its request body matters here.
        assert!(super::advance_durable_upload(
            &reqwest::Client::new(),
            &url,
            None,
            b"ciphertext",
            1,
            "0xowner",
            "test",
            "0xpackage",
            "job",
            journal,
        )
        .await
        .is_err());
        server.abort();
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0]["registerTransaction"]["digest"],
            "cancelled-digest"
        );
        assert_eq!(
            requests[1]["resumeStep"]["registerRebuild"],
            "cancelled-digest"
        );
        assert_eq!(requests[1]["resumeStep"]["blobId"], "blob");
        assert!(requests[1]["registerTransaction"].is_null());
    }

    #[tokio::test]
    async fn durable_upload_shared_outage_preserves_request_for_retry() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = axum::Router::new().route(
            "/walrus/upload-step-v3",
            axum::routing::post({
                let seen = seen.clone();
                move |axum::Json(request): axum::Json<serde_json::Value>| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(request);
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            axum::Json(serde_json::json!({
                                "code": "SHARED_SERVICE_UNAVAILABLE", "error": "connection reset"
                            })),
                        )
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let journal = super::UploadJournal {
            wallet_index: 3,
            wallet_address: Some("0xsigner".into()),
            execution_identity: None,
            resume_step: Some(serde_json::json!({"step":"encoded","blobId":"blob"})),
            register_transaction: Some(super::PreparedRegisterTransaction {
                transaction_bytes: "bytes".into(),
                signature: "signature".into(),
                digest: "digest".into(),
                sponsor_digest: None,
            }),
        };
        for _ in 0..2 {
            let result = super::advance_durable_upload(
                &reqwest::Client::new(),
                &url,
                None,
                b"ciphertext",
                1,
                "0xowner",
                "test",
                "0xpackage",
                "job",
                journal.clone(),
            )
            .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("outage must not advance journal"),
            };
            assert!(matches!(
                crate::jobs::WalletJobError::classify_sidecar_error(&error.to_string()),
                crate::jobs::WalletJobError::UploadSlotCongestion(_)
            ));
        }
        server.abort();
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[0]["keyIndex"], 3);
        assert_eq!(requests[0]["registerTransaction"]["digest"], "digest");
    }

    #[tokio::test]
    async fn find_blob_by_job_returns_found() {
        let (url, server, seen) = mock_find_blob_server(
            axum::http::StatusCode::OK,
            serde_json::json!({ "blob_id": "blob-x", "object_id": "0xobj" }),
        )
        .await;
        let out = super::find_blob_by_job(&reqwest::Client::new(), &url, None, "0xowner", "job-1")
            .await
            .unwrap();
        server.abort();
        let found = out.expect("should be Some");
        assert_eq!(found.blob_id, "blob-x");
        assert_eq!(found.object_id.as_deref(), Some("0xobj"));
        // request carried owner + jobId
        let req = seen.lock().unwrap().clone().unwrap();
        assert_eq!(req["owner"], "0xowner");
        assert_eq!(req["jobId"], "job-1");
    }

    #[tokio::test]
    async fn find_blob_by_job_null_is_none() {
        let (url, server, _seen) = mock_find_blob_server(
            axum::http::StatusCode::OK,
            serde_json::json!({ "blob_id": null, "object_id": null }),
        )
        .await;
        let out = super::find_blob_by_job(&reqwest::Client::new(), &url, None, "0xowner", "job-1")
            .await
            .unwrap();
        server.abort();
        assert!(out.is_none(), "blob_id:null → Ok(None) → upload normally");
    }

    #[tokio::test]
    async fn find_blob_by_job_indeterminate_409_fails_closed() {
        let (url, server, _seen) = mock_find_blob_server(
            axum::http::StatusCode::CONFLICT,
            serde_json::json!({ "error": "indeterminate", "indeterminate": true }),
        )
        .await;
        let out =
            super::find_blob_by_job(&reqwest::Client::new(), &url, None, "0xowner", "job-1").await;
        server.abort();
        assert!(
            out.is_err(),
            "409 indeterminate must be Err (fail closed), NEVER Ok(None)"
        );
    }

    #[tokio::test]
    async fn find_blob_by_job_server_error_fails_closed() {
        let (url, server, _seen) = mock_find_blob_server(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "boom" }),
        )
        .await;
        let out =
            super::find_blob_by_job(&reqwest::Client::new(), &url, None, "0xowner", "job-1").await;
        server.abort();
        assert!(
            out.is_err(),
            "5xx must be Err (fail closed), never Ok(None)"
        );
    }
}
