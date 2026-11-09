use crate::types::{AppError, AuthInfo, SidecarError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Credential used to authorize a SEAL decrypt request against the sidecar.
///
/// `Session` (an exported `SessionKey`, built on the client) is
/// preferred. `DelegateKey` is the legacy path where the SDK transmits the
/// raw Ed25519 private key — retained temporarily so existing clients keep
/// working. At EOL the `DelegateKey` variant will be removed.
///
/// Owned so it can be cheaply cloned into async tasks.
#[derive(Debug, Clone)]
pub enum SealCredential {
    Session(String),
    DelegateKey(String),
}

impl SealCredential {
    /// Build the credential from an `AuthInfo`, preferring `seal_session`
    /// when present. Falls back to `delegate_key` (legacy), then to a
    /// server-side fallback private key (used when a route lacks a user
    /// context). Returns `None` if no credential is available.
    pub fn from_auth_or_fallback(
        auth: &AuthInfo,
        fallback_private_key: Option<&str>,
    ) -> Option<Self> {
        if let Some(s) = auth.seal_session.as_deref() {
            return Some(SealCredential::Session(s.to_string()));
        }
        if let Some(k) = auth.delegate_key.as_deref() {
            return Some(SealCredential::DelegateKey(k.to_string()));
        }
        fallback_private_key.map(|k| SealCredential::DelegateKey(k.to_string()))
    }
}

#[derive(serde::Deserialize)]
struct BatchDecryptItem {
    index: usize,
    #[serde(rename = "decryptedData")]
    decrypted_data: String,
}

#[derive(serde::Deserialize)]
struct BatchDecryptError {
    index: usize,
    #[serde(default)]
    code: Option<String>,
    error: String,
}

#[derive(serde::Deserialize)]
struct SealDecryptBatchResponse {
    results: Vec<BatchDecryptItem>,
    errors: Vec<BatchDecryptError>,
}

/// Which on-chain `seal_approve` ABI the sidecar should build. Two are live
/// during the V1 -> v1-new migration; an enum keeps callers from typo'ing the
/// wire value, which the sidecar would reject with a 400.
#[derive(serde::Serialize)]
enum SealAbi {
    #[serde(rename = "v1")]
    V1,
    #[serde(rename = "v1-new")]
    V1New,
}

/// Request/response types for sidecar HTTP API
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SealEncryptRequest {
    data: String,
    owner: String,
    package_id: String,
    account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_seal_committee_identity: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealEncryptResponse {
    encrypted_data: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SealDecryptRequest {
    data: String,
    /// Immutable original-publish package ID used by the SessionKey and
    /// ciphertext namespace.
    package_id: String,
    /// Current published package whose `seal_approve` entry is executed.
    policy_package_id: String,
    /// Shared `AccountRegistry` object id used by the current policy's version
    /// gate. Historical ciphertext targets the current policy package.
    registry_id: String,
    account_id: String,
    /// This server always runs against the current v1-new package (3-arg,
    /// registry-gated).
    seal_abi: SealAbi,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealDecryptResponse {
    decrypted_data: String,
}

/// Batch variant of `SealDecryptRequest`. A struct (not a hand-written json!)
/// so the camelCase keys and the v1-new `sealAbi` are asserted in a serde test
/// rather than trusting the string literals.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SealDecryptBatchRequest {
    items: Vec<String>,
    package_id: String,
    policy_package_id: String,
    registry_id: String,
    account_id: String,
    seal_abi: SealAbi,
}

/// Encrypt plaintext using SEAL threshold encryption via HTTP sidecar.
///
/// Calls the long-lived sidecar server at `POST /seal/encrypt`.
/// The ciphertext is bound to the SEAL key ID `owner ‖ access_counter_version`.
///
/// `account_id` is the owner's `MemWalAccount`. The sidecar reads the counter
/// off that object itself rather than taking one from us, so a stale caller
/// cannot pin new memories to an identity a just-removed delegate still holds a
/// key for. It is required: the route rejects the request without it.
///
/// Returns: SEAL encrypted bytes
pub async fn seal_encrypt(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    data: &[u8],
    owner_address: &str,
    account_id: &str,
    package_id: &str,
    expected_seal_committee_identity: Option<&serde_json::Value>,
) -> Result<Vec<u8>, AppError> {
    let url = format!("{}/seal/encrypt", sidecar_url);
    let data_b64 = BASE64.encode(data);

    let mut req = client.post(&url).json(&SealEncryptRequest {
        data: data_b64,
        owner: owner_address.to_string(),
        package_id: package_id.to_string(),
        account_id: account_id.to_string(),
        expected_seal_committee_identity: expected_seal_committee_identity.cloned(),
    });
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);
    let started = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sidecar",
            "seal_encrypt",
            "transport_error",
            started.elapsed(),
        );
        crate::observability::record_sidecar_failure("seal_encrypt", "transport_error");
        tracing::error!(error = %e, "sidecar seal/encrypt transport failed");
        AppError::UpstreamUnavailable("Memory encryption backend is unavailable".into())
    })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "seal_encrypt",
        &status_label,
        started.elapsed(),
    );

    if !resp.status().is_success() {
        crate::observability::record_sidecar_failure("seal_encrypt", "http_error");
        let body = resp.text().await.unwrap_or_default();
        if let Ok(err) = serde_json::from_str::<SidecarError>(&body) {
            return Err(AppError::Internal(format!(
                "seal encrypt failed: {}",
                err.error
            )));
        }
        return Err(AppError::Internal(format!("seal encrypt failed: {}", body)));
    }

    let result: SealEncryptResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse seal/encrypt response: {}", e)))?;

    let encrypted_bytes = BASE64
        .decode(&result.encrypted_data)
        .map_err(|e| AppError::Internal(format!("Failed to decode encrypted base64: {}", e)))?;

    tracing::info!(
        "seal encrypt ok: {} bytes -> {} encrypted bytes",
        data.len(),
        encrypted_bytes.len()
    );

    Ok(encrypted_bytes)
}

/// Decrypt SEAL-encrypted data via the sidecar.
///
/// Calls `POST /seal/decrypt` on the long-lived sidecar server. The
/// credential is either an exported SessionKey token or a
/// legacy delegate private key. The client must have authority for
/// `seal_approve` against the given `account_id`; `registry_id` is the shared
/// `AccountRegistry` used by the current policy's version gate.
///
/// Returns: decrypted plaintext bytes.
pub async fn seal_decrypt(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    encrypted_data: &[u8],
    credential: &SealCredential,
    package_id: &str,
    policy_package_id: &str,
    registry_id: &str,
    account_id: &str,
) -> Result<Vec<u8>, AppError> {
    let url = format!("{}/seal/decrypt", sidecar_url);
    let data_b64 = BASE64.encode(encrypted_data);

    let mut req = client.post(&url).json(&SealDecryptRequest {
        data: data_b64,
        package_id: package_id.to_string(),
        policy_package_id: policy_package_id.to_string(),
        registry_id: registry_id.to_string(),
        account_id: account_id.to_string(),
        seal_abi: SealAbi::V1New,
    });
    req = match credential {
        SealCredential::Session(s) => req.header("x-seal-session", s),
        SealCredential::DelegateKey(k) => req.header("x-delegate-key", k),
    };
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);
    let started = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sidecar",
            "seal_decrypt",
            "transport_error",
            started.elapsed(),
        );
        crate::observability::record_sidecar_failure("seal_decrypt", "transport_error");
        tracing::error!(error = %e, "sidecar seal/decrypt transport failed");
        AppError::UpstreamUnavailable("Memory encryption backend is unavailable".into())
    })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "seal_decrypt",
        &status_label,
        started.elapsed(),
    );

    if !resp.status().is_success() {
        crate::observability::record_sidecar_failure("seal_decrypt", "http_error");
        let body = resp.text().await.unwrap_or_default();
        if let Ok(err) = serde_json::from_str::<SidecarError>(&body) {
            return Err(AppError::Internal(format!(
                "seal decrypt failed: {}",
                err.error
            )));
        }
        return Err(AppError::Internal(format!("seal decrypt failed: {}", body)));
    }

    let result: SealDecryptResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse seal/decrypt response: {}", e)))?;

    let decrypted_bytes = BASE64
        .decode(&result.decrypted_data)
        .map_err(|e| AppError::Internal(format!("Failed to decode decrypted base64: {}", e)))?;

    tracing::info!(
        "seal decrypt ok: {} encrypted bytes -> {} decrypted bytes",
        encrypted_data.len(),
        decrypted_bytes.len()
    );

    Ok(decrypted_bytes)
}

/// Per-blob outcome of a batch SEAL decrypt call.
#[derive(Debug)]
pub enum DecryptOutcome {
    Ok(Vec<u8>),
    Failed { error: String, permanent: bool },
    Missing,
}

impl DecryptOutcome {
    /// Classifies a SEAL decrypt error string as permanent (deterministic —
    /// wrong key/policy, will never succeed for this owner) vs transient
    /// (timeout/429/503/rate-limit — must be retried, never cached as bad).
    ///
    /// `pub(crate)` so `routes::admin::restore()` can reuse it to decide
    /// whether a foreign/attacker blob's decrypt failure is safe to record
    /// in the `restore_failed_blobs` negative cache (GH #501 / WALM-299) —
    /// a permanent failure never gets discovered-and-decrypted again for
    /// this owner, while a transient one must keep being retried so an
    /// infra blip can never permanently blacklist a legitimate blob.
    pub(crate) fn permanent_from_code_and_error(code: Option<&str>, err: &str) -> bool {
        match code {
            Some("CORRUPT_CIPHERTEXT") => true,
            Some("SHARED_SERVICE_UNAVAILABLE") => false,
            _ => Self::permanent_from_error(err),
        }
    }

    pub(crate) fn permanent_from_error(err: &str) -> bool {
        if err.contains("Not enough shares")
            || err.contains("InvalidCiphertext")
            || err.contains("InvalidPersonalMessageSignature")
            // @mysten/seal's NoAccessError: key servers rejected the request
            // because the caller doesn't hold access to the requested key(s).
            // Checked before "fetch_keys failed" because /seal/decrypt-batch
            // prefixes every fetchKeys error with "fetch_keys failed: ...".
            || err.contains("NoAccessError")
            || err.contains("Ciphertext packageId does not match")
        {
            return true;
        }

        let lower = err.to_ascii_lowercase();
        // sendSealFailure (sidecar) echoes the configured request timeout as
        // "(traceId=..., timeoutMs=...)" on every single error it composes,
        // permanent or not, so a bare "timeout" substring match here would
        // misclassify everything (including NoAccessError/InvalidCiphertext)
        // as transient. Match the actual timeout signal instead.
        if lower.contains("timeouterror")
            || lower.contains("aborted due to timeout")
            || lower.contains("fetch_keys failed")
            || lower.contains("too many failed fetch")
            || lower.contains("internal server")
            || lower.contains("temporarily unavailable")
            || lower.contains("rate limit")
            || lower.contains("429")
            || lower.contains("503")
        {
            return false;
        }

        false
    }
}

/// Batch-decrypt multiple SEAL-encrypted blobs in a single sidecar HTTP call.
pub async fn seal_decrypt_batch(
    client: &reqwest::Client,
    sidecar_url: &str,
    sidecar_secret: Option<&str>,
    encrypted_blobs: &[(String, Vec<u8>)],
    credential: &SealCredential,
    package_id: &str,
    policy_package_id: &str,
    registry_id: &str,
    account_id: &str,
) -> Result<Vec<DecryptOutcome>, AppError> {
    if encrypted_blobs.is_empty() {
        return Ok(vec![]);
    }

    let url = format!("{}/seal/decrypt-batch", sidecar_url);
    let items: Vec<String> = encrypted_blobs
        .iter()
        .map(|(_, data)| BASE64.encode(data))
        .collect();
    // `items` (the base64 ciphertexts, up to ~8 MB) is moved in, not cloned;
    // only the short ids are copied, so owning the struct costs nothing here.
    let body = SealDecryptBatchRequest {
        items,
        package_id: package_id.to_string(),
        policy_package_id: policy_package_id.to_string(),
        registry_id: registry_id.to_string(),
        account_id: account_id.to_string(),
        // This server always runs against the current v1-new package.
        seal_abi: SealAbi::V1New,
    };

    let mut req = client.post(&url).json(&body);
    req = match credential {
        SealCredential::Session(s) => req.header("x-seal-session", s),
        SealCredential::DelegateKey(k) => req.header("x-delegate-key", k),
    };
    if let Some(secret) = sidecar_secret {
        req = req.header("authorization", format!("Bearer {}", secret));
    }
    let req = crate::observability::apply_request_id_header(req);

    let started = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sidecar",
            "seal_decrypt_batch",
            "transport_error",
            started.elapsed(),
        );
        crate::observability::record_sidecar_failure("seal_decrypt_batch", "transport_error");
        tracing::error!(error = %e, "sidecar seal/decrypt-batch transport failed");
        AppError::UpstreamUnavailable("Memory encryption backend is unavailable".into())
    })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "seal_decrypt_batch",
        &status_label,
        started.elapsed(),
    );

    let status = resp.status();
    if !status.is_success() {
        crate::observability::record_sidecar_failure("seal_decrypt_batch", "http_error");
        let body_text = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<SidecarError>(&body_text)
            .map(|err| err.error)
            .unwrap_or(body_text);
        // 503 is the sidecar's shared-outage signal. Recall retries that;
        // Internal becomes a non-retryable 500.
        if status.as_u16() == 503 {
            return Err(AppError::UpstreamUnavailable(format!(
                "seal decrypt-batch failed: {}",
                detail
            )));
        }
        return Err(AppError::Internal(format!(
            "seal decrypt-batch failed: {}",
            detail
        )));
    }

    let batch_resp: SealDecryptBatchResponse = resp.json().await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to parse seal/decrypt-batch response: {}",
            e
        ))
    })?;

    let mut out: Vec<DecryptOutcome> = (0..encrypted_blobs.len())
        .map(|_| DecryptOutcome::Missing)
        .collect();

    for item in &batch_resp.results {
        if item.index >= out.len() {
            continue;
        }
        out[item.index] = match BASE64.decode(&item.decrypted_data) {
            Ok(bytes) => DecryptOutcome::Ok(bytes),
            Err(e) => DecryptOutcome::Failed {
                error: format!("base64 decode failed: {}", e),
                permanent: false,
            },
        };
    }

    for err in &batch_resp.errors {
        let blob_id = encrypted_blobs
            .get(err.index)
            .map(|(id, _)| id.as_str())
            .unwrap_or("?");
        let permanent =
            DecryptOutcome::permanent_from_code_and_error(err.code.as_deref(), &err.error);
        tracing::warn!(
            "seal decrypt-batch: sidecar error for blob {} (index {}, permanent={}): {}",
            blob_id,
            err.index,
            permanent,
            err.error
        );
        if err.index < out.len() {
            out[err.index] = DecryptOutcome::Failed {
                error: err.error.clone(),
                permanent,
            };
        }
    }

    tracing::info!(
        "seal decrypt-batch ok: {}/{} decrypted, {} errors",
        batch_resp.results.len(),
        encrypted_blobs.len(),
        batch_resp.errors.len()
    );

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        DecryptOutcome, SealAbi, SealDecryptBatchRequest, SealDecryptRequest, SealEncryptRequest,
    };

    #[test]
    fn decrypt_request_carries_registry_and_account_ids() {
        let value = serde_json::to_value(SealDecryptRequest {
            data: "ciphertext".into(),
            package_id: "0x2".into(),
            policy_package_id: "0x4".into(),
            registry_id: "0x9".into(),
            account_id: "0x3".into(),
            seal_abi: SealAbi::V1New,
        })
        .expect("serialize decrypt request");
        // seal_approve takes the registry alongside the account; without
        // registryId the sidecar policy PTB is missing an argument and every
        // decrypt reverts on-chain. sealAbi=v1-new selects that 3-arg shape.
        assert_eq!(value["registryId"], "0x9");
        assert_eq!(value["packageId"], "0x2");
        assert_eq!(value["policyPackageId"], "0x4");
        assert_eq!(value["accountId"], "0x3");
        assert_eq!(value["sealAbi"], "v1-new");
    }

    #[test]
    fn decrypt_batch_request_carries_registry_and_seal_abi() {
        let items = vec!["Y2lwaGVy".to_string()];
        let value = serde_json::to_value(SealDecryptBatchRequest {
            items,
            package_id: "0x2".into(),
            policy_package_id: "0x4".into(),
            registry_id: "0x9".into(),
            account_id: "0x3".into(),
            seal_abi: SealAbi::V1New,
        })
        .expect("serialize decrypt batch request");
        // Same 3-arg v1-new contract as the single decrypt; a typo'd camelCase
        // key or a dropped registry here fails this test instead of only
        // surfacing as a runtime 400 from the sidecar.
        assert_eq!(value["registryId"], "0x9");
        assert_eq!(value["packageId"], "0x2");
        assert_eq!(value["policyPackageId"], "0x4");
        assert_eq!(value["accountId"], "0x3");
        assert_eq!(value["sealAbi"], "v1-new");
        assert_eq!(value["items"][0], "Y2lwaGVy");
    }

    #[test]
    fn encrypt_request_carries_the_account_id() {
        let value = serde_json::to_value(SealEncryptRequest {
            data: "plaintext".into(),
            owner: "0x1".into(),
            package_id: "0x2".into(),
            account_id: "0x3".into(),
            expected_seal_committee_identity: Some(serde_json::json!({
                "servers": [{ "objectId": "0x4", "weight": 1 }],
                "threshold": 1,
            })),
        })
        .expect("serialize encrypt request");
        // The sidecar reads access_counter_version off this object to build the
        // SEAL identity; without it POST /seal/encrypt is a 400 and every
        // remember/analyze write fails.
        assert_eq!(value["accountId"], "0x3");
        assert_eq!(value["expectedSealCommitteeIdentity"]["threshold"], 1);
    }

    #[test]
    fn classifies_seal_timeouts_as_transient() {
        for msg in [
            "fetch_keys failed: TimeoutError: The operation was aborted due to timeout",
            "decrypt failed: TimeoutError: The operation was aborted due to timeout",
            "seal decrypt-batch failed: Internal server error",
            "TooManyFailedFetchKeyRequestsError",
        ] {
            assert!(
                !DecryptOutcome::permanent_from_error(msg),
                "expected transient: {}",
                msg
            );
        }
    }

    #[test]
    fn classifies_clear_seal_auth_or_ciphertext_errors_as_permanent() {
        for msg in [
            "Not enough shares",
            "InvalidCiphertext",
            "InvalidPersonalMessageSignature",
        ] {
            assert!(
                DecryptOutcome::permanent_from_error(msg),
                "expected permanent: {}",
                msg
            );
        }
    }

    #[test]
    fn classifies_no_access_error_as_permanent() {
        // The exact wrapped error shape produced when restore() attempts to
        // decrypt a foreign blob (GH #501/WALM-299): SEAL's key servers
        // correctly reject a caller with no access, and the sidecar/Rust
        // wrapping composes it into this message — including the
        // "timeoutMs=" request-config echo that sendSealFailure adds to
        // every error regardless of type. A naive "timeout" substring check
        // would misclassify this as transient; this pins that it doesn't.
        let msg = "seal decrypt failed: seal/decrypt failed during fetch_keys: \
                    NoAccessError: user does not have access to one or more of \
                    the requested keys (traceId=abc123, timeoutMs=10000)";
        assert!(
            DecryptOutcome::permanent_from_error(msg),
            "expected permanent: {}",
            msg
        );
    }

    #[test]
    fn classifies_real_wire_format_timeout_as_transient() {
        // sendSealFailure's actual composed shape for a genuine timeout,
        // including the same "(traceId=..., timeoutMs=...)" suffix as every
        // other error — must still classify as transient despite that
        // shared suffix, on the strength of "TimeoutError" / "aborted due to
        // timeout" in the inner message, not the bare word "timeout".
        let msg = "seal decrypt failed: seal/decrypt failed during fetch_keys: \
                    TimeoutError: The operation was aborted due to timeout \
                    (traceId=abc123, timeoutMs=10000)";
        assert!(
            !DecryptOutcome::permanent_from_error(msg),
            "expected transient: {}",
            msg
        );
    }

    #[test]
    fn classifies_batch_prefixed_no_access_error_as_permanent() {
        let msg = "fetch_keys failed: NoAccessError: user does not have access to one or more of the requested keys";
        assert!(
            DecryptOutcome::permanent_from_error(msg),
            "expected permanent even with fetch_keys prefix: {}",
            msg
        );
    }

    #[test]
    fn code_takes_precedence_for_decrypt_permanence() {
        assert!(DecryptOutcome::permanent_from_code_and_error(
            Some("CORRUPT_CIPHERTEXT"),
            "unexpected error string"
        ));
        assert!(!DecryptOutcome::permanent_from_code_and_error(
            Some("SHARED_SERVICE_UNAVAILABLE"),
            "unexpected error string"
        ));
    }
}
